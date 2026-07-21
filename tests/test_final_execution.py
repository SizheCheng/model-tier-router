from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from mtr_dogfood.final_execution import CampaignLedger, self_test


ROOT = Path(__file__).resolve().parents[1]


class FinalExecutionTests(unittest.TestCase):
    def test_self_test_has_hard_campaign_limits(self):
        value = self_test()
        self.assertEqual(value["status"], "passed")
        self.assertEqual(value["maximum_real_starts"], 2)
        self.assertTrue(value["no_retry"])
        self.assertTrue(value["stop_on_first_failure"])
        self.assertEqual(value["real_model_process_starts"], 0)

    def test_real_reservation_is_consumed_before_process_start(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = CampaignLedger(
                Path(temporary) / "ledger.json",
                qualification_only=False,
            )
            ledger.reserve("lane-1")
            self.assertEqual(ledger.starts_consumed, 1)
            saved = json.loads((Path(temporary) / "ledger.json").read_text())
            self.assertEqual(saved["starts_consumed"], 1)
            self.assertFalse(saved["records"][0]["process_started"])

    def test_qualification_reservations_consume_no_real_starts(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = CampaignLedger(
                Path(temporary) / "ledger.json",
                qualification_only=True,
            )
            ledger.reserve("lane-1")
            ledger.reserve("lane-2")
            self.assertEqual(ledger.starts_consumed, 0)
            with self.assertRaisesRegex(
                RuntimeError,
                "START_RESERVATION_LIMIT_REACHED",
            ):
                ledger.reserve("lane-3")

    def test_wrapper_is_static_and_has_no_bare_carriage_return(self):
        wrapper = (
            ROOT
            / "final_execution"
            / "RUN_FINAL_TWO_PRODUCT_LANES.ps1"
        ).read_bytes()
        self.assertEqual(wrapper.replace(b"\r\n", b"").count(b"\r"), 0)
        text = wrapper.decode("utf-8").replace("\r\n", "\n")
        param_block = text.split("\n)\n", 1)[0]
        self.assertNotIn("$PSScriptRoot", param_block)
        self.assertIn("--runner-pid $PID", text)

    def test_final_execution_zipapp_is_reproducible(self):
        with (
            tempfile.TemporaryDirectory() as first,
            tempfile.TemporaryDirectory() as second,
        ):
            artifacts = []
            for output in (first, second):
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-B",
                        str(ROOT / "scripts" / "build_qualification_artifact.py"),
                        "--output-directory",
                        output,
                        "--entrypoint",
                        "final-execution",
                    ],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=180,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                artifacts.append(
                    (Path(output) / "mtr-dogfood-final-execution.pyz").read_bytes()
                )
            self.assertEqual(artifacts[0], artifacts[1])


if __name__ == "__main__":
    unittest.main()