from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from mtr_dogfood.remaining_lane_execution import CampaignLedger, self_test


ROOT = Path(__file__).resolve().parents[1]
ROUTER = Path(r"C:\Users\sizhe\Documents\model-tier-router")
QWEN = Path(r"C:\Users\sizhe\Documents\qwen-redaction-standalone")


class RemainingLaneExecutionTests(unittest.TestCase):
    def test_self_test_has_one_start_no_retry_contract(self):
        value = self_test()
        self.assertEqual(value["status"], "passed")
        self.assertEqual(
            value["route_id"],
            "FINAL_REMAINING_QWEN_PRODUCT_LANE_EXECUTION_R1",
        )
        self.assertEqual(value["maximum_real_starts"], 1)
        self.assertTrue(value["no_retry"])
        self.assertTrue(value["stop_on_first_failure"])
        self.assertEqual(value["real_model_process_starts"], 0)

    def test_ledger_allows_exactly_one_reservation(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = CampaignLedger(
                Path(temporary) / "ledger.json",
                qualification_only=True,
            )
            record = ledger.reserve("qwen-docx-hidden-elements-r1")
            self.assertEqual(ledger.starts_consumed, 0)
            self.assertTrue(record["prior_r5_ordinal_1_permanently_consumed"])
            with self.assertRaisesRegex(
                RuntimeError,
                "START_RESERVATION_LIMIT_REACHED|DUPLICATE_LANE_RESERVATION",
            ):
                ledger.reserve("another-lane")

    def test_wrapper_is_static_and_has_no_bare_carriage_return(self):
        wrapper = (
            ROOT
            / "final_execution"
            / "RUN_FINAL_REMAINING_QWEN_LANE.ps1"
        ).read_bytes()
        self.assertEqual(wrapper.replace(b"\r\n", b"").count(b"\r"), 0)
        text = wrapper.decode("utf-8").replace("\r\n", "\n")
        param_block = text.split("\n)\n", 1)[0]
        self.assertNotIn("$PSScriptRoot", param_block)
        self.assertIn("mtr-dogfood-remaining-lane.pyz", text)
        self.assertIn(r"C:\Users\sizhe\mtr-work\qwen-r1", text)
        self.assertIn("--runner-pid $PID", text)

    def test_artifact_is_reproducible(self):
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
                        "remaining-lane",
                    ],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=180,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                artifacts.append(
                    (Path(output) / "mtr-dogfood-remaining-lane.pyz").read_bytes()
                )
            self.assertEqual(artifacts[0], artifacts[1])

    def test_packet_contains_only_remaining_lane_and_qualifies_without_model(self):
        if not ROUTER.is_dir() or not QWEN.is_dir():
            self.skipTest("live source repositories are unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            packet = base / "packet"
            build = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(ROOT / "scripts" / "build_final_remaining_lane_packet.py"),
                    "--output-directory",
                    str(packet),
                    "--router-repository",
                    str(ROUTER),
                    "--qwen-repository",
                    str(QWEN),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
                timeout=240,
            )
            self.assertEqual(build.returncode, 0, build.stderr)
            manifest = json.loads(
                (packet / "FINAL_EXECUTION_MANIFEST.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["execution_order"], ["qwen-docx-hidden-elements-r1"])
            self.assertEqual(manifest["maximum_new_starts"], 1)
            self.assertTrue(manifest["prior_campaign_terminal"])
            self.assertFalse(manifest["prior_campaign_reused"])
            result = packet / "results" / "qualification"
            qualify = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(packet / "mtr-dogfood-remaining-lane.pyz"),
                    "--qualification-only",
                    "--packet-root",
                    str(packet),
                    "--router-repository",
                    str(ROUTER),
                    "--qwen-repository",
                    str(QWEN),
                    "--workspace-parent",
                    str(base / "workspaces"),
                    "--result-root",
                    str(result),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
                timeout=240,
            )
            self.assertEqual(qualify.returncode, 0, qualify.stderr + qualify.stdout)
            closeout = json.loads(qualify.stdout)
            self.assertEqual(closeout["status"], "passed")
            self.assertFalse(closeout["campaign_started"])
            self.assertEqual(closeout["starts_consumed"], 0)
            self.assertEqual(closeout["maximum_new_starts"], 1)
            self.assertEqual(closeout["process_accounting"]["os_child_process_started"], 0)
            self.assertEqual(
                closeout["outcomes"][0]["qualification_state"],
                "START_RESERVATION_REQUESTED",
            )
            self.assertTrue(closeout["source_repositories_unchanged"])
            blocked = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(packet / "mtr-dogfood-remaining-lane.pyz"),
                    "--packet-root",
                    str(packet),
                    "--router-repository",
                    str(ROUTER),
                    "--qwen-repository",
                    str(QWEN),
                    "--workspace-parent",
                    str(base / "blocked-workspaces"),
                    "--result-root",
                    str(packet / "results" / "blocked-dirty-source"),
                    "--runner-pid",
                    "1",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
                timeout=120,
            )
            self.assertNotEqual(blocked.returncode, 0)
            blocked_result = json.loads(blocked.stdout)
            self.assertEqual(
                blocked_result["error"],
                "FINAL_EXECUTION_ARTIFACT_BINDING_DRIFT",
            )
            self.assertFalse(blocked_result["campaign_started"])
            self.assertEqual(blocked_result["real_model_process_starts"], 0)


if __name__ == "__main__":
    unittest.main()