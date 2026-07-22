from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.build_qualification_artifact import materialize_head
from mtr_dogfood.qualification import self_test, verify_packet
from mtr_dogfood.router_adapter import verify_decision
from tests.r5k_regression_fixture import materialize_r5k_regression_packet


ROOT = Path(__file__).resolve().parents[1]


class QualificationTests(unittest.TestCase):
    def test_embedded_asset_contract_is_available(self):
        receipt = self_test()
        self.assertEqual(receipt["status"], "passed")
        self.assertEqual(receipt["real_model_process_starts"], 0)
        self.assertEqual(receipt["real_model_requests"], 0)
        self.assertEqual(
            set(receipt["assets"]),
            {
                "authority-receipt.schema.json",
                "bounded-writer-receipt.schema.json",
                "bounded-writer.py",
                "host-materialization-lanes.json",
                "proposed-files-result.schema.json",
                "task.schema.json",
            },
        )

    def test_wrapper_resolves_psscriptroot_after_param_binding(self):
        wrapper = (
            ROOT / "qualification" / "RUN_QUALIFICATION.ps1"
        ).read_bytes()
        self.assertEqual(wrapper.replace(b"\r\n", b"").count(b"\r"), 0)
        text = wrapper.decode("utf-8").replace("\r\n", "\n")
        param_block = text.split("\n)\n", 1)[0]
        self.assertNotIn("$PSScriptRoot", param_block)
        self.assertIn("Join-Path $PSScriptRoot", text)

    def test_tracked_text_policy_and_head_materialization_preserve_lf_bytes(self):
        self.assertEqual(
            (ROOT / ".gitattributes").read_bytes(),
            b"* text=auto eol=lf\n",
        )
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository"
            repository.mkdir()
            commands = (
                ["git", "init", "-q", "-b", "main"],
                ["git", "config", "user.name", "Fixture"],
                ["git", "config", "user.email", "fixture@example.invalid"],
                ["git", "config", "core.autocrlf", "true"],
            )
            for command in commands:
                subprocess.run(command, cwd=repository, check=True)
            sample = repository / "sample.txt"
            sample.write_bytes(b"line-one\nline-two\n")
            subprocess.run(["git", "add", "sample.txt"], cwd=repository, check=True)
            subprocess.run(
                ["git", "commit", "-q", "-m", "baseline"],
                cwd=repository,
                check=True,
            )
            head = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repository,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            sample.write_bytes(b"line-one\r\nline-two\r\n")
            archived = Path(temporary) / "archived"
            materialize_head(repository, head, archived)
            committed = subprocess.run(
                ["git", "show", "HEAD:sample.txt"],
                cwd=repository,
                capture_output=True,
                check=True,
            ).stdout
            self.assertEqual(committed, b"line-one\nline-two\n")
            self.assertEqual((archived / "sample.txt").read_bytes(), committed)
            self.assertNotEqual(sample.read_bytes(), committed)

    def test_packet_verifier_rejects_data_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = root / "payload.json"
            payload.write_bytes(b"{}\n")
            digest = hashlib.sha256(payload.read_bytes()).hexdigest()
            (root / "PACKET_SHA256SUMS.txt").write_text(
                f"{digest}  payload.json\n", encoding="utf-8"
            )
            self.assertEqual(verify_packet(root)["status"], "passed")
            payload.write_bytes(b"{\"changed\":true}\n")
            with self.assertRaisesRegex(RuntimeError, "PACKET_HASH_DRIFT"):
                verify_packet(root)

    def test_r5k_frozen_decisions_are_valid_regression_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            packet = materialize_r5k_regression_packet(Path(temporary), ROOT)
            manifest = json.loads(
                (packet / "EXECUTION_MANIFEST.json").read_text(encoding="utf-8")
            )
            known_profiles = set(manifest["model_mapping"])
            for lane in manifest["lanes"]:
                expected = json.loads(
                    (packet / lane["decision_snapshot"]).read_text(
                        encoding="utf-8"
                    )
                )
                self.assertEqual(
                    verify_decision(expected, expected, known_profiles),
                    expected,
                )

    def test_final_zipapp_self_test_uses_built_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(ROOT / "scripts" / "build_qualification_artifact.py"),
                    "--output-directory",
                    temporary,
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
                timeout=120,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            artifact = Path(temporary) / "mtr-dogfood-qualification.pyz"
            receipt = subprocess.run(
                [sys.executable, "-B", str(artifact), "--self-test"],
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )
            self.assertEqual(receipt.returncode, 0, receipt.stderr)
            value = json.loads(receipt.stdout)
            self.assertEqual(value["status"], "passed")
            self.assertEqual(value["real_model_process_starts"], 0)
            self.assertEqual(value["real_model_requests"], 0)

    def test_final_zipapp_build_is_byte_reproducible(self):
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
                    ],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=120,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                artifacts.append(
                    (Path(output) / "mtr-dogfood-qualification.pyz").read_bytes()
                )
            self.assertEqual(artifacts[0], artifacts[1])


if __name__ == "__main__":
    unittest.main()
