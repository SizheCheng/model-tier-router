from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from mtr_dogfood.bounded_writer import (
    POLICY_FILENAME,
    RECEIPT_DIRECTORY,
    validate_writer_receipts,
)
from mtr_dogfood.external_runner import (
    BOUNDED_WRITER_RELATIVE,
    _inspect_bounded_write,
    _scan_child_commands,
    _split_child_command,
    _substantive_lane_content,
    _target_aliases,
    classify_external_attempt,
)
from mtr_dogfood.r2_contract import validate_instance


ROOT = Path(__file__).resolve().parents[1]
WRITER = ROOT / "src/mtr_dogfood/bounded_writer.py"
FIXTURE = ROOT / "tests/fixtures/r4a-bounded-writer-command-events.json"
SMOKE_ALIASES = {"smoke_result": "smoke/result.txt"}


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def install(workspace: Path, aliases=None, limit: int = 1_000_000) -> tuple[Path, Path]:
    metadata = workspace / ".mtr-dogfood-r4"
    metadata.mkdir(parents=True)
    helper = metadata / "bounded-writer.py"
    policy = metadata / POLICY_FILENAME
    shutil.copyfile(WRITER, helper)
    policy.write_text(json.dumps({
        "schema_version": "2.0.0",
        "workspace": str(workspace.resolve()),
        "target_aliases": aliases or SMOKE_ALIASES,
        "max_content_bytes": limit,
    }, sort_keys=True), encoding="utf-8")
    return helper, policy


def run(workspace: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-B", BOUNDED_WRITER_RELATIVE, *arguments],
        cwd=workspace,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )


def validate(workspace: Path, aliases=None) -> dict:
    metadata = workspace / ".mtr-dogfood-r4"
    return validate_writer_receipts(
        workspace=workspace,
        helper_sha256=hashlib.sha256(
            (metadata / "bounded-writer.py").read_bytes()
        ).hexdigest(),
        policy_sha256=hashlib.sha256(
            (metadata / POLICY_FILENAME).read_bytes()
        ).hexdigest(),
        target_aliases=aliases or SMOKE_ALIASES,
    )


def command_event(command: str, output: str, exit_code: int = 0) -> dict:
    return {
        "type": "item.completed",
        "item": {
            "id": "writer-1",
            "type": "command_execution",
            "command": f'"powershell.exe" -Command "{command}"',
            "aggregated_output": output,
            "exit_code": exit_code,
            "status": "completed" if exit_code == 0 else "failed",
        },
    }


class HistoricalR4AProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_exact_raw_event_lines_are_byte_and_hash_bound(self):
        self.assertEqual([event["event_index"] for event in self.fixture["events"]], [3, 4])
        for event in self.fixture["events"]:
            raw = base64.b64decode(event["raw_line_base64"], validate=True)
            self.assertEqual(len(raw), event["raw_line_byte_count"])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), event["raw_line_sha256"])
            self.assertEqual(json.loads(raw), event["decoded_event"])

    def test_event_pair_has_same_display_command_and_no_structured_argv(self):
        started, completed = [entry["decoded_event"]["item"] for entry in self.fixture["events"]]
        self.assertEqual(started["command"], completed["command"])
        self.assertNotIn("executable", completed)
        self.assertNotIn("argv", completed)
        self.assertIsNone(started["exit_code"])
        self.assertEqual(completed["exit_code"], 1)

    def test_exact_child_failure_and_model_note_are_preserved(self):
        completed = self.fixture["events"][1]["decoded_event"]["item"]
        self.assertIn("Could not find file", completed["aggregated_output"])
        self.assertIn("lane-policy.json", completed["aggregated_output"])
        self.assertIn("target path must be workspace-relative", completed["aggregated_output"])
        self.assertEqual(
            self.fixture["exact_model_failure_note"],
            "The lane-policy file was absent, and the writer rejected the absolute "
            "target path as not workspace-relative. The single allowed invocation was consumed.",
        )

    def test_historical_display_falls_outside_simple_future_grammar(self):
        command = self.fixture["events"][1]["decoded_event"]["item"]["command"]
        executable, argv, payload, parsed = _split_child_command(command)
        self.assertTrue(parsed)
        self.assertTrue(executable.casefold().endswith("pwsh.exe"))
        self.assertIn("-Command", payload)
        inspection = _inspect_bounded_write(payload, SMOKE_ALIASES)
        self.assertTrue(inspection["recognized"])
        self.assertFalse(inspection["authorized"])
        self.assertEqual(inspection["reason"], "malformed_bounded_writer_command")
        self.assertGreater(len(argv), 2)

    def test_malformed_writer_has_narrow_non_security_classification(self):
        execution = {
            "model_execution_observed": True,
            "model_execution_completed": True,
            "host_policy_failure_count": 0,
            "infrastructure_failure_class": None,
        }
        value = classify_external_attempt(
            execution, {}, output_valid=True, schema_unchanged=True,
            changed=[], changed_paths_allowed=False, automated_acceptance=False,
            forbidden_action=False, malformed_bounded_writer_invocation=True,
        )
        self.assertEqual(value, "MALFORMED_BOUNDED_WRITER_INVOCATION")

    def test_true_security_violation_keeps_precedence(self):
        execution = {
            "model_execution_observed": True,
            "model_execution_completed": True,
            "host_policy_failure_count": 0,
            "infrastructure_failure_class": None,
        }
        value = classify_external_attempt(
            execution, {}, output_valid=True, schema_unchanged=True,
            changed=[], changed_paths_allowed=False, automated_acceptance=False,
            forbidden_action=True, malformed_bounded_writer_invocation=True,
        )
        self.assertEqual(value, "UNAUTHORIZED_ACTION")


class AliasWriterReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp.name) / ("workspace with spaces " + "\u6d4b\u8bd5")
        self.workspace.mkdir()
        install(self.workspace)

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self, content: bytes = b"WORKSPACE_WRITE_OK\n"):
        return run(
            self.workspace, "--slot", "smoke_result",
            "--content-base64", b64(content),
        )

    def test_alias_map_is_exact_and_case_sensitive(self):
        self.assertEqual(_target_aliases(["smoke/result.txt"]), SMOKE_ALIASES)
        self.assertEqual(self.invoke().returncode, 0)
        self.assertEqual(
            run(
                self.workspace, "--slot", "Smoke_Result",
                "--content-base64", b64(b"blocked\n"),
            ).returncode,
            2,
        )

    def test_simple_invocation_writes_exact_bytes_and_atomic_receipt(self):
        completed = self.invoke()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        receipt = json.loads(completed.stdout)
        self.assertEqual((self.workspace / "smoke/result.txt").read_bytes(), b"WORKSPACE_WRITE_OK\n")
        self.assertEqual(receipt["target_alias"], "smoke_result")
        self.assertEqual(receipt["relative_path"], "smoke/result.txt")
        self.assertEqual(receipt["content_encoding"], "base64-utf8")
        self.assertEqual(receipt["content_sha256"], receipt["post_write_file_sha256"])
        receipt_files = list(
            (self.workspace / ".mtr-dogfood-r4" / RECEIPT_DIRECTORY).glob("*.json")
        )
        self.assertEqual(len(receipt_files), 1)
        self.assertEqual(list(receipt_files[0].parent.glob("*.tmp")), [])

    def test_parent_receipt_validation_binds_hashes_and_actual_file(self):
        self.invoke()
        result = validate(self.workspace)
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(result["receipt_count"], 1)
        self.assertEqual(result["receipts"][0]["canonical_workspace"], str(self.workspace.resolve()))

    def test_missing_receipt_fails_parent_validation_when_command_is_scanned(self):
        completed = self.invoke()
        shutil.rmtree(self.workspace / ".mtr-dogfood-r4" / RECEIPT_DIRECTORY)
        events = self.workspace / "events.jsonl"
        command = (
            f"python -B {BOUNDED_WRITER_RELATIVE} --slot smoke_result "
            f"--content-base64 {b64(b'WORKSPACE_WRITE_OK\n')}"
        )
        events.write_text(json.dumps(command_event(command, completed.stdout)) + "\n", encoding="utf-8")
        scan = _scan_child_commands(events, [], self.workspace, SMOKE_ALIASES, [])
        self.assertTrue(scan["bounded_write_violation_detected"])
        self.assertTrue(scan["malformed_bounded_writer_invocation_detected"])

    def test_tampered_receipt_is_rejected(self):
        self.invoke()
        path = next((self.workspace / ".mtr-dogfood-r4" / RECEIPT_DIRECTORY).glob("*.json"))
        value = json.loads(path.read_text(encoding="utf-8"))
        value["content_sha256"] = "0" * 64
        path.write_text(json.dumps(value), encoding="utf-8")
        result = validate(self.workspace)
        self.assertFalse(result["valid"])
        self.assertIn("actual file", result["errors"][0])

    def test_fake_receipt_is_not_authority(self):
        receipt_root = self.workspace / ".mtr-dogfood-r4" / RECEIPT_DIRECTORY
        receipt_root.mkdir()
        (receipt_root / ("0" * 32 + ".json")).write_text(
            json.dumps({"schema_version": "1.0.0"}), encoding="utf-8"
        )
        result = validate(self.workspace)
        self.assertFalse(result["valid"])

    def test_duplicate_alias_receipts_are_rejected(self):
        self.assertEqual(self.invoke(b"same\n").returncode, 0)
        self.assertEqual(self.invoke(b"same\n").returncode, 0)
        result = validate(self.workspace)
        self.assertFalse(result["valid"])
        self.assertTrue(any("duplicated" in error for error in result["errors"]))

    def test_incorrect_parent_helper_hash_rejects_receipt(self):
        self.invoke()
        metadata = self.workspace / ".mtr-dogfood-r4"
        policy_hash = hashlib.sha256((metadata / POLICY_FILENAME).read_bytes()).hexdigest()
        result = validate_writer_receipts(
            workspace=self.workspace, helper_sha256="0" * 64,
            policy_sha256=policy_hash, target_aliases=SMOKE_ALIASES,
        )
        self.assertFalse(result["valid"])

    def test_incorrect_parent_policy_hash_rejects_receipt(self):
        self.invoke()
        metadata = self.workspace / ".mtr-dogfood-r4"
        helper_hash = hashlib.sha256((metadata / "bounded-writer.py").read_bytes()).hexdigest()
        result = validate_writer_receipts(
            workspace=self.workspace, helper_sha256=helper_hash,
            policy_sha256="0" * 64, target_aliases=SMOKE_ALIASES,
        )
        self.assertFalse(result["valid"])

    def test_arbitrary_path_argument_is_not_supported(self):
        completed = run(
            self.workspace, "--target", "smoke/result.txt",
            "--content-base64", b64(b"blocked\n"),
        )
        self.assertNotEqual(completed.returncode, 0)

    def test_unknown_alias_is_rejected_without_deliverable(self):
        completed = run(
            self.workspace, "--slot", "unknown_alias",
            "--content-base64", b64(b"blocked\n"),
        )
        self.assertEqual(completed.returncode, 2)
        self.assertFalse((self.workspace / "smoke/result.txt").exists())

    def test_empty_and_over_limit_content_are_rejected(self):
        self.assertEqual(self.invoke(b"").returncode, 2)
        policy = self.workspace / ".mtr-dogfood-r4" / POLICY_FILENAME
        value = json.loads(policy.read_text(encoding="utf-8"))
        value["max_content_bytes"] = 4
        policy.write_text(json.dumps(value), encoding="utf-8")
        self.assertEqual(self.invoke(b"12345").returncode, 2)

    def test_maximum_content_and_both_line_endings_are_exact(self):
        policy = self.workspace / ".mtr-dogfood-r4" / POLICY_FILENAME
        value = json.loads(policy.read_text(encoding="utf-8"))
        value["max_content_bytes"] = 8
        policy.write_text(json.dumps(value), encoding="utf-8")
        self.assertEqual(self.invoke(b"a\r\nb\n123").returncode, 0)
        self.assertEqual((self.workspace / "smoke/result.txt").read_bytes(), b"a\r\nb\n123")

    def test_existing_target_status_is_recorded(self):
        target = self.workspace / "smoke/result.txt"
        target.parent.mkdir()
        target.write_bytes(b"old\n")
        receipt = json.loads(self.invoke(b"new\n").stdout)
        self.assertTrue(receipt["preexisting_target"])
        self.assertEqual(target.read_bytes(), b"new\n")

    def test_protected_and_escaping_policy_targets_are_rejected(self):
        cases = [
            "../escape.txt", r"C:\outside.txt", r"\\server\share\x.txt",
            r"C:drive-relative.txt", r"\rooted.txt", r"\\?\C:\extended.txt",
            ".codex/auth.json", ".git/config",
            ".mtr-dogfood-r4/bounded-write-policy.json",
        ]
        policy = self.workspace / ".mtr-dogfood-r4" / POLICY_FILENAME
        for target in cases:
            with self.subTest(target=target):
                policy.write_text(json.dumps({
                    "schema_version": "2.0.0",
                    "workspace": str(self.workspace.resolve()),
                    "target_aliases": {"bad": target},
                    "max_content_bytes": 100,
                }), encoding="utf-8")
                completed = run(
                    self.workspace, "--slot", "bad",
                    "--content-base64", b64(b"blocked\n"),
                )
                self.assertEqual(completed.returncode, 2)


class ReceiptBackedScannerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp.name) / "workspace"
        self.workspace.mkdir()
        install(self.workspace)
        self.events = self.workspace / "events.jsonl"

    def tearDown(self):
        self.temp.cleanup()

    def test_simple_display_command_requires_matching_receipt_and_output(self):
        content = b"WORKSPACE_WRITE_OK\n"
        completed = run(
            self.workspace, "--slot", "smoke_result",
            "--content-base64", b64(content),
        )
        command = (
            f"python -B {BOUNDED_WRITER_RELATIVE} --slot smoke_result "
            f"--content-base64 {b64(content)}"
        )
        self.events.write_text(
            json.dumps(command_event(command, completed.stdout)) + "\n",
            encoding="utf-8",
        )
        receipts = validate(self.workspace)["receipts"]
        scan = _scan_child_commands(
            self.events, [], self.workspace, SMOKE_ALIASES, receipts
        )
        self.assertFalse(scan["bounded_write_violation_detected"])
        self.assertEqual(scan["bounded_write_aliases"], ["smoke_result"])
        self.assertEqual(scan["bounded_write_targets"], ["smoke/result.txt"])

    def test_structured_python_argv_is_recognized_without_display_reconstruction(self):
        content = b"WORKSPACE_WRITE_OK\n"
        completed = run(
            self.workspace, "--slot", "smoke_result",
            "--content-base64", b64(content),
        )
        event = {
            "type": "item.completed",
            "item": {
                "id": "structured-writer",
                "type": "command_execution",
                "executable": sys.executable,
                "argv": [
                    "-B", BOUNDED_WRITER_RELATIVE, "--slot", "smoke_result",
                    "--content-base64", b64(content),
                ],
                "aggregated_output": completed.stdout,
                "exit_code": 0,
                "status": "completed",
            },
        }
        self.events.write_text(json.dumps(event) + "\n", encoding="utf-8")
        scan = _scan_child_commands(
            self.events, [], self.workspace, SMOKE_ALIASES,
            validate(self.workspace)["receipts"],
        )
        self.assertEqual(scan["bounded_write_count"], 1)
        self.assertEqual(
            scan["command_records"][0]["command_source"], "structured_event"
        )

    def test_display_string_alone_never_authorizes(self):
        command = (
            f"python -B {BOUNDED_WRITER_RELATIVE} --slot smoke_result "
            f"--content-base64 {b64(b'x\n')}"
        )
        self.events.write_text(
            json.dumps(command_event(command, "")) + "\n", encoding="utf-8"
        )
        scan = _scan_child_commands(
            self.events, [], self.workspace, SMOKE_ALIASES, []
        )
        self.assertTrue(scan["bounded_write_violation_detected"])
        self.assertEqual(scan["bounded_write_count"], 0)

    def test_unknown_alias_is_security_violation(self):
        command = (
            f"python -B {BOUNDED_WRITER_RELATIVE} --slot other "
            f"--content-base64 {b64(b'x\n')}"
        )
        self.events.write_text(
            json.dumps(command_event(command, "", 2)) + "\n", encoding="utf-8"
        )
        scan = _scan_child_commands(
            self.events, [], self.workspace, SMOKE_ALIASES, []
        )
        self.assertTrue(scan["bounded_write_security_violation_detected"])

    def test_direct_writes_and_extra_file_paths_are_rejected(self):
        commands = [
            "Set-Content smoke/result.txt blocked",
            "python -c \"open('smoke/result.txt','w').write('x')\"",
            "echo blocked > smoke/result.txt",
            "python -c \"open('extra.txt','w').write('x')\"",
        ]
        for command in commands:
            with self.subTest(command=command):
                self.events.write_text(
                    json.dumps(command_event(command, "")) + "\n",
                    encoding="utf-8",
                )
                scan = _scan_child_commands(
                    self.events, [], self.workspace, SMOKE_ALIASES, []
                )
                self.assertTrue(scan["bounded_write_security_violation_detected"])

    def test_unmatched_fake_receipt_is_rejected(self):
        target = self.workspace / "smoke/result.txt"
        target.parent.mkdir()
        target.write_bytes(b"fake\n")
        metadata = self.workspace / ".mtr-dogfood-r4"
        helper_hash = hashlib.sha256((metadata / "bounded-writer.py").read_bytes()).hexdigest()
        policy_hash = hashlib.sha256((metadata / POLICY_FILENAME).read_bytes()).hexdigest()
        fake = {
            "schema_version": "1.0.0", "invocation_id": "0" * 32,
            "helper_sha256": helper_hash, "policy_sha256": policy_hash,
            "target_alias": "smoke_result", "relative_path": "smoke/result.txt",
            "canonical_workspace": str(self.workspace.resolve()),
            "content_encoding": "base64-utf8", "content_byte_count": 5,
            "content_sha256": hashlib.sha256(b"fake\n").hexdigest(),
            "preexisting_target": False,
            "post_write_file_sha256": hashlib.sha256(b"fake\n").hexdigest(),
            "write_status": "written", "timestamp": "2026-07-21T00:00:00Z",
            "error_classification": None,
        }
        receipt_root = metadata / RECEIPT_DIRECTORY
        receipt_root.mkdir()
        (receipt_root / ("0" * 32 + ".json")).write_text(json.dumps(fake), encoding="utf-8")
        receipts = validate(self.workspace)["receipts"]
        self.events.write_text("", encoding="utf-8")
        scan = _scan_child_commands(
            self.events, [], self.workspace, SMOKE_ALIASES, receipts
        )
        self.assertTrue(scan["bounded_write_security_violation_detected"])


class ValidationSemanticsTests(unittest.TestCase):
    def test_success_receipt_matches_strict_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            install(root)
            completed = run(
                root, "--slot", "smoke_result",
                "--content-base64", b64(b"WORKSPACE_WRITE_OK\n"),
            )
            schema = json.loads(
                (ROOT / "schemas/bounded-writer-receipt.schema.json").read_text(
                    encoding="utf-8"
                )
            )
            validate_instance(json.loads(completed.stdout), schema)

    def test_absent_smoke_file_is_not_substantive(self):
        with tempfile.TemporaryDirectory() as directory:
            case = {
                "case_id": "writable_smoke",
                "changed_path_patterns": ["smoke/result.txt"],
            }
            self.assertFalse(_substantive_lane_content(case, Path(directory)))

    def test_smoke_requires_exact_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "smoke/result.txt"
            target.parent.mkdir()
            case = {
                "case_id": "writable_smoke",
                "changed_path_patterns": ["smoke/result.txt"],
            }
            target.write_bytes(b"wrong\n")
            self.assertFalse(_substantive_lane_content(case, root))
            target.write_bytes(b"WORKSPACE_WRITE_OK\n")
            self.assertTrue(_substantive_lane_content(case, root))

    def test_absent_non_smoke_required_file_is_not_substantive(self):
        with tempfile.TemporaryDirectory() as directory:
            case = {
                "case_id": "qwen-docx-hidden-elements-r1",
                "changed_path_patterns": ["tests/redaction/test_docx_package.py"],
            }
            self.assertFalse(_substantive_lane_content(case, Path(directory)))


if __name__ == "__main__":
    unittest.main()
