from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from mtr_dogfood.config import load_json
from mtr_dogfood.external_runner import product_tasks_allowed
from mtr_dogfood.process_ancestry import NestedCodexAncestorError
from mtr_dogfood.r2_contract import PayloadValidationError
from mtr_dogfood.runtime_contract import ProcessAccounting
from mtr_dogfood.writable_smoke import (
    build_external_codex_command,
    run_writable_smoke,
    validate_external_command_shape,
)


ROOT = Path(__file__).resolve().parents[1]
PARSER_FIXTURE = ROOT / "tests" / "fixtures" / "fake_codex_parser.py"


def run_parser_fixture(command: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "-B", str(PARSER_FIXTURE), *command[1:]],
        cwd=ROOT,
        input=b"",
        capture_output=True,
        check=False,
    )


def old_invalid_order(command: list[str]) -> list[str]:
    invalid = [command[0], *command[3:]]
    insertion = invalid.index("read-only") + 1
    invalid[insertion:insertion] = ["--ask-for-approval", "never"]
    return invalid


def successful_result():
    return {
        "exit_code": 0,
        "child_process_started": True,
        "model_execution_observed": True,
        "model_execution_completed": True,
        "infrastructure_failure_class": None,
        "host_policy_failure_count": 0,
        "input_tokens": 11,
        "cached_input_tokens": 3,
        "output_tokens": 5,
        "reasoning_output_tokens": 2,
    }


class WritableSmokeTests(unittest.TestCase):
    def setUp(self):
        self.contract = load_json(
            ROOT / "contracts" / "MODEL_TIER_ROUTER_DOGFOOD_R3_EXTERNAL_RUNTIME.json"
        )

    def test_builder_renders_global_and_exec_options_as_exact_argv(self):
        with tempfile.TemporaryDirectory() as directory:
            worktree = Path(directory) / "workspace with spaces" / "路径"
            worktree.mkdir(parents=True)
            schema = worktree / "schema folder" / "结果 schema.json"
            output = worktree / "output folder" / "final 结果.json"
            model = 'fixture-"quoted"-model'
            command = build_external_codex_command(
                "fake-codex.exe", worktree, model, "low", schema, output
            )
            self.assertEqual(
                command,
                [
                    "fake-codex.exe", "--ask-for-approval", "never", "exec",
                    "-C", str(worktree.resolve()), "--ephemeral", "--model",
                    model, "-c", 'model_reasoning_effort="low"', "-c",
                    "memories.generate_memories=false", "--sandbox",
                    "read-only", "--json", "--output-schema",
                    str(schema.resolve()), "--output-last-message",
                    str(output.resolve()), "-",
                ],
            )
            self.assertIsInstance(command, list)
            self.assertTrue(all(isinstance(value, str) for value in command))
            self.assertIn("\\", command[5])
            self.assertIn("路径", command[5])
            self.assertEqual(command[8], model)
            validate_external_command_shape(command, worktree)

    def test_synthetic_parser_rejects_old_order_and_accepts_repair(self):
        with tempfile.TemporaryDirectory() as directory:
            worktree = Path(directory)
            repaired = build_external_codex_command(
                "fake-codex.exe", worktree, "fake-model", "low",
                worktree / "schema.json", worktree / "result.json",
            )
            rejected = run_parser_fixture(old_invalid_order(repaired))
            self.assertEqual(rejected.returncode, 2)
            self.assertEqual(rejected.stdout, b"")
            self.assertEqual(
                rejected.stderr,
                b"error: unexpected argument '--ask-for-approval' found\n",
            )
            accepted = run_parser_fixture(repaired)
            self.assertEqual(accepted.returncode, 0)
            self.assertEqual(accepted.stderr, b"")
            self.assertFalse(accepted.stdout.startswith(b"\xef\xbb\xbf"))
            payload = json.loads(accepted.stdout.decode("utf-8"))
            self.assertTrue(payload["accepted"])
            self.assertEqual(payload["argv"], repaired[1:])
            self.assertEqual(payload["prompt_bytes_read"], 0)
            self.assertEqual(payload["api_or_model_request_count"], 0)
            self.assertEqual(payload["model_execution_count"], 0)
            self.assertEqual(payload["attempts_consumed"], 0)

    def test_command_validation_fails_closed_for_missing_and_unsupported_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            worktree = Path(directory)
            command = build_external_codex_command(
                "fake-codex.exe", worktree, "fake-model", "low",
                worktree / "schema.json", worktree / "result.json",
            )
            missing = command.copy()
            missing.pop(2)
            with self.assertRaises(PayloadValidationError):
                validate_external_command_shape(missing, worktree)
            unsupported = command.copy()
            unsupported.insert(15, "--unsupported")
            with self.assertRaises(PayloadValidationError):
                validate_external_command_shape(unsupported, worktree)
            completed = run_parser_fixture(unsupported)
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(completed.stdout, b"")
            self.assertTrue(completed.stderr.startswith(b"error: "))

    def test_parser_fixture_preserves_accounting_and_is_not_real_codex(self):
        with tempfile.TemporaryDirectory() as directory:
            worktree = Path(directory)
            command = build_external_codex_command(
                "fake-codex.exe", worktree, "fake-model", "medium",
                worktree / "schema.json", worktree / "result.json",
            )
            budget = ProcessAccounting()
            completed = run_parser_fixture(command)
            self.assertEqual(completed.args[0], sys.executable)
            self.assertNotEqual(Path(completed.args[0]).name.casefold(), "codex.exe")
            self.assertEqual(completed.returncode, 0)
            self.assertEqual(completed.stderr, b"")
            self.assertEqual(budget.prelaunch_validation_attempted, 0)
            self.assertEqual(budget.os_child_process_started, 0)
            self.assertEqual(budget.model_execution_observed, 0)
            self.assertEqual(budget.model_execution_completed, 0)

    def test_success_uses_fixture_local_transport_and_exact_one_start(self):
        captured = {}

        def launcher(**kwargs):
            captured.update(kwargs)
            self.assertEqual(kwargs["command"][0], "fake-codex.exe")
            kwargs["on_process_started"]()
            worktree = Path(kwargs["worktree"])
            content = "WORKSPACE_WRITE_OK\n"
            payload = content.encode("utf-8")
            output = Path(
                kwargs["command"][
                    kwargs["command"].index("--output-last-message") + 1
                ]
            )
            output.write_text(
                json.dumps({
                    "schema_version": "1.0.0",
                    "status": "completed",
                    "summary": "synthetic read-only proposal completed",
                    "notes": [],
                    "proposed_files": [{
                        "target_alias": "smoke_result",
                        "representation": "utf8_text",
                        "encoding": "UTF-8",
                        "content": content,
                        "utf8_byte_count": len(payload),
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "line_endings": "LF",
                        "media_type": "text/plain",
                    }],
                    "validation_expectations": [{
                        "name": "exact bytes",
                        "expectation": "parent verifies exact smoke bytes",
                        "required": True,
                    }],
                }),
                encoding="utf-8",
            )
            Path(kwargs["raw_directory"], "codex-events.jsonl").write_text(
                json.dumps({
                    "type": "turn.completed",
                    "usage": {
                        "input_tokens": 11,
                        "cached_input_tokens": 3,
                        "output_tokens": 5,
                        "reasoning_output_tokens": 2,
                    },
                }) + "\n",
                encoding="utf-8",
            )
            return successful_result()

        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            budget = ProcessAccounting()
            receipt_path = parent / "receipt.json"
            receipt = run_writable_smoke(
                self.contract,
                ROOT,
                budget,
                launcher,
                lambda: {"ordinary_powershell_ancestor_verified": True},
                lambda: "fake-codex.exe",
                parent / "raw",
                receipt_path,
                fixture_parent=parent,
            )
            self.assertTrue(receipt["accepted"])
            self.assertTrue(receipt["fixture_removed"])
            self.assertEqual(budget.os_child_process_started, 1)
            self.assertEqual(budget.model_execution_observed, 1)
            command = captured["command"]
            worktree = Path(captured["worktree"])
            validate_external_command_shape(command, worktree)
            schema = Path(command[command.index("--output-schema") + 1])
            output = Path(command[command.index("--output-last-message") + 1])
            self.assertTrue(schema.is_relative_to(worktree))
            self.assertTrue(output.is_relative_to(worktree))
            self.assertFalse(worktree.exists())

    def test_host_policy_failure_is_not_retried_and_stops_products(self):
        calls = []

        def launcher(**kwargs):
            calls.append(kwargs["command"])
            kwargs["on_process_started"]()
            return {
                **successful_result(),
                "exit_code": 0,
                "model_execution_observed": True,
                "model_execution_completed": True,
                "host_policy_failure_count": 1,
                "infrastructure_failure_class": (
                    "HOST_POLICY_REJECTED_CHILD_FILESYSTEM_ACCESS"
                ),
            }

        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            budget = ProcessAccounting()
            receipt = run_writable_smoke(
                self.contract,
                ROOT,
                budget,
                launcher,
                lambda: {},
                lambda: "fake-codex.exe",
                parent / "raw",
                parent / "receipt.json",
                fixture_parent=parent,
            )
        self.assertFalse(receipt["accepted"])
        self.assertEqual(
            receipt["failure_class"],
            "HOST_POLICY_REJECTED_CHILD_FILESYSTEM_ACCESS",
        )
        self.assertEqual(len(calls), 1)
        self.assertEqual(budget.os_child_process_started, 1)
        self.assertFalse(product_tasks_allowed(receipt))

    def test_nested_refusal_precedes_fixture_and_executable_resolution(self):
        resolver_called = False

        def resolver():
            nonlocal resolver_called
            resolver_called = True
            return "fake-codex.exe"

        def reject():
            raise NestedCodexAncestorError("NESTED_CODEX_ANCESTOR_DETECTED")

        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            with self.assertRaises(NestedCodexAncestorError):
                run_writable_smoke(
                    self.contract,
                    ROOT,
                    ProcessAccounting(),
                    lambda **kwargs: self.fail("launcher must not run"),
                    reject,
                    resolver,
                    parent / "raw",
                    parent / "receipt.json",
                    fixture_parent=parent,
                )
            self.assertEqual(list(parent.iterdir()), [])
        self.assertFalse(resolver_called)

    def test_missing_fake_executable_consumes_no_process_start(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            budget = ProcessAccounting()
            receipt = run_writable_smoke(
                self.contract,
                ROOT,
                budget,
                lambda **kwargs: self.fail("launcher must not run"),
                lambda: {},
                lambda: (_ for _ in ()).throw(FileNotFoundError()),
                parent / "raw",
                parent / "receipt.json",
                fixture_parent=parent,
            )
        self.assertEqual(receipt["failure_class"], "MISSING_COMMAND")
        self.assertEqual(budget.prelaunch_validation_attempted, 1)
        self.assertEqual(budget.os_child_process_started, 0)


if __name__ == "__main__":
    unittest.main()
