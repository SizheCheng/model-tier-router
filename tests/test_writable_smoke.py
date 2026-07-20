from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from mtr_dogfood.config import load_json
from mtr_dogfood.external_runner import product_tasks_allowed
from mtr_dogfood.process_ancestry import NestedCodexAncestorError
from mtr_dogfood.runtime_contract import ProcessAccounting
from mtr_dogfood.writable_smoke import (
    run_writable_smoke,
    validate_external_command_shape,
)


ROOT = Path(__file__).resolve().parents[1]


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

    def test_success_uses_fixture_local_transport_and_exact_one_start(self):
        captured = {}

        def launcher(**kwargs):
            captured.update(kwargs)
            self.assertEqual(kwargs["command"][0], "fake-codex.exe")
            kwargs["on_process_started"]()
            worktree = Path(kwargs["worktree"])
            result_path = worktree / self.contract["fixture_smoke"]["result_path"]
            result_path.parent.mkdir(parents=True)
            result_path.write_bytes(b"WORKSPACE_WRITE_OK\n")
            output = Path(
                kwargs["command"][
                    kwargs["command"].index("--output-last-message") + 1
                ]
            )
            output.write_text(
                json.dumps({
                    "schema_version": "1.0.0",
                    "status": "completed",
                    "summary": "synthetic fixture write completed",
                    "changed_paths": ["smoke/result.txt"],
                    "prohibited_action_attempted": False,
                    "notes": [],
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
