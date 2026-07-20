from __future__ import annotations

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mtr_dogfood.config import ContractError, load_json
from mtr_dogfood.external_runner import (
    ExternalRunner,
    _confidentiality_scan,
    _empty_closeout,
    _pool_state,
    _run_attempt,
    _scan_child_commands,
    classify_external_attempt,
    execute_lane,
)
from mtr_dogfood.git_worktrees import (
    commit_exact_paths,
    create_worktree,
    fast_forward,
    remove_worktree,
    repository_state,
)
from mtr_dogfood.runtime_contract import (
    ProcessAccounting,
    assert_control_action_allowed,
    next_escalation_profile,
    validate_closeout,
    validate_contract_paths,
    validate_runtime_contract,
)
from mtr_dogfood.r2_contract import PayloadValidationError
from mtr_dogfood.writable_smoke import (
    build_external_codex_command,
    validate_external_command_shape,
)
from mtr_dogfood.validation import freeze_validator_plan


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = (
    ROOT / "contracts" / "MODEL_TIER_ROUTER_DOGFOOD_R3_EXTERNAL_RUNTIME.json"
)


def run_git(repository, *arguments):
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    if completed.returncode:
        raise AssertionError(completed.stderr or completed.stdout)
    return completed.stdout.strip()


def initialize_repository(path):
    path.mkdir()
    run_git(path, "init", "-q", "-b", "main")
    (path / "README.md").write_text("baseline\n", encoding="utf-8")
    run_git(path, "add", "--", "README.md")
    run_git(
        path,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-q",
        "-m",
        "baseline",
    )
    return run_git(path, "rev-parse", "HEAD")


def attempt_outcome(profile, failure):
    accepted = not failure
    return {
        "profile": profile,
        "attempt": 1,
        "accepted": accepted,
        "failure_class": failure,
        "target_commit": "abc" if accepted else "",
        "branch": "retained" if accepted else "",
        "automatic_merge": False,
        "changed_paths": ["allowed.txt"] if accepted else [],
        "diff_sha256": "0" * 64,
        "usage": {
            "input_tokens": 1,
            "cached_input_tokens": 0,
            "output_tokens": 1,
            "reasoning_output_tokens": 0,
        },
    }


class RuntimeContractTests(unittest.TestCase):
    def setUp(self):
        self.contract = load_json(CONTRACT_PATH)

    def test_embedded_runtime_contract_strictly_validates(self):
        validated = validate_runtime_contract(copy.deepcopy(self.contract))
        self.assertEqual(validated["maximum_new_codex_exec_process_starts"], 5)
        validate_closeout(
            _empty_closeout(validated),
            load_json(ROOT / validated["paths"]["closeout_schema"]),
        )

    def test_runtime_contract_rejects_unknown_key(self):
        value = copy.deepcopy(self.contract)
        value["unexpected"] = True
        with self.assertRaises(ContractError):
            validate_runtime_contract(value)

    def test_external_child_command_rejects_any_extra_argument(self):
        with tempfile.TemporaryDirectory() as directory:
            worktree = Path(directory)
            schema = worktree / "schema.json"
            output = worktree / "result.json"
            command = build_external_codex_command(
                "fake-codex.exe", worktree, "fake-model", "low", schema, output
            )
            validate_external_command_shape(command, worktree)
            command.insert(-1, "--unexpected")
            with self.assertRaises(PayloadValidationError):
                validate_external_command_shape(command, worktree)

    def test_nested_external_runner_refuses_before_preflight_or_fixture(self):
        closeout_path = ROOT / self.contract["reporting"]["closeout"]
        self.assertFalse(closeout_path.exists())
        rows = {
            100: {"pid": 100, "parent_pid": 90, "name": "powershell.exe"},
            90: {"pid": 90, "parent_pid": 0, "name": "codex.exe"},
        }
        runner = ExternalRunner(
            CONTRACT_PATH,
            closeout_path,
            100,
            launcher=lambda **kwargs: self.fail("launcher must not run"),
            executable_resolver=lambda: "fake-codex.exe",
            process_provider=lambda pid: rows.get(pid),
        )
        try:
            with patch(
                "mtr_dogfood.external_runner._preflight",
                side_effect=AssertionError("preflight must not run"),
            ):
                closeout, exit_code = runner.run()
            self.assertEqual(exit_code, 2)
            self.assertTrue(closeout["nested_codex_ancestor_detected"])
            self.assertFalse(closeout["fixture_smoke"]["created"])
            self.assertEqual(
                closeout["hard_stop_code"], "NESTED_CODEX_ANCESTOR_DETECTED"
            )
            self.assertEqual(load_json(closeout_path), closeout)
        finally:
            closeout_path.unlink(missing_ok=True)

    def test_out_of_scope_repository_path_is_denied(self):
        value = copy.deepcopy(self.contract)
        value["repositories"]["model-tier-router"]["path"] = value["denylist"][0]
        with self.assertRaises(ContractError):
            validate_contract_paths(value, ROOT)

    def test_child_command_scan_rejects_relative_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            events = root / "events.jsonl"
            events.write_text(
                json.dumps({
                    "type": "item.completed",
                    "item": {
                        "type": "command_execution",
                        "command": r"Get-Content ..\outside\secret.txt",
                    },
                }) + "\n",
                encoding="utf-8",
            )
            scan = _scan_child_commands(events, [], root / "worktree")
            self.assertTrue(scan["external_path_access_detected"])

    def test_qwen_confidentiality_scan_accepts_synthetic_and_rejects_key(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "test_synthetic.py"
            path.write_text("value = 'SYNTHETIC_SECRET_001'\n", encoding="utf-8")
            self.assertTrue(_confidentiality_scan(
                root, "qwen-redaction-standalone", [path.name]
            ))
            path.write_text(
                "value = 'sk-abcdefghijklmnopqrstuvwxyz123456'\n",
                encoding="utf-8",
            )
            self.assertFalse(_confidentiality_scan(
                root, "qwen-redaction-standalone", [path.name]
            ))

    def test_fixed_control_actions_are_immutable(self):
        for action in ("rerun", "merge", "modify"):
            with self.subTest(action=action):
                with self.assertRaises(RuntimeError):
                    assert_control_action_allowed(action)


class ProcessAndEscalationTests(unittest.TestCase):
    def setUp(self):
        self.contract = load_json(CONTRACT_PATH)

    def test_global_budget_counts_exactly_five_os_process_starts(self):
        budget = ProcessAccounting(maximum=5)
        for _ in range(5):
            budget.record_prelaunch()
            budget.record_process_start()
        self.assertEqual(budget.os_child_process_started, 5)
        self.assertEqual(budget.remaining, 0)
        with self.assertRaisesRegex(RuntimeError, "CHILD_INVOCATION_LIMIT_REACHED"):
            budget.record_process_start()

    def test_host_policy_failure_is_classified_before_no_change(self):
        failure = classify_external_attempt(
            {
                "child_process_started": True,
                "model_execution_observed": True,
                "model_execution_completed": True,
                "host_policy_failure_count": 1,
                "infrastructure_failure_class": (
                    "HOST_POLICY_REJECTED_CHILD_FILESYSTEM_ACCESS"
                ),
            },
            {},
            output_valid=False,
            schema_unchanged=True,
            changed=[],
            changed_paths_allowed=False,
            automated_acceptance=False,
            forbidden_action=False,
        )
        self.assertEqual(
            failure, "HOST_POLICY_REJECTED_CHILD_FILESYSTEM_ACCESS"
        )
        self.assertIsNone(next_escalation_profile(
            self.contract, "balanced", failure, 0
        ))

    def test_out_of_scope_change_is_unauthorized_and_never_escalates(self):
        failure = classify_external_attempt(
            {
                "child_process_started": True,
                "model_execution_observed": True,
                "model_execution_completed": True,
                "host_policy_failure_count": 0,
                "infrastructure_failure_class": None,
            },
            {"status": "completed"},
            output_valid=True,
            schema_unchanged=True,
            changed=["outside-scope.txt"],
            changed_paths_allowed=False,
            automated_acceptance=False,
            forbidden_action=False,
        )
        self.assertEqual(failure, "UNAUTHORIZED_ACTION")
        self.assertIsNone(next_escalation_profile(
            self.contract, "balanced", failure, 0
        ))

    def test_implementation_incomplete_escalates_once(self):
        profiles = []

        def fake_attempt(*args):
            profile = args[5]
            profiles.append(profile)
            return attempt_outcome(
                profile,
                "IMPLEMENTATION_INCOMPLETE" if len(profiles) == 1 else "",
            )

        case = {
            "case_id": "mtr-docs-private-executor-r1",
            "repository": "model-tier-router",
            "baseline_head": self.contract["repositories"]["model-tier-router"][
                "baseline_head"
            ],
            "requires_confidential_payload": False,
            "requires_network": False,
            "requires_other_repository": False,
            "router_request": {},
        }
        decision = {
            "status": "recommended",
            "selected_profile": "balanced",
            "execution_authorized": False,
            "authorized_write_scope": [],
        }
        with patch(
            "mtr_dogfood.external_runner._load_frozen_case",
            return_value=(case, b"{}"),
        ), patch("mtr_dogfood.external_runner._task_still_useful"):
            lane = execute_lane(
                self.contract,
                self.contract["cases"][0],
                ProcessAccounting(),
                lambda **kwargs: {},
                lambda: {},
                lambda: "fake-codex.exe",
                ROOT,
                assessor=lambda *args: decision,
                attempt_runner=fake_attempt,
            )
        self.assertEqual(profiles, ["balanced", "premium"])
        self.assertEqual(lane["escalation_count"], 1)
        self.assertTrue(lane["accepted"])

    def test_host_policy_attempt_never_escalates(self):
        profiles = []

        def fake_attempt(*args):
            profiles.append(args[5])
            return attempt_outcome(
                args[5], "HOST_POLICY_REJECTED_CHILD_FILESYSTEM_ACCESS"
            )

        case = {
            "case_id": "mtr-docs-private-executor-r1",
            "repository": "model-tier-router",
            "baseline_head": self.contract["repositories"]["model-tier-router"][
                "baseline_head"
            ],
            "requires_confidential_payload": False,
            "requires_network": False,
            "requires_other_repository": False,
            "router_request": {},
        }
        decision = {
            "status": "recommended",
            "selected_profile": "balanced",
            "execution_authorized": False,
            "authorized_write_scope": [],
        }
        with patch(
            "mtr_dogfood.external_runner._load_frozen_case",
            return_value=(case, b"{}"),
        ), patch("mtr_dogfood.external_runner._task_still_useful"):
            lane = execute_lane(
                self.contract,
                self.contract["cases"][0],
                ProcessAccounting(),
                lambda **kwargs: {},
                lambda: {},
                lambda: "fake-codex.exe",
                ROOT,
                assessor=lambda *args: decision,
                attempt_runner=fake_attempt,
            )
        self.assertEqual(profiles, ["balanced"])
        self.assertEqual(lane["escalation_count"], 0)

    def test_second_escalation_is_refused(self):
        self.assertIsNone(next_escalation_profile(
            self.contract, "balanced", "IMPLEMENTATION_INCOMPLETE", 1
        ))


class TemporaryGitPolicyTests(unittest.TestCase):
    def test_fake_child_full_attempt_validates_commits_merges_and_cleans(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            harness = base / "harness"
            repository = base / "repository"
            pool = base / "pool"
            harness.mkdir()
            baseline = initialize_repository(repository)
            (harness / "schemas").mkdir()
            for name in (
                "execution-result.schema.json",
                "task.schema.json",
                "authority-receipt.schema.json",
            ):
                shutil.copyfile(ROOT / "schemas" / name, harness / "schemas" / name)

            validator_plan = {
                "commands": [{
                    "name": "focused-fake",
                    "layer": "focused",
                    "command": [
                        "python",
                        "-B",
                        "-c",
                        "from pathlib import Path; assert Path('docs.txt').read_text(encoding='utf-8') == 'validated\\n'",
                    ],
                    "timeout_seconds": 30,
                }]
            }
            case = {
                "schema_version": "1.0.0",
                "case_id": "fake-mtr-r3",
                "repository": "model-tier-router",
                "baseline_head": baseline,
                "title": "fake isolated change",
                "task_text": "Create docs.txt with deterministic synthetic text.",
                "changed_path_patterns": ["docs.txt"],
                "risk": "LOW_RISK",
                "change_class": "documentation",
                "validator_plan": validator_plan,
                "validator_plan_digest": freeze_validator_plan(validator_plan),
                "model_timeout_seconds": 30,
            }
            contract = load_json(CONTRACT_PATH)
            contract["paths"]["worktree_pool"] = str(pool)
            contract["repositories"] = {
                "model-tier-router": {
                    "path": str(repository),
                    "branch": "main",
                    "baseline_head": baseline,
                },
                "qwen-redaction-standalone": {
                    "path": str(base / "unused-qwen"),
                    "branch": "qwen-redaction-r1",
                    "baseline_head": "b" * 40,
                },
            }
            contract["reporting"]["receipt_root"] = "receipts"
            contract["reporting"]["raw_root"] = "raw"
            contract["commit_identity"] = {
                "name": "Fixture",
                "email": "fixture@example.invalid",
                "persistent_configuration": False,
            }
            descriptor = {
                "branch_prefix": "test/fake-router",
                "automatic_fast_forward_merge": True,
            }
            decision = {
                "status": "recommended",
                "selected_profile": "balanced",
                "execution_authorized": False,
                "authorized_write_scope": [],
            }

            def launcher(**kwargs):
                kwargs["on_process_started"]()
                worktree = Path(kwargs["worktree"])
                (worktree / "docs.txt").write_text(
                    "validated\n", encoding="utf-8"
                )
                output = Path(
                    kwargs["command"][
                        kwargs["command"].index("--output-last-message") + 1
                    ]
                )
                output.write_text(json.dumps({
                    "schema_version": "1.0.0",
                    "case_id": case["case_id"],
                    "status": "completed",
                    "summary": "fake child completed",
                    "changed_paths": ["docs.txt"],
                    "tests_run": [{
                        "command": "parent validators only",
                        "status": "not_run",
                    }],
                    "prohibited_action_attempted": False,
                    "notes": [],
                }), encoding="utf-8")
                raw = Path(kwargs["raw_directory"])
                raw.mkdir(parents=True, exist_ok=True)
                (raw / "codex-events.jsonl").write_text(
                    json.dumps({
                        "type": "turn.completed",
                        "usage": {
                            "input_tokens": 4,
                            "cached_input_tokens": 1,
                            "output_tokens": 2,
                            "reasoning_output_tokens": 1,
                        },
                    }) + "\n",
                    encoding="utf-8",
                )
                return {
                    "exit_code": 0,
                    "wall_time_seconds": 0.01,
                    "child_process_started": True,
                    "model_execution_observed": True,
                    "model_execution_completed": True,
                    "timed_out": False,
                    "host_policy_failure_count": 0,
                    "infrastructure_failure_class": None,
                    "rate_limit_event_count": 0,
                    "model_unavailable_event_count": 0,
                    "authentication_event_count": 0,
                    "output_schema_error_count": 0,
                    "input_tokens": 4,
                    "cached_input_tokens": 1,
                    "output_tokens": 2,
                    "reasoning_output_tokens": 1,
                }

            budget = ProcessAccounting()
            outcome = _run_attempt(
                contract,
                case,
                descriptor,
                b"{}",
                decision,
                "balanced",
                1,
                0,
                budget,
                launcher,
                lambda: {},
                lambda: "fake-codex.exe",
                harness,
            )
            self.assertTrue(outcome["accepted"])
            self.assertTrue(outcome["automatic_merge"])
            self.assertEqual(run_git(repository, "rev-parse", "HEAD"), outcome["target_commit"])
            self.assertEqual(budget.os_child_process_started, 1)
            self.assertEqual(_pool_state(pool, [repository])["entry_count"], 0)
            self.assertEqual(
                _pool_state(pool, [repository])["registered_worktree_count"], 0
            )
            self.assertTrue(repository_state(repository)["clean"])

    def test_low_risk_fast_forward_and_qwen_branch_retention(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            pool = root / "pool"
            baseline = initialize_repository(repository)

            mtr_worktree = pool / "mtr" / "attempt-1"
            create_worktree(
                repository, pool, mtr_worktree, "mtr/router-auto-1", baseline
            )
            self.assertEqual(
                _pool_state(pool, [repository])["registered_worktree_count"], 1
            )
            (mtr_worktree / "docs.txt").write_text("validated\n", encoding="utf-8")
            mtr_commit = commit_exact_paths(
                mtr_worktree,
                ["docs.txt"],
                "validated MTR result",
                "Fixture",
                "fixture@example.invalid",
            )
            remove_worktree(repository, pool, mtr_worktree)
            merged = fast_forward(repository, baseline, mtr_commit)
            self.assertEqual(merged, mtr_commit)
            self.assertTrue(repository_state(repository)["clean"])
            self.assertEqual(list(pool.iterdir()), [])
            self.assertEqual(
                _pool_state(pool, [repository])["registered_worktree_count"], 0
            )

            qwen_baseline = merged
            qwen_worktree = pool / "qwen" / "attempt-1"
            create_worktree(
                repository,
                pool,
                qwen_worktree,
                "qwen/router-auto-1",
                qwen_baseline,
            )
            (qwen_worktree / "synthetic-test.txt").write_text(
                "synthetic only\n", encoding="utf-8"
            )
            qwen_commit = commit_exact_paths(
                qwen_worktree,
                ["synthetic-test.txt"],
                "validated qwen result",
                "Fixture",
                "fixture@example.invalid",
            )
            remove_worktree(repository, pool, qwen_worktree)
            self.assertEqual(run_git(repository, "rev-parse", "HEAD"), qwen_baseline)
            self.assertEqual(
                run_git(repository, "rev-parse", "qwen/router-auto-1"), qwen_commit
            )
            self.assertTrue(repository_state(repository)["clean"])
            self.assertEqual(list(pool.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
