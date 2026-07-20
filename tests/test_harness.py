from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from mtr_dogfood.codex_runner import (
    build_command,
    classify_infrastructure,
    extract_usage,
    observe_model_execution,
    resolve_codex_executable,
)
from mtr_dogfood.cli import _forbidden_action_detected
from mtr_dogfood.concurrency import measurement_quality, sanitize_process_rows
from mtr_dogfood.config import (
    ContractError,
    ensure_repository_allowed,
    is_contained,
    load_json,
    strict_json_loads,
)
from mtr_dogfood.escalation import next_profile
from mtr_dogfood.git_worktrees import (
    can_fast_forward,
    commit_exact_paths,
    create_worktree,
    fast_forward,
    remove_worktree,
    repository_state,
)
from mtr_dogfood.receipts import sanitize, validate_required_fields, write_json
from mtr_dogfood.r2_contract import (
    InvocationBudget,
    PayloadValidationError,
    assert_control_action_allowed,
    classify_attempt,
    classify_child_claim,
    validate_child_transport,
    validate_codex_output_schema,
    validate_r2_repository_scope,
)
from mtr_dogfood.r2_execution import _load_case
from mtr_dogfood.router_adapter import (
    RouterDecisionError,
    map_profile,
    validate_decision,
)
from mtr_dogfood.task_selection import arm_order
from mtr_dogfood.validation import (
    freeze_validator_plan,
    paths_allowed,
    risk_allows_auto_merge,
    validate_command,
)


ROOT = Path(__file__).resolve().parents[1]


class JsonContractTests(unittest.TestCase):
    def test_strict_json_rejects_duplicate_keys(self):
        with self.assertRaises(ContractError):
            strict_json_loads('{"a":1,"a":2}')

    def test_strict_json_rejects_non_finite(self):
        with self.assertRaises(ContractError):
            strict_json_loads('{"a":NaN}')

    def test_all_committed_json_is_strict(self):
        for path in sorted((ROOT / "config").glob("*.json")) + sorted(
            (ROOT / "schemas").glob("*.json")
        ):
            self.assertIsNotNone(load_json(path), path)

    def test_codex_output_schema_types_all_const_and_enum_fields(self):
        schema = load_json(ROOT / "schemas" / "execution-result.schema.json")
        def walk(value):
            if isinstance(value, dict):
                if "const" in value or "enum" in value:
                    self.assertIn("type", value)
                for child in value.values():
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)
        walk(schema)

    def test_codex_output_schema_uses_supported_strict_subset(self):
        schema = load_json(ROOT / "schemas" / "execution-result.schema.json")
        encoded = json.dumps(schema, sort_keys=True)
        for forbidden in ('"$schema"', '"const"', '"minLength"', '"uniqueItems"'):
            self.assertNotIn(forbidden, encoded)

    def test_invalid_internal_schema_is_rejected_before_process_start(self):
        schema = load_json(ROOT / "schemas" / "execution-result.schema.json")
        del schema["properties"]["status"]["type"]
        budget = InvocationBudget()
        with self.assertRaises(PayloadValidationError):
            try:
                validate_codex_output_schema(schema)
            except PayloadValidationError:
                budget.record_payload_rejection()
                raise
        self.assertEqual(budget.process_starts, 0)
        self.assertEqual(budget.pre_model_payload_rejections, 1)


class EvidenceClassificationTests(unittest.TestCase):
    def test_non_error_event_does_not_trigger_infrastructure_pattern(self):
        events = json.dumps(
            {"type": "turn.completed", "message": "model unavailable in task text"}
        )
        self.assertIsNone(classify_infrastructure(events, "")["infrastructure_failure_class"])

    def test_structured_error_event_is_classified(self):
        events = json.dumps({"type": "error", "message": "model not found"})
        result = classify_infrastructure(events, "")
        self.assertEqual(result["infrastructure_failure_class"], "MODEL_UNAVAILABLE")

    def test_forbidden_scan_reads_command_field_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text(
                json.dumps(
                    {
                        "type": "item.completed",
                        "message": "do not run git commit",
                        "item": {"type": "command_execution", "command": "python -m pytest"},
                    }
                ),
                encoding="utf-8",
            )
            self.assertFalse(_forbidden_action_detected(path))
            path.write_text(
                json.dumps(
                    {
                        "type": "item.completed",
                        "item": {"type": "command_execution", "command": "git commit -m bad"},
                    }
                ),
                encoding="utf-8",
            )
            self.assertTrue(_forbidden_action_detected(path))


class PathPolicyTests(unittest.TestCase):
    def test_path_containment(self):
        root = ROOT / "worktrees"
        self.assertTrue(is_contained(root, root / "repo" / "case"))
        self.assertFalse(is_contained(root, root.parent / "escape"))

    def test_repository_allowlist(self):
        repositories = {"one": str(ROOT / "one")}
        self.assertEqual(
            ensure_repository_allowed(ROOT / "one", repositories, []), "one"
        )
        with self.assertRaises(ContractError):
            ensure_repository_allowed(ROOT / "two", repositories, [])

    def test_known_external_repository_denylist(self):
        denied = str(ROOT / "external")
        with self.assertRaises(ContractError):
            ensure_repository_allowed(denied, {"bad": denied}, [denied])


class ConcurrencyTests(unittest.TestCase):
    def test_process_metadata_sanitization(self):
        rows = sanitize_process_rows(
            [
                {
                    "name": "codex.exe",
                    "pid": "42",
                    "start_time": "now",
                    "command_line": "secret prompt",
                    "repository_paths_exposed": ["qwen"],
                }
            ]
        )
        self.assertNotIn("command_line", rows[0])
        self.assertEqual(rows[0]["repository_paths_exposed"], ["qwen"])

    def test_wall_time_contamination_label(self):
        self.assertEqual(
            measurement_quality(True),
            "CONTAMINATED_BY_CONCURRENT_CODEX_SESSIONS",
        )


class RouterTests(unittest.TestCase):
    def test_router_decision_validation(self):
        value = validate_decision(
            {
                "status": "recommended",
                "selected_profile": "balanced",
                "execution_authorized": False,
                "authorized_write_scope": [],
            },
            {"balanced"},
        )
        self.assertIn("dogfood_decision_digest", value)

    def test_router_attempted_authority_rejected(self):
        with self.assertRaises(RouterDecisionError):
            validate_decision(
                {
                    "status": "recommended",
                    "selected_profile": "balanced",
                    "execution_authorized": True,
                },
                {"balanced"},
            )

    def test_unknown_profile_rejected(self):
        with self.assertRaises(RouterDecisionError):
            validate_decision(
                {
                    "status": "recommended",
                    "selected_profile": "mystery",
                    "execution_authorized": False,
                },
                {"balanced"},
            )

    def test_profile_mapping(self):
        model_map = load_json(ROOT / "config" / "model-map.json")
        self.assertEqual(map_profile(model_map, "economy"), ("gpt-5.6-luna", "low"))


class CodexRunnerTests(unittest.TestCase):
    def test_jsonl_usage_extraction_sums_turns(self):
        lines = [
            json.dumps(
                {
                    "type": "turn.completed",
                    "usage": {
                        "input_tokens": 10,
                        "cached_input_tokens": 2,
                        "output_tokens": 3,
                        "reasoning_output_tokens": 1,
                    },
                }
            ),
            json.dumps(
                {
                    "type": "turn.completed",
                    "usage": {
                        "input_tokens": 20,
                        "cached_input_tokens": 4,
                        "output_tokens": 6,
                        "reasoning_output_tokens": 2,
                    },
                }
            ),
        ]
        self.assertEqual(extract_usage(lines)["input_tokens"], 30)
        self.assertEqual(extract_usage(lines)["reasoning_output_tokens"], 3)

    def test_missing_usage_is_unavailable(self):
        self.assertIsNone(extract_usage([json.dumps({"type": "turn.completed"})])["input_tokens"])

    def test_rate_limit_classification(self):
        self.assertEqual(
            classify_infrastructure("rate limit exceeded", "")["infrastructure_failure_class"],
            "RATE_LIMIT",
        )

    def test_model_unavailable_classification(self):
        self.assertEqual(
            classify_infrastructure("model not found", "")["infrastructure_failure_class"],
            "MODEL_UNAVAILABLE",
        )

    def test_invalid_output_schema_is_validator_defect(self):
        self.assertEqual(
            classify_infrastructure("invalid_json_schema", "")["infrastructure_failure_class"],
            "VALIDATOR_DEFECT",
        )

    def test_read_only_sandbox_is_host_policy_failure(self):
        result = classify_infrastructure(
            "",
            "patch rejected: writing is blocked by read-only sandbox; rejected by user approval settings",
        )
        self.assertEqual(
            result["infrastructure_failure_class"],
            "HOST_POLICY_REJECTED_CHILD_FILESYSTEM_ACCESS",
        )

    def test_command_enforces_no_approval_and_workspace_sandbox(self):
        command = build_command(
            ROOT,
            "model",
            "low",
            ROOT / "schema",
            ROOT / "out",
        )
        self.assertEqual(Path(command[0]).suffix.lower(), ".exe")
        self.assertTrue(Path(resolve_codex_executable()).is_file())
        self.assertIn('approval_policy="never"', command)
        self.assertIn("workspace-write", command)
        self.assertIn("--strict-config", command)
        self.assertIn("--ignore-user-config", command)
        self.assertIn('web_search="disabled"', command)
        self.assertIn("sandbox_workspace_write.network_access=false", command)
        self.assertNotIn("--add-dir", command)

    def test_model_observation_excludes_schema_rejection(self):
        rejected = [
            json.dumps({"type": "thread.started"}),
            json.dumps({"type": "turn.started"}),
            json.dumps({"type": "error", "message": "invalid_json_schema"}),
        ]
        self.assertEqual(observe_model_execution(rejected), (False, False))
        completed = [
            json.dumps(
                {
                    "type": "item.completed",
                    "item": {"type": "agent_message", "text": "done"},
                }
            ),
            json.dumps({"type": "turn.completed", "usage": {"input_tokens": 1}}),
        ]
        self.assertEqual(observe_model_execution(completed), (True, True))

    def test_worktree_local_schema_and_host_policy_transport(self):
        with tempfile.TemporaryDirectory() as directory:
            worktree = Path(directory) / "worktree"
            metadata = worktree / ".mtr-dogfood-r2"
            metadata.mkdir(parents=True)
            schema = metadata / "schema.json"
            output = metadata / "result.json"
            schema.write_text("{}", encoding="utf-8")
            command = build_command(worktree, "model", "low", schema, output)
            prompt = f"Work only in {worktree}"
            validate_child_transport(
                worktree,
                command,
                prompt,
                [Path(directory) / "harness", Path(directory) / "other-repository"],
            )
            self.assertTrue(
                Path(command[command.index("--output-schema") + 1]).is_relative_to(
                    worktree
                )
            )

    def test_external_repository_path_is_rejected_before_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            worktree = Path(directory) / "worktree"
            metadata = worktree / ".mtr-dogfood-r2"
            metadata.mkdir(parents=True)
            schema = metadata / "schema.json"
            output = metadata / "result.json"
            other = Path(directory) / "other"
            command = build_command(worktree, "model", "low", schema, output)
            with self.assertRaises(PayloadValidationError):
                validate_child_transport(
                    worktree,
                    command,
                    f"Read {other / 'source.py'}",
                    [other],
                )


class EscalationTests(unittest.TestCase):
    def test_one_step_escalation(self):
        self.assertEqual(next_profile("economy", "IMPLEMENTATION_INCOMPLETE", 0), "balanced")
        self.assertIsNone(next_profile("economy", "IMPLEMENTATION_INCOMPLETE", 1))

    def test_no_escalation_for_infrastructure_failure(self):
        self.assertIsNone(next_profile("balanced", "RATE_LIMIT", 0))
        self.assertIsNone(next_profile("balanced", "MODEL_UNAVAILABLE", 0))
        self.assertIsNone(next_profile("balanced", "VALIDATOR_DEFECT", 0))
        self.assertIsNone(
            next_profile(
                "balanced", "HOST_POLICY_REJECTED_EXTERNAL_CODE_TRANSFER", 0
            )
        )

    def test_no_change_result_triggers_one_escalation(self):
        failure = classify_attempt(
            {
                "model_execution_observed": True,
                "infrastructure_failure_class": None,
            },
            [],
        )
        self.assertEqual(failure, "IMPLEMENTATION_INCOMPLETE")
        self.assertEqual(next_profile("balanced", failure, 0), "premium")
        self.assertIsNone(next_profile("balanced", failure, 1))

    def test_read_only_child_claim_is_not_capability_failure(self):
        failure = classify_child_claim(
            {
                "status": "blocked",
                "summary": "The workspace filesystem is read-only.",
                "notes": ["Write access is required."],
            }
        )
        self.assertEqual(
            failure, "HOST_POLICY_REJECTED_CHILD_FILESYSTEM_ACCESS"
        )
        self.assertIsNone(next_profile("balanced", failure, 0))

    def test_process_start_budget_accounting(self):
        budget = InvocationBudget(maximum=2)
        budget.record_payload_rejection()
        self.assertEqual(budget.remaining, 2)
        budget.record_process_start()
        self.assertEqual(budget.remaining, 1)
        budget.record_process_start()
        with self.assertRaises(RuntimeError):
            budget.record_process_start()


class R2ScopeTests(unittest.TestCase):
    def test_frozen_router_request_is_hash_bound_to_r1_config(self):
        case, _, source_bytes = _load_case("mtr-docs-private-executor-r1")
        self.assertIn("router_request", case)
        self.assertTrue(source_bytes)
        self.assertEqual(
            case["router_request"]["request_id"],
            "mtr-docs-private-executor-r1",
        )

    def test_canonical_memories_is_absent_from_r2_final_gates(self):
        settings = load_json(ROOT / "config" / "repositories.json")
        validate_r2_repository_scope(settings)
        self.assertNotIn("canonical-memories", settings["repositories"])
        pilot = load_json(ROOT / "config" / "pilot-r2.json")
        self.assertTrue(
            all(
                case.get("repository") is None
                or case.get("repository") != "canonical-memories"
                for case in pilot["cases"]
            )
        )

    def test_existing_fixed_premium_control_cannot_be_mutated(self):
        for action in ("rerun", "merge", "modify"):
            with self.assertRaises(RuntimeError):
                assert_control_action_allowed(action)


class ValidationTests(unittest.TestCase):
    def test_validator_freeze_is_order_stable(self):
        self.assertEqual(
            freeze_validator_plan({"a": 1, "b": 2}),
            freeze_validator_plan({"b": 2, "a": 1}),
        )

    def test_changed_path_boundary(self):
        self.assertTrue(paths_allowed(["docs/guide.md"], ["docs/*.md"]))
        self.assertFalse(paths_allowed(["src/prod.py"], ["docs/*.md"]))

    def test_risk_classification(self):
        self.assertTrue(risk_allows_auto_merge("LOW_RISK", "documentation", "ROUTER_AUTO"))
        self.assertFalse(
            risk_allows_auto_merge("LOW_RISK", "documentation", "FIXED_PREMIUM_CONTROL")
        )
        self.assertFalse(risk_allows_auto_merge("MEDIUM_RISK", "tests", "ROUTER_AUTO"))

    def test_remote_and_push_prohibition(self):
        with self.assertRaises(ValueError):
            validate_command(["git", "push"])
        with self.assertRaises(ValueError):
            validate_command(["git", "remote", "add", "x", "url"])


class ReceiptTests(unittest.TestCase):
    def test_sanitized_receipt_generation(self):
        value = sanitize({"case_id": "c", "stdout": "secret", "nested": {"prompt": "x"}})
        self.assertEqual(value, {"case_id": "c", "nested": {}})

    def test_required_receipt_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            write_json(path, {"case_id": "c"})
            self.assertEqual(validate_required_fields(path, ["case_id"])["case_id"], "c")

    def test_raw_data_gitignore_enforcement(self):
        ignore = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        for required in ("runs/raw/", "worktrees/", "*.token", "*.secret"):
            self.assertIn(required, ignore)


class WorktreeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.repo = self.base / "repo"
        self.pool = self.base / "pool"
        self.repo.mkdir()
        self.pool.mkdir()
        self._run("init", "-b", "main")
        (self.repo / "README.md").write_text("baseline\n", encoding="utf-8")
        self._run("add", "--", "README.md")
        self._run(
            "-c",
            "user.name=Tester",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-m",
            "baseline",
        )
        self.head = repository_state(self.repo)["head"]

    def tearDown(self):
        self.temp.cleanup()

    def _run(self, *args: str):
        subprocess.run(["git", "-C", str(self.repo), *args], check=True, capture_output=True)

    def test_worktree_creation_and_cleanup(self):
        worktree = self.pool / "repo" / "case" / "router_auto-1"
        create_worktree(self.repo, self.pool, worktree, "mtr-dogfood/test", self.head)
        self.assertTrue(worktree.exists())
        remove_worktree(self.repo, self.pool, worktree)
        self.assertFalse(worktree.exists())
        create_worktree(self.repo, self.pool, worktree, "mtr-dogfood/test", self.head)
        self.assertTrue(worktree.exists())
        remove_worktree(self.repo, self.pool, worktree)

    def test_commit_and_fast_forward_conditions(self):
        worktree = self.pool / "repo" / "case" / "router_auto-1"
        create_worktree(self.repo, self.pool, worktree, "mtr-dogfood/test", self.head)
        (worktree / "README.md").write_text("changed\n", encoding="utf-8")
        commit = commit_exact_paths(
            worktree,
            ["README.md"],
            "Dogfood test: change",
            "Tester",
            "test@example.invalid",
        )
        self.assertTrue(can_fast_forward(self.repo, self.head, commit))
        self.assertEqual(fast_forward(self.repo, self.head, commit), commit)
        remove_worktree(self.repo, self.pool, worktree)

    def test_concurrent_target_head_change_prevents_merge(self):
        self.assertFalse(can_fast_forward(self.repo, "0" * 40, self.head))

    def test_repository_state_supports_unborn_head(self):
        unborn = self.base / "unborn"
        unborn.mkdir()
        subprocess.run(
            ["git", "-C", str(unborn), "init", "-b", "main"],
            check=True,
            capture_output=True,
        )
        state = repository_state(unborn)
        self.assertIsNone(state["head"])
        self.assertEqual(state["branch"], "main")


class ExperimentTests(unittest.TestCase):
    def test_control_arm_order_is_hash_determined(self):
        first = arm_order("case-one")
        self.assertEqual(first, arm_order("case-one"))
        self.assertEqual(set(first), {"ROUTER_AUTO", "FIXED_PREMIUM_CONTROL"})


if __name__ == "__main__":
    unittest.main()
