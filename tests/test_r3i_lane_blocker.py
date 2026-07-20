from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from mtr_dogfood.config import load_json
from mtr_dogfood.external_runner import (
    _child_prompt,
    _scan_child_commands,
    classify_external_attempt,
    next_product_lane_allowed,
    product_tasks_allowed,
)
from mtr_dogfood.git_worktrees import (
    GitContractError,
    create_worktree,
    remove_worktree,
    repository_state,
)
from mtr_dogfood.r2_contract import classify_model_reported_blocker
from mtr_dogfood.runtime_contract import (
    TERMINALLY_INCOMPLETE_INSUFFICIENT_SEQUENCE_CAPACITY,
    classify_campaign_capacity,
    next_escalation_profile,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/r3h-lane-1-blocked-final-result.json"
CONTRACT = ROOT / "contracts/MODEL_TIER_ROUTER_DOGFOOD_R3_EXTERNAL_RUNTIME.json"


def run(*command: str, cwd: Path) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        check=True,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
    )
    return completed.stdout.strip()


def initialize_repository(path: Path) -> str:
    path.mkdir()
    run("git", "init", "-b", "main", cwd=path)
    (path / "docs").mkdir()
    (path / "docs/README.md").write_text("documentation\n", encoding="utf-8")
    (path / "tests/integrations").mkdir(parents=True)
    (path / "tests/integrations/.gitkeep").write_text("", encoding="utf-8")
    run("git", "add", "docs/README.md", "tests/integrations/.gitkeep", cwd=path)
    run(
        "git", "-c", "user.name=Fixture", "-c",
        "user.email=fixture@example.invalid", "commit", "-m", "baseline", cwd=path,
    )
    return run("git", "rev-parse", "HEAD", cwd=path)


def execution() -> dict[str, object]:
    return {
        "child_process_started": True,
        "model_execution_observed": True,
        "model_execution_completed": True,
        "host_policy_failure_count": 0,
        "infrastructure_failure_class": None,
    }


def classify(claim: dict[str, object], **overrides: object) -> str:
    arguments = {
        "output_valid": True,
        "schema_unchanged": True,
        "changed": [],
        "changed_paths_allowed": False,
        "automated_acceptance": False,
        "forbidden_action": False,
        "confidentiality_ok": True,
    }
    arguments.update(overrides)
    return classify_external_attempt(execution(), claim, **arguments)


def legacy_r3h_classification(claim: dict[str, object]) -> str:
    paths: list[str] = []
    claim_paths_match = sorted(claim["changed_paths"]) == paths
    path_scope_ok = bool(paths)
    forbidden = bool(claim["prohibited_action_attempted"])
    if forbidden or not claim_paths_match or not path_scope_ok:
        return "UNAUTHORIZED_ACTION"
    if not paths:
        return "IMPLEMENTATION_INCOMPLETE"
    return "ACCEPTED"


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def security_scan(command: str, worktree: Path, protected: list[Path]) -> dict[str, object]:
    events = worktree / "events.jsonl"
    events.write_text(
        json.dumps({
            "type": "item.completed",
            "item": {"type": "command_execution", "command": command},
        }) + "\n",
        encoding="utf-8",
    )
    return _scan_child_commands(events, protected, worktree)


class ExactR3HBlockerTests(unittest.TestCase):
    def setUp(self):
        self.claim = load_json(FIXTURE)

    def test_exact_fixture_preserves_result_notes_paths_and_tests(self):
        self.assertEqual(self.claim["status"], "blocked")
        self.assertEqual(
            self.claim["summary"],
            "Could not create the two allowed files: the required apply_patch "
            "editor failed with “Failed to write file” for "
            "docs/dogfood-automation.md despite the assigned worktree being "
            "present and writable by ACL.",
        )
        self.assertEqual(self.claim["changed_paths"], [])
        self.assertEqual(
            self.claim["notes"],
            [
                "No repository files were changed.",
                "No prohibited network, Git mutation, external-path, credential, "
                "plugin, browser, or subagent actions were used.",
            ],
        )
        self.assertEqual(
            [item["status"] for item in self.claim["tests_run"]],
            ["not_run", "not_run", "not_run"],
        )

    def test_exact_historical_classifier_bug_is_reproduced(self):
        self.assertEqual(legacy_r3h_classification(self.claim), "UNAUTHORIZED_ACTION")

    def test_future_classifier_reports_model_blocker_not_unauthorized(self):
        self.assertEqual(classify(self.claim), "MODEL_REPORTED_BLOCKED")
        self.assertIsNone(
            next_escalation_profile(
                load_json(CONTRACT), "balanced", "MODEL_REPORTED_BLOCKED", 0
            )
        )

    def test_valid_artifact_is_not_confused_with_execution_acceptance(self):
        self.assertEqual(self.claim["schema_version"], "1.0.0")
        self.assertNotEqual(classify(self.claim), "")


class ClassifierSafetyBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.claim = load_json(FIXTURE)

    def test_actual_out_of_scope_change_remains_unauthorized(self):
        self.assertEqual(
            classify(
                {**self.claim, "changed_paths": ["outside.txt"]},
                changed=["outside.txt"],
                changed_paths_allowed=False,
            ),
            "UNAUTHORIZED_ACTION",
        )

    def test_claimed_prohibited_action_remains_unauthorized(self):
        self.assertEqual(
            classify({**self.claim, "prohibited_action_attempted": True}, forbidden_action=True),
            "UNAUTHORIZED_ACTION",
        )

    def test_child_command_external_credential_remote_and_git_actions_remain_unauthorized(self):
        with tempfile.TemporaryDirectory() as directory:
            worktree = Path(directory)
            protected = [Path(r"C:\Users\sizhe\Documents\model-tier-router")]
            cases = [
                (
                    "Get-Content C:\\Users\\sizhe\\Documents\\model-tier-router\\README.md",
                    "external_path_access_detected",
                ),
                ("Get-Content C:\\Users\\sizhe\\.codex\\auth.json", "credential_access_detected"),
                ("git push origin main", "remote_operation_attempted"),
                ("git commit -m forbidden", "forbidden_action_detected"),
            ]
            for command, flag in cases:
                with self.subTest(flag=flag):
                    scan = security_scan(command, worktree, protected)
                    self.assertTrue(scan[flag])
                    self.assertEqual(classify(self.claim, forbidden_action=True), "UNAUTHORIZED_ACTION")

    def test_missing_input_and_contradictory_authority_have_narrow_categories(self):
        missing = {**self.claim, "summary": "The required input file is missing."}
        contradictory = {
            **self.claim,
            "summary": "The task authority is internally inconsistent and contradictory.",
        }
        self.assertEqual(classify_model_reported_blocker(missing), "REQUIRED_INPUT_MISSING")
        self.assertEqual(
            classify_model_reported_blocker(contradictory), "TASK_CONTRACT_AMBIGUOUS"
        )
        self.assertEqual(classify(missing), "REQUIRED_INPUT_MISSING")
        self.assertEqual(classify(contradictory), "TASK_CONTRACT_AMBIGUOUS")


class WorkspaceAndAuthorityTests(unittest.TestCase):
    def test_disposable_workspace_allows_exact_lane_files_without_source_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "source"
            pool = root / "pool"
            baseline = initialize_repository(repository)
            source_tree = run("git", "write-tree", cwd=repository)
            source_doc_hash = file_sha256(repository / "docs/README.md")
            source_stat = os.stat(repository / "docs")
            workspace = pool / "router_lane_1" / "attempt-1"
            create_worktree(repository, pool, workspace, "fixture/r3i", baseline)
            try:
                documentation = workspace / "docs/dogfood-automation.md"
                integration = workspace / "tests/integrations/test_dogfood_automation.py"
                documentation.write_text("bounded documentation\n", encoding="utf-8")
                integration.write_text("# bounded integration test\n", encoding="utf-8")
                self.assertEqual(documentation.read_text(encoding="utf-8"), "bounded documentation\n")
                self.assertTrue(integration.is_file())
                self.assertTrue(os.access(workspace, os.W_OK))
                self.assertTrue(os.access(workspace / "docs", os.W_OK))
                self.assertEqual(run("git", "write-tree", cwd=repository), source_tree)
                self.assertEqual(file_sha256(repository / "docs/README.md"), source_doc_hash)
                self.assertEqual(os.stat(repository / "docs").st_file_attributes, source_stat.st_file_attributes)
                self.assertTrue(repository_state(repository)["clean"])
            finally:
                remove_worktree(repository, pool, workspace)

    def test_workspace_boundary_rejects_acl_normalization_style_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "source"
            pool = root / "pool"
            baseline = initialize_repository(repository)
            with self.assertRaisesRegex(GitContractError, "escapes pool"):
                create_worktree(
                    repository, pool, root / "outside" / "attempt-1", "fixture/escape", baseline
                )

    def test_reparse_escape_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "source"
            pool = root / "pool"
            outside = root / "outside"
            baseline = initialize_repository(repository)
            pool.mkdir()
            outside.mkdir()
            link = pool / "reparse"
            try:
                os.symlink(outside, link, target_is_directory=True)
            except OSError:
                subprocess.run(
                    ["cmd", "/c", "mklink", "/J", str(link), str(outside)],
                    check=True,
                    capture_output=True,
                )
            with self.assertRaisesRegex(GitContractError, "escapes pool"):
                create_worktree(
                    repository, pool, link / "attempt-1", "fixture/reparse", baseline
                )

    def test_prompt_grants_only_bounded_disposable_authority(self):
        case = {
            "title": "Document advisory execution",
            "task_text": "Create the documentation and its integration test.",
            "changed_path_patterns": [
                "docs/dogfood-automation.md",
                "tests/integrations/test_dogfood_automation.py",
            ],
            "validator_plan": {"commands": []},
        }
        worktree = Path(r"C:\fixture\disposable")
        prompt = _child_prompt(case, worktree)
        self.assertIn("Implement one bounded task", prompt)
        self.assertIn("Read and write only inside the assigned worktree", prompt)
        self.assertIn("docs/dogfood-automation.md", prompt)
        self.assertIn("tests/integrations/test_dogfood_automation.py", prompt)
        self.assertIn("Do not access", prompt)
        for action in ("commit", "push", "tag", "remote"):
            self.assertIn(action, prompt)
        self.assertNotIn("model-tier-router\\", prompt)


class SequenceAndCampaignTests(unittest.TestCase):
    def test_r3h_smoke_acceptance_still_enables_first_product_lane(self):
        self.assertTrue(product_tasks_allowed({"accepted": True}))

    def test_failed_lane_one_prevents_lane_two(self):
        self.assertTrue(next_product_lane_allowed([]))
        self.assertTrue(next_product_lane_allowed([{"accepted": True}]))
        self.assertFalse(next_product_lane_allowed([{"accepted": False}]))

    def test_old_campaign_is_terminally_incomplete_without_consuming_ordinal_five(self):
        closeout = classify_campaign_capacity(5, 4, 2)
        self.assertEqual(closeout["unused_nominal_capacity"], 1)
        self.assertFalse(closeout["completion_possible_under_existing_ceiling"])
        self.assertEqual(
            closeout["terminal_classification"],
            TERMINALLY_INCOMPLETE_INSUFFICIENT_SEQUENCE_CAPACITY,
        )
        self.assertEqual(closeout["consumed_starts"], 4)


if __name__ == "__main__":
    unittest.main()
