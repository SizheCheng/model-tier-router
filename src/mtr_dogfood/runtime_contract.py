from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import ContractError, is_contained, load_json, same_path
from .r2_contract import PayloadValidationError, validate_instance


RUNTIME_ROUTE_ID = (
    "MODEL_TIER_ROUTER_DOGFOOD_R3_EXTERNAL_WRITABLE_SMOKE_AND_TWO_REAL_LANES"
)
PREPARATION_ROUTE_ID = "MODEL_TIER_ROUTER_DOGFOOD_R3_EXTERNAL_RUNNER_PREPARATION_R1"

ELIGIBLE_FAILURES = {
    "IMPLEMENTATION_INCOMPLETE",
    "VALIDATOR_FAILURE_AFTER_ALLOWED_CHANGE",
    "CONTEXT_OR_REASONING_INSUFFICIENT",
}
NEVER_ESCALATE_FAILURES = {
    "MODEL_REPORTED_BLOCKED",
    "REQUIRED_INPUT_MISSING",
    "TASK_CONTRACT_AMBIGUOUS",
    "HOST_POLICY_REJECTED_CHILD_FILESYSTEM_ACCESS",
    "HOST_POLICY_REJECTED_EXTERNAL_CODE_TRANSFER",
    "NESTED_CODEX_ANCESTOR_DETECTED",
    "SCHEMA_REJECTION",
    "AUTHENTICATION_FAILURE",
    "RATE_LIMIT",
    "MODEL_UNAVAILABLE",
    "MISSING_COMMAND",
    "ENVIRONMENT_FAILURE",
    "BASELINE_FAILURE",
    "CONCURRENT_TARGET_CHANGE",
    "CONFIDENTIALITY_BOUNDARY",
    "UNAUTHORIZED_ACTION",
}
PROFILE_SEQUENCE = ("economy", "balanced", "premium")
TERMINALLY_INCOMPLETE_INSUFFICIENT_SEQUENCE_CAPACITY = (
    "TERMINALLY_INCOMPLETE_INSUFFICIENT_SEQUENCE_CAPACITY"
)


@dataclass
class ProcessAccounting:
    maximum: int = 5
    prelaunch_validation_attempted: int = 0
    os_child_process_started: int = 0
    model_execution_observed: int = 0
    model_execution_completed: int = 0
    final_output_validated: int = 0
    filesystem_mutation_observed: int = 0
    validator_completed: int = 0

    @property
    def remaining(self) -> int:
        return self.maximum - self.os_child_process_started

    def record_prelaunch(self) -> None:
        self.prelaunch_validation_attempted += 1

    def require_start_available(self) -> None:
        if self.remaining <= 0:
            raise RuntimeError("CHILD_INVOCATION_LIMIT_REACHED")

    def record_process_start(self) -> None:
        self.require_start_available()
        self.os_child_process_started += 1

    def record_result(
        self,
        result: dict[str, Any],
        *,
        final_output_valid: bool,
        filesystem_mutation: bool,
        validator_completed: bool | int,
    ) -> None:
        validator_count = int(validator_completed)
        if validator_count < 0:
            raise ValueError("validator_completed must be non-negative")
        self.model_execution_observed += int(
            bool(result.get("model_execution_observed"))
        )
        self.model_execution_completed += int(
            bool(result.get("model_execution_completed"))
        )
        self.final_output_validated += int(final_output_valid)
        self.filesystem_mutation_observed += int(filesystem_mutation)
        self.validator_completed += validator_count

    def as_dict(self) -> dict[str, int]:
        return {
            "prelaunch_validation_attempted": self.prelaunch_validation_attempted,
            "os_child_process_started": self.os_child_process_started,
            "model_execution_observed": self.model_execution_observed,
            "model_execution_completed": self.model_execution_completed,
            "final_output_validated": self.final_output_validated,
            "filesystem_mutation_observed": self.filesystem_mutation_observed,
            "validator_completed": self.validator_completed,
        }


def _require_exact_keys(value: dict[str, Any], expected: set[str], location: str) -> None:
    actual = set(value)
    if actual != expected:
        raise ContractError(
            f"{location}: keys differ; missing={sorted(expected-actual)} "
            f"unknown={sorted(actual-expected)}"
        )


def _require_object(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{location}: expected object")
    return value


def _require_sha256(value: Any, location: str) -> None:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ContractError(f"{location}: expected lowercase SHA-256")


def _require_git_oid(value: Any, location: str) -> None:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{40}", value) is None:
        raise ContractError(f"{location}: expected lowercase Git object id")


def validate_runtime_contract(value: Any) -> dict[str, Any]:
    contract = _require_object(value, "$")
    _require_exact_keys(
        contract,
        {
            "schema_version",
            "preparation_route_id",
            "route_id",
            "prepared_from_harness_head",
            "preparation_commit_subject",
            "execution_topology",
            "maximum_new_codex_exec_process_starts",
            "additional_retry_budget",
            "silent_model_substitution",
            "allocation",
            "paths",
            "repositories",
            "denylist",
            "model_mapping",
            "fixture_smoke",
            "cases",
            "existing_fixed_premium_control",
            "child",
            "failure_policy",
            "worktree_policy",
            "reporting",
            "commit_identity",
        },
        "$",
    )
    if contract["schema_version"] != "1.0.0":
        raise ContractError("runtime contract schema version mismatch")
    if contract["preparation_route_id"] != PREPARATION_ROUTE_ID:
        raise ContractError("preparation route id mismatch")
    if contract["route_id"] != RUNTIME_ROUTE_ID:
        raise ContractError("runtime route id mismatch")
    _require_git_oid(
        contract["prepared_from_harness_head"], "$.prepared_from_harness_head"
    )
    if contract["preparation_commit_subject"] != "Add external PowerShell dogfood runner":
        raise ContractError("preparation commit subject mismatch")
    if contract["execution_topology"] != (
        "ordinary PowerShell -> standalone harness runner -> Router -> "
        "top-level child codex exec"
    ):
        raise ContractError("execution topology mismatch")
    if contract["maximum_new_codex_exec_process_starts"] != 5:
        raise ContractError("process-start budget mismatch")
    if contract["additional_retry_budget"] != 0:
        raise ContractError("additional retry budget must be zero")
    if contract["silent_model_substitution"] is not False:
        raise ContractError("silent model substitution is forbidden")

    allocation = _require_object(contract["allocation"], "$.allocation")
    expected_allocation = {
        "fixture_writable_smoke": 1,
        "model_tier_router_initial": 1,
        "model_tier_router_escalation_if_eligible": 1,
        "qwen_redaction_initial": 1,
        "qwen_redaction_escalation_if_eligible": 1,
    }
    if allocation != expected_allocation:
        raise ContractError("process-start allocation mismatch")

    paths = _require_object(contract["paths"], "$.paths")
    _require_exact_keys(
        paths,
        {
            "harness", "worktree_pool", "source_router_request_config",
            "source_router_request_config_sha256", "closeout_schema",
            "writable_smoke_schema",
        },
        "$.paths",
    )
    expected_paths = {
        "harness": "C:/Users/sizhe/Documents/model-tier-router-dogfood",
        "worktree_pool": (
            "C:/Users/sizhe/Documents/model-tier-router-dogfood-worktrees"
        ),
        "source_router_request_config": "config/pilot-r1.json",
        "closeout_schema": "schemas/external-run-closeout.schema.json",
        "writable_smoke_schema": "schemas/writable-smoke-result.schema.json",
    }
    for key, expected in expected_paths.items():
        if paths[key] != expected:
            raise ContractError(f"runtime path mismatch: {key}")
    _require_sha256(
        paths["source_router_request_config_sha256"],
        "$.paths.source_router_request_config_sha256",
    )

    repositories = _require_object(contract["repositories"], "$.repositories")
    if set(repositories) != {"model-tier-router", "qwen-redaction-standalone"}:
        raise ContractError("runtime repository allowlist mismatch")
    expected_repositories = {
        "model-tier-router": (
            "C:/Users/sizhe/Documents/model-tier-router",
            "main",
            "a455debff9a01faa5481cb8a6ca98e31e29ec52a",
        ),
        "qwen-redaction-standalone": (
            "C:/Users/sizhe/Documents/qwen-redaction-standalone",
            "qwen-redaction-r1",
            "bbb1bd68882aeb735f29c448b00a5c21783b355f",
        ),
    }
    for repository_id, entry_value in repositories.items():
        entry = _require_object(entry_value, f"$.repositories.{repository_id}")
        _require_exact_keys(entry, {"path", "branch", "baseline_head"}, repository_id)
        _require_git_oid(entry["baseline_head"], f"{repository_id}.baseline_head")
        if (
            entry["path"], entry["branch"], entry["baseline_head"]
        ) != expected_repositories[repository_id]:
            raise ContractError(f"runtime repository mismatch: {repository_id}")

    expected_denylist = [
        "C:/Users/sizhe/Documents/model-tier-router-public",
        "C:/Users/sizhe/Documents/canonical-memories",
        "C:/Users/sizhe/Documents/shortage-B",
        "C:/Users/sizhe/Documents/qwen",
        "C:/Users/sizhe/Documents/trading-authority-OS",
    ]
    if contract["denylist"] != expected_denylist:
        raise ContractError("runtime repository denylist mismatch")

    profiles = _require_object(contract["model_mapping"], "$.model_mapping")
    expected_profiles = {
        "economy": ("gpt-5.6-luna", "low", "balanced"),
        "balanced": ("gpt-5.6-terra", "medium", "premium"),
        "premium": ("gpt-5.6-sol", "high", None),
    }
    if set(profiles) != set(expected_profiles):
        raise ContractError("model profile set mismatch")
    for profile, expected in expected_profiles.items():
        entry = _require_object(profiles[profile], f"$.model_mapping.{profile}")
        actual = (entry.get("model"), entry.get("reasoning_effort"), entry.get("next"))
        if actual != expected or set(entry) != {"model", "reasoning_effort", "next"}:
            raise ContractError(f"model profile mismatch: {profile}")

    expected_fixture = {
        "model_profile": "economy",
        "readme_text": (
            "Synthetic writable-workspace smoke repository for "
            "model-tier-router dogfood R3.\n"
        ),
        "result_path": "smoke/result.txt",
        "result_text": "WORKSPACE_WRITE_OK\n",
        "timeout_seconds": 300,
    }
    if contract["fixture_smoke"] != expected_fixture:
        raise ContractError("writable fixture smoke contract mismatch")

    cases = contract["cases"]
    if not isinstance(cases, list) or len(cases) != 2:
        raise ContractError("runtime contract requires exactly two cases")
    expected_cases = {
        "mtr-docs-private-executor-r1": "model-tier-router",
        "qwen-docx-hidden-elements-r1": "qwen-redaction-standalone",
    }
    expected_case_values = {
        "mtr-docs-private-executor-r1": {
            "source_task_receipt": (
                "runs/receipts/mtr-docs-private-executor-r1--router_auto/task.json"
            ),
            "source_task_sha256": (
                "ab0446be54ba29b4151c53c8f8cd8c156b021b0b9cd1189cde0206c6a1c55e7e"
            ),
            "branch_prefix": (
                "mtr-dogfood/mtr-docs-private-executor-r3/router_auto"
            ),
            "automatic_fast_forward_merge": True,
            "retain_for_human_review": False,
        },
        "qwen-docx-hidden-elements-r1": {
            "source_task_receipt": (
                "runs/receipts/qwen-docx-hidden-elements-r1--router_auto/task.json"
            ),
            "source_task_sha256": (
                "d4f289857977eeccd8b9327ae3565e83f9939a71510be08a71f56f98ca821b31"
            ),
            "branch_prefix": (
                "mtr-dogfood/qwen-docx-hidden-elements-r3/router_auto"
            ),
            "automatic_fast_forward_merge": False,
            "retain_for_human_review": True,
        },
    }
    for case_value in cases:
        case = _require_object(case_value, "$.cases[]")
        _require_exact_keys(
            case,
            {
                "case_id",
                "repository",
                "source_task_receipt",
                "source_task_sha256",
                "branch_prefix",
                "automatic_fast_forward_merge",
                "retain_for_human_review",
            },
            "$.cases[]",
        )
        if expected_cases.get(case["case_id"]) != case["repository"]:
            raise ContractError("case repository binding mismatch")
        _require_sha256(case["source_task_sha256"], "$.cases[].source_task_sha256")
        expected = expected_case_values[case["case_id"]]
        if any(case[key] != value for key, value in expected.items()):
            raise ContractError(f"case contract mismatch: {case['case_id']}")

    failure_policy = _require_object(contract["failure_policy"], "$.failure_policy")
    _require_exact_keys(
        failure_policy,
        {"eligible_for_one_escalation", "never_escalate", "classification_order"},
        "$.failure_policy",
    )
    if set(failure_policy.get("eligible_for_one_escalation", [])) != ELIGIBLE_FAILURES:
        raise ContractError("eligible escalation set mismatch")
    if set(failure_policy.get("never_escalate", [])) != NEVER_ESCALATE_FAILURES:
        raise ContractError("infrastructure non-escalation set mismatch")
    if failure_policy["classification_order"] != [
        "host-policy and infrastructure signals",
        "schema and transport signals",
        "authentication, rate-limit and model-availability signals",
        "filesystem changes",
        "validator results",
        "model final claim",
    ]:
        raise ContractError("failure classification order mismatch")

    expected_control = {
        "repository": "model-tier-router",
        "branch": (
            "mtr-dogfood/mtr-docs-private-executor-r1/fixed_premium_control-1"
        ),
        "commit": "e544cb7ee7497aa7706a06ef4aa55bfcf18bcca1",
        "baseline": "a455debff9a01faa5481cb8a6ca98e31e29ec52a",
        "read_only": True,
        "rerun": False,
        "merge": False,
    }
    if contract["existing_fixed_premium_control"] != expected_control:
        raise ContractError("fixed premium control contract mismatch")

    expected_worktree_policy = {
        "one_fresh_worktree_per_attempt": True,
        "every_attempt_starts_from_original_baseline": True,
        "failed_attempt_commit": False,
        "failed_attempt_cleanup": True,
        "validated_branch_preservation": True,
        "primary_repository_reset_clean_restore_or_stash": False,
        "final_pool_registered_worktree_count": 0,
    }
    if contract["worktree_policy"] != expected_worktree_policy:
        raise ContractError("worktree policy mismatch")

    child = _require_object(contract["child"], "$.child")
    expected_child = {
        "sandbox": "workspace-write",
        "approval_policy": "never",
        "prompt_transport": "stdin",
        "jsonl_output": True,
        "network_tools": False,
        "web_search": False,
        "additional_writable_directories": [],
        "command_shape": [
            "codex", "--ask-for-approval", "never", "exec", "-C",
            "<EXACT_WORKTREE_OR_FIXTURE>",
            "--ephemeral", "--model", "<MAPPED_MODEL>", "-c",
            'model_reasoning_effort="<MAPPED_REASONING_EFFORT>"',
            "-c", "memories.generate_memories=false", "--sandbox",
            "workspace-write", "--json", "--output-schema",
            "<WORKTREE_LOCAL_SCHEMA>",
            "--output-last-message", "<WORKTREE_LOCAL_FINAL_RESULT>", "-",
        ],
    }
    if child != expected_child:
        raise ContractError("child execution contract mismatch")

    expected_reporting = {
        "reports": [
            "reports/pilot-r3.json",
            "reports/pilot-r3.md",
            "reports/pilot-r3.csv",
        ],
        "closeout": "reports/pilot-r3-closeout.json",
        "receipt_root": "runs/receipts/r3",
        "raw_root": "runs/raw/r3",
        "report_commit_subject": "Record external automated dogfood pilot R3",
        "maximum_report_commits": 1,
    }
    if contract["reporting"] != expected_reporting:
        raise ContractError("reporting contract mismatch")
    if contract["commit_identity"] != {
        "name": "SizheCheng",
        "email": "286442303+SizheCheng@users.noreply.github.com",
        "persistent_configuration": False,
    }:
        raise ContractError("commit identity contract mismatch")
    return contract


def load_runtime_contract(path: str | Path, harness_root: str | Path) -> dict[str, Any]:
    resolved = Path(path).resolve()
    if not is_contained(harness_root, resolved):
        raise ContractError("runtime contract path escapes harness")
    return validate_runtime_contract(load_json(resolved))


def validate_contract_paths(contract: dict[str, Any], harness_root: str | Path) -> None:
    paths = _require_object(contract["paths"], "$.paths")
    if not same_path(paths.get("harness"), harness_root):
        raise ContractError("runtime harness path mismatch")
    repository_paths = {entry["path"] for entry in contract["repositories"].values()}
    denied = {str(Path(path).resolve()).casefold() for path in contract["denylist"]}
    if any(str(Path(path).resolve()).casefold() in denied for path in repository_paths):
        raise ContractError("denied repository entered runtime allowlist")


def next_escalation_profile(
    contract: dict[str, Any],
    profile: str,
    failure_class: str,
    escalation_count: int,
) -> str | None:
    if failure_class not in ELIGIBLE_FAILURES or escalation_count >= 1:
        return None
    if failure_class in NEVER_ESCALATE_FAILURES:
        return None
    entry = contract["model_mapping"].get(profile)
    return entry.get("next") if isinstance(entry, dict) else None


def classify_campaign_capacity(
    ceiling: int, consumed_starts: int, starts_required: int
) -> dict[str, Any]:
    if min(ceiling, consumed_starts, starts_required) < 0:
        raise ContractError("campaign capacity values must be non-negative")
    if consumed_starts > ceiling:
        raise ContractError("campaign consumed starts exceed ceiling")
    remaining = ceiling - consumed_starts
    possible = starts_required <= remaining
    return {
        "ceiling": ceiling,
        "consumed_starts": consumed_starts,
        "unused_nominal_capacity": remaining,
        "starts_required_to_complete_remaining_sequence": starts_required,
        "completion_possible_under_existing_ceiling": possible,
        "terminal_classification": (
            None
            if possible
            else TERMINALLY_INCOMPLETE_INSUFFICIENT_SEQUENCE_CAPACITY
        ),
    }


def assert_control_action_allowed(action: str) -> None:
    if action in {"rerun", "merge", "modify"}:
        raise RuntimeError("UNAUTHORIZED_CONTROL_RERUN_OR_MERGE")


def validate_closeout(value: dict[str, Any], schema: dict[str, Any]) -> None:
    try:
        validate_instance(value, schema)
    except PayloadValidationError as exc:
        raise ContractError(f"invalid external closeout: {exc}") from exc


__all__ = [
    "ELIGIBLE_FAILURES",
    "NEVER_ESCALATE_FAILURES",
    "PREPARATION_ROUTE_ID",
    "ProcessAccounting",
    "RUNTIME_ROUTE_ID",
    "assert_control_action_allowed",
    "classify_campaign_capacity",
    "load_runtime_contract",
    "next_escalation_profile",
    "validate_closeout",
    "validate_contract_paths",
    "validate_runtime_contract",
]
