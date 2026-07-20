from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .codex_runner import build_command, classify_infrastructure, run_codex
from .concurrency import capture_process_metadata, measurement_quality
from .config import harness_root, is_contained, load_json
from .escalation import next_profile
from .git_worktrees import (
    GitContractError,
    changed_paths,
    commit_exact_paths,
    create_worktree,
    delete_unadvanced_branch,
    diff_bytes,
    fast_forward,
    remove_worktree,
    repository_state,
    require_clean_baseline,
)
from .r2_contract import (
    CONTROL_BRANCH,
    CONTROL_COMMIT,
    ROUTE_ID,
    InvocationBudget,
    PayloadValidationError,
    classify_child_claim,
    classify_attempt,
    final_output_valid,
    validate_child_transport,
    validate_launch_payloads,
    validate_r2_repository_scope,
)
from .receipts import write_json
from .reporting import build_r2_report, write_r2_reports
from .router_adapter import assess_live, load_model_map, map_profile
from .validation import (
    freeze_validator_plan,
    paths_allowed,
    risk_allows_auto_merge,
    run_plan,
    summarize_validation,
)


FORBIDDEN_ACTION_RE = re.compile(
    r"\bgit\s+(commit|merge|rebase|reset|clean|push|remote|tag|stash)\b"
    r"|\b(publish|deploy|release|customer\s+delivery)\b",
    re.I,
)
CREDENTIAL_ACCESS_RE = re.compile(
    r"auth\.json|\.ssh|credential|cookie|token|secret|Get-ChildItem\s+Env:|"
    r"\$env:(?:CODEX|OPENAI|GITHUB|GH)_",
    re.I,
)


def _root() -> Path:
    return harness_root()


def _settings() -> dict[str, Any]:
    value = load_json(_root() / "config" / "repositories.json")
    validate_r2_repository_scope(value)
    return value


def _pilot() -> dict[str, Any]:
    value = load_json(_root() / "config" / "pilot-r2.json")
    if value.get("route_id") != ROUTE_ID:
        raise PayloadValidationError("R2 route id mismatch")
    return value


def _load_case(case_id: str) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    pilot = _pilot()
    request_source = (_root() / pilot["source_router_request_config"]).resolve()
    request_bytes = request_source.read_bytes()
    if (
        hashlib.sha256(request_bytes).hexdigest()
        != pilot["source_router_request_config_sha256"]
    ):
        raise PayloadValidationError("frozen R1 Router request config hash mismatch")
    request_config = load_json(request_source)
    for descriptor in pilot.get("cases", []):
        if descriptor.get("case_id") != case_id:
            continue
        source = (_root() / descriptor["source_task_receipt"]).resolve()
        if not is_contained(_root(), source):
            raise PayloadValidationError("source task receipt escapes the harness")
        source_bytes = source.read_bytes()
        digest = hashlib.sha256(source_bytes).hexdigest()
        if digest != descriptor["source_task_sha256"]:
            raise PayloadValidationError("frozen R1 task receipt hash mismatch")
        case = load_json(source)
        if case.get("case_id") != case_id:
            raise PayloadValidationError("frozen task case id mismatch")
        if freeze_validator_plan(case["validator_plan"]) != case["validator_plan_digest"]:
            raise PayloadValidationError("frozen validator plan digest mismatch")
        request_case = next(
            (
                candidate
                for candidate in request_config.get("cases", [])
                if candidate.get("case_id") == case_id
            ),
            None,
        )
        if request_case is None:
            raise PayloadValidationError("frozen R1 Router request is missing")
        for field in ("repository", "baseline_head", "task_text"):
            if request_case.get(field) != case.get(field):
                raise PayloadValidationError(
                    f"frozen R1 Router request binding mismatch: {field}"
                )
        if (
            freeze_validator_plan(request_case["validator_plan"])
            != case["validator_plan_digest"]
        ):
            raise PayloadValidationError(
                "frozen R1 Router request validator binding mismatch"
            )
        case["router_request"] = request_case["router_request"]
        return case, descriptor, source_bytes
    raise PayloadValidationError(f"unknown R2 case: {case_id}")


def _task_payload(case: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "schema_version",
        "case_id",
        "repository",
        "baseline_head",
        "title",
        "task_text",
        "changed_path_patterns",
        "risk",
        "validator_plan_digest",
    )
    return {key: case[key] for key in keys}


def _prompt(case: dict[str, Any], worktree: Path) -> str:
    validators = [
        {"name": item["name"], "layer": item.get("layer", "focused")}
        for item in case["validator_plan"]["commands"]
    ]
    return f"""Implement one bounded task inside this assigned worktree:
{worktree}

Task: {case['title']}
{case['task_text']}

Allowed changed paths: {json.dumps(case['changed_path_patterns'])}
Frozen parent-run validators: {json.dumps(validators)}

Rules:
- Read and write only inside the assigned worktree.
- Use only repository files and synthetic fixtures already inside the assigned worktree.
- Do not access credentials, user memory, external repositories, or paths outside the worktree.
- Do not use network access, web search, browser tools, apps, plugins, or subagents.
- Do not run git commit, merge, rebase, reset, clean, push, remote, tag, or stash.
- Do not deploy, publish, release, deliver, or modify persistent Git configuration.
- Do not weaken validators, safety boundaries, authority semantics, or compatibility.
- Make the smallest useful change and stop.
- Return only the required structured final result.
"""


def _known_target_paths(settings: dict[str, Any]) -> dict[str, str]:
    return {
        repository_id: entry["path"]
        for repository_id, entry in settings["repositories"].items()
    }


def _scan_child_commands(
    events_path: Path,
    forbidden_paths: list[str | Path],
) -> dict[str, bool]:
    result = {
        "forbidden_action_detected": False,
        "external_path_access_detected": False,
        "credential_access_detected": False,
    }
    if not events_path.exists():
        return result
    normalized = [
        str(Path(path).resolve()).replace("/", "\\").rstrip("\\").casefold()
        for path in forbidden_paths
    ]
    for line in events_path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        item = event.get("item")
        command = None
        if isinstance(item, dict) and item.get("type") == "command_execution":
            command = item.get("command")
        elif event.get("type") == "command_execution":
            command = event.get("command")
        if not isinstance(command, str):
            continue
        if FORBIDDEN_ACTION_RE.search(command):
            result["forbidden_action_detected"] = True
        if CREDENTIAL_ACCESS_RE.search(command):
            result["credential_access_detected"] = True
        command_normalized = command.replace("/", "\\").casefold()
        if any(path + "\\" in command_normalized for path in normalized):
            result["external_path_access_detected"] = True
    return result


def _render_plan(
    plan: dict[str, Any],
    worktree: Path,
    run_temp: Path,
) -> dict[str, Any]:
    encoded = json.dumps(plan)
    encoded = encoded.replace("{worktree}", str(worktree))
    encoded = encoded.replace("{run_temp}", str(run_temp))
    return json.loads(encoded)


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise GitContractError(completed.stderr.strip() or completed.stdout.strip())
    return completed.stdout.strip()


def verify_control_read_only(settings: dict[str, Any]) -> dict[str, Any]:
    repository = Path(settings["repositories"]["model-tier-router"]["path"])
    branch_commit = _git(repository, "rev-parse", f"refs/heads/{CONTROL_BRANCH}")
    parent = _git(repository, "rev-parse", f"{CONTROL_COMMIT}^")
    expected_baseline = _pilot()["existing_fixed_premium_control"]["baseline"]
    if branch_commit != CONTROL_COMMIT or parent != expected_baseline:
        raise RuntimeError("EXISTING_CONTROL_MISSING_OR_MUTATED")
    return {
        "branch": CONTROL_BRANCH,
        "commit": CONTROL_COMMIT,
        "parent": parent,
        "unchanged": True,
        "rerun": False,
        "merge": False,
    }


def _validate_model_map(model_map: dict[str, Any]) -> None:
    expected = {
        "economy": ("gpt-5.6-luna", "low", "balanced"),
        "balanced": ("gpt-5.6-terra", "medium", "premium"),
        "premium": ("gpt-5.6-sol", "high", None),
    }
    profiles = model_map.get("logical_profiles", {})
    if set(profiles) != set(expected):
        raise PayloadValidationError("model profile set mismatch")
    for profile, values in expected.items():
        entry = profiles[profile]
        actual = (
            entry.get("codex_model"),
            entry.get("model_reasoning_effort"),
            entry.get("next_escalation_profile"),
        )
        if actual != values:
            raise PayloadValidationError(f"model mapping mismatch for {profile}")


def preflight_r2() -> dict[str, Any]:
    settings = _settings()
    rows = []
    for repository_id, entry in settings["repositories"].items():
        state = require_clean_baseline(entry["path"], entry["path"], entry["baseline_head"])
        if state["branch"] != entry["branch"]:
            raise GitContractError("target primary branch mismatch")
        rows.append(
            {
                "repository": repository_id,
                "branch": state["branch"],
                "head": state["head"],
                "clean": state["clean"],
                "locks": state["locks"],
                "active_operations": state["active_operations"],
            }
        )
    model_map = load_model_map(_root() / "config" / "model-map.json")
    _validate_model_map(model_map)
    return {
        "schema_version": "2.0.0",
        "route_id": ROUTE_ID,
        "repositories": rows,
        "control": verify_control_read_only(settings),
        "harness_remote_count": len(repository_state(_root())["remotes"]),
        "model_map_valid": True,
        "out_of_scope_repository_access_count": 0,
    }


def _attempt(
    case: dict[str, Any],
    descriptor: dict[str, Any],
    source_task_bytes: bytes,
    decision: dict[str, Any],
    profile: str,
    attempt: int,
    escalation_count: int,
    budget: InvocationBudget,
) -> dict[str, Any]:
    settings = _settings()
    repository_entry = settings["repositories"][case["repository"]]
    repository = Path(repository_entry["path"])
    baseline = case["baseline_head"]
    require_clean_baseline(repository, repository, baseline)
    attempt_name = f"attempt-{attempt}"
    receipt_dir = (
        _root() / "runs" / "receipts" / "r2" / case["case_id"] / attempt_name
    )
    raw_dir = _root() / "runs" / "raw" / "r2" / case["case_id"] / attempt_name
    run_temp = raw_dir / "validator-temp"
    receipt_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)
    (run_temp / "validation" / "atomic").mkdir(parents=True, exist_ok=True)
    worktree = (
        Path(settings["worktree_pool"])
        / case["repository"]
        / f"{case['case_id']}-r2"
        / f"router_auto-{attempt}"
    )
    branch = f"{descriptor['branch_prefix']}-{attempt}"
    create_worktree(repository, settings["worktree_pool"], worktree, branch, baseline)
    committed = False
    try:
        metadata = worktree / ".mtr-dogfood-r2"
        metadata.mkdir(parents=True, exist_ok=False)
        local_schema = metadata / "execution-result.schema.json"
        final_output = metadata / "final-result.json"
        schema_source = _root() / "schemas" / "execution-result.schema.json"
        schema_bytes = schema_source.read_bytes()
        local_schema.write_bytes(schema_bytes)
        schema_digest = hashlib.sha256(schema_bytes).hexdigest()
        output_schema = load_json(local_schema)

        task_path = receipt_dir / "task.json"
        task_path.write_bytes(source_task_bytes)
        authority = {
            "schema_version": "1.0.0",
            "contract_id": ROUTE_ID,
            "case_id": case["case_id"],
            "target_repository": str(repository),
            "baseline_head": baseline,
            "allowed_worktree": str(worktree),
            "allowed_task": case["task_text"],
            "allowed_validation": [
                item["name"] for item in case["validator_plan"]["commands"]
            ],
            "allowed_commit_behavior": "validated local commit; risk-gated merge",
            "external_push_authorized": False,
            "known_external_sessions_declared_active": True,
            "execution_authority_source": "current explicit user authorization for MODEL_TIER_ROUTER_DOGFOOD_R2",
            "router_execution_authorized": False,
            "router_authorized_write_scope": [],
            "worktree_local_schema_path": str(local_schema),
            "child_writable_roots": [str(worktree)],
        }
        write_json(receipt_dir / "authority-receipt.json", authority)
        write_json(receipt_dir / "decision.json", decision)

        model_map = load_model_map(_root() / "config" / "model-map.json")
        model, effort = map_profile(model_map, profile)
        prompt = _prompt(case, worktree)
        command = build_command(worktree, model, effort, local_schema, final_output)
        forbidden_paths = [
            _root(),
            *[
                entry["path"]
                for entry in settings["repositories"].values()
            ],
        ]
        try:
            validate_launch_payloads(
                _task_payload(case),
                load_json(_root() / "schemas" / "task.schema.json"),
                authority,
                load_json(_root() / "schemas" / "authority-receipt.schema.json"),
                decision,
                output_schema,
                set(model_map["logical_profiles"]),
            )
            validate_child_transport(worktree, command, prompt, forbidden_paths)
        except (PayloadValidationError, ValueError):
            budget.record_payload_rejection()
            raise

        start_observation = capture_process_metadata(
            _known_target_paths(settings), {case["repository"]}
        )
        if start_observation.get("target_overlap") is True:
            raise RuntimeError("TARGET_REPOSITORY_OVERLAP_DETECTED")
        budget.require_available()
        execution = run_codex(
            command,
            prompt,
            raw_dir,
            worktree=worktree,
            timeout_seconds=int(case.get("model_timeout_seconds", 1200)),
            on_process_started=budget.record_process_start,
        )
        end_observation = capture_process_metadata(
            _known_target_paths(settings), {case["repository"]}
        )
        concurrency = {
            "schema_version": "2.0.0",
            "case_id": case["case_id"],
            "attempt": attempt,
            "start": start_observation,
            "end": end_observation,
            "measurement_quality": measurement_quality(True),
        }
        write_json(receipt_dir / "concurrency.json", concurrency)

        output_valid = final_output_valid(final_output, output_schema)
        if final_output.exists():
            shutil.copyfile(final_output, raw_dir / "final-result.json")
        schema_unchanged = (
            local_schema.exists()
            and hashlib.sha256(local_schema.read_bytes()).hexdigest() == schema_digest
        )
        child_claim = {}
        if output_valid:
            child_claim = load_json(final_output)
            claim_failure = classify_child_claim(child_claim)
            if (
                claim_failure is not None
                and execution.get("infrastructure_failure_class") is None
            ):
                execution["infrastructure_failure_class"] = claim_failure
                execution["host_policy_failure_count"] = max(
                    1, int(execution.get("host_policy_failure_count") or 0)
                )
                execution["child_reported_read_only_sandbox"] = True
        command_scan = _scan_child_commands(raw_dir / "codex-events.jsonl", forbidden_paths)
        shutil.rmtree(metadata)

        paths = changed_paths(worktree)
        patch = diff_bytes(worktree)
        (raw_dir / "diff.patch").write_bytes(patch)
        forbidden = any(command_scan.values()) or bool(
            child_claim.get("prohibited_action_attempted")
        )
        execution.update(
            {
                "schema_version": "2.0.0",
                "route_id": ROUTE_ID,
                "case_id": case["case_id"],
                "repository": case["repository"],
                "baseline_head": baseline,
                "experiment_arm": "ROUTER_AUTO",
                "router_profile": profile,
                "requested_codex_model": model,
                "requested_reasoning_effort": effort,
                "attempt": attempt,
                "escalation_count": escalation_count,
                "pre_model_payload_rejection_count": budget.pre_model_payload_rejections,
                "codex_exec_process_start_count_cumulative": budget.process_starts,
                "validator_completed": False,
                "wall_time_measurement_quality": measurement_quality(True),
                "changed_path_count": len(paths),
                "changed_paths": paths,
                "diff_sha256": hashlib.sha256(patch).hexdigest(),
                "final_output_valid": output_valid,
                "worktree_schema_unchanged": schema_unchanged,
                **command_scan,
            }
        )

        results: list[dict[str, Any]] = []
        if (
            execution.get("model_execution_completed")
            and execution.get("exit_code") == 0
            and paths
            and output_valid
            and schema_unchanged
            and not forbidden
            and execution.get("infrastructure_failure_class") is None
        ):
            plan = _render_plan(case["validator_plan"], worktree, run_temp)
            results = run_plan(worktree, plan, raw_dir)
            execution["validator_completed"] = True
        validation = summarize_validation(
            bool(
                execution.get("model_execution_completed")
                and execution.get("exit_code") == 0
            ),
            paths_allowed(paths, case["changed_path_patterns"]),
            results,
            forbidden,
        )
        if forbidden:
            failure_class = "FORBIDDEN_CHILD_ACTION"
        elif not schema_unchanged:
            failure_class = "CHILD_SCHEMA_TAMPER"
        elif not output_valid:
            failure_class = "MODEL_OUTPUT_SCHEMA_FAILURE"
        elif (
            execution.get("model_execution_observed")
            and not execution.get("model_execution_completed")
        ):
            failure_class = "IMPLEMENTATION_INCOMPLETE"
        else:
            failure_class = classify_attempt(
                execution, paths, validation["automated_acceptance"]
            )
        validation.update(
            {
                "schema_version": "2.0.0",
                "case_id": case["case_id"],
                "attempt": attempt,
                "changed_paths": paths,
                "failure_class": failure_class,
            }
        )
        write_json(receipt_dir / "execution.json", execution)
        write_json(receipt_dir / "validation.json", validation)

        commit_oid = None
        auto_merged = False
        merge_oid = None
        if validation["automated_acceptance"]:
            primary_before_commit = repository_state(repository)
            primary_unchanged = (
                primary_before_commit["head"] == baseline
                and primary_before_commit["clean"]
                and not primary_before_commit["locks"]
                and not primary_before_commit["active_operations"]
            )
            commit_oid = commit_exact_paths(
                worktree,
                paths,
                f"Dogfood {case['case_id']}: {case['title']}",
                settings["commit_identity"]["name"],
                settings["commit_identity"]["email"],
            )
            committed = True
            auto_merge_eligible = bool(
                descriptor["automatic_fast_forward_merge"]
                and primary_unchanged
                and risk_allows_auto_merge(
                    case["risk"], case["change_class"], "ROUTER_AUTO"
                )
            )
            if auto_merge_eligible:
                merge_oid = fast_forward(repository, baseline, commit_oid)
                auto_merged = True
        else:
            auto_merge_eligible = False
        outcome = {
            "schema_version": "2.0.0",
            "case_id": case["case_id"],
            "repository": case["repository"],
            "attempt": attempt,
            "router_profile": profile,
            "commit_created": commit_oid is not None,
            "commit_oid": commit_oid,
            "branch": branch,
            "baseline_head": baseline,
            "auto_merge_eligible": auto_merge_eligible,
            "auto_merged": auto_merged,
            "merge_oid": merge_oid,
            "automated_acceptance": validation["automated_acceptance"],
            "failure_class": failure_class,
            "worktree": str(worktree),
        }
        write_json(receipt_dir / "outcome.json", outcome)
        return {
            "execution": execution,
            "validation": validation,
            "outcome": outcome,
            "concurrency": concurrency,
        }
    finally:
        if worktree.exists():
            remove_worktree(repository, settings["worktree_pool"], worktree)
        if not committed:
            delete_unadvanced_branch(repository, branch, baseline)


def execute_lane(case_id: str, budget: InvocationBudget) -> dict[str, Any]:
    case, descriptor, source_bytes = _load_case(case_id)
    settings = _settings()
    repository_entry = settings["repositories"][case["repository"]]
    repository = Path(repository_entry["path"])
    require_clean_baseline(repository, repository, case["baseline_head"])
    if case_id == "mtr-docs-private-executor-r1" and any(
        (repository / relative).exists()
        for relative in (
            "docs/dogfood-automation.md",
            "tests/integrations/test_dogfood_automation.py",
        )
    ):
        raise RuntimeError("FROZEN_TASK_OR_VALIDATOR_MISSING")
    if case_id == "qwen-docx-hidden-elements-r1":
        focused_test = (
            repository / "tests" / "redaction" / "test_docx_package.py"
        ).read_text(encoding="utf-8")
        if "vanish" in focused_test or "webHidden" in focused_test:
            raise RuntimeError("FROZEN_TASK_OR_VALIDATOR_MISSING")
    model_map = load_model_map(_root() / "config" / "model-map.json")
    _validate_model_map(model_map)
    decision = assess_live(
        settings["router_repository"],
        case["router_request"],
        set(model_map["logical_profiles"]),
    )
    if decision.get("status") != "recommended":
        return {
            "case_id": case_id,
            "decision": decision,
            "attempts": [],
            "final_status": "ROUTER_NON_EXECUTION",
        }
    attempts = []
    profile = decision["selected_profile"]
    first = _attempt(
        case, descriptor, source_bytes, decision, profile, 1, 0, budget
    )
    attempts.append(first)
    if first["validation"]["automated_acceptance"]:
        return {
            "case_id": case_id,
            "decision": decision,
            "attempts": attempts,
            "escalation_count": 0,
            "final_status": "VALIDATED",
        }
    failure = first["validation"].get("failure_class")
    escalated = next_profile(profile, str(failure), 0)
    mapped_next = model_map["logical_profiles"][profile]["next_escalation_profile"]
    if escalated != mapped_next or escalated is None or budget.remaining <= 0:
        return {
            "case_id": case_id,
            "decision": decision,
            "attempts": attempts,
            "escalation_count": 0,
            "final_status": str(failure),
        }
    second = _attempt(
        case, descriptor, source_bytes, decision, escalated, 2, 1, budget
    )
    attempts.append(second)
    return {
        "case_id": case_id,
        "decision": decision,
        "attempts": attempts,
        "escalation_count": 1,
        "final_status": (
            "VALIDATED"
            if second["validation"]["automated_acceptance"]
            else str(second["validation"].get("failure_class"))
        ),
    }


def run_r2_batch() -> dict[str, Any]:
    preflight = preflight_r2()
    pilot = _pilot()
    budget = InvocationBudget(
        maximum=int(pilot["maximum_child_codex_exec_process_starts"])
    )
    lanes = []
    for descriptor in pilot["cases"]:
        try:
            lanes.append(execute_lane(descriptor["case_id"], budget))
        except RuntimeError as exc:
            if str(exc) == "TARGET_REPOSITORY_OVERLAP_DETECTED":
                lanes.append(
                    {
                        "case_id": descriptor["case_id"],
                        "attempts": [],
                        "final_status": str(exc),
                    }
                )
                continue
            raise
    verify_control_read_only(_settings())
    result = {
        "schema_version": "2.0.0",
        "route_id": ROUTE_ID,
        "preflight": preflight,
        "lanes": lanes,
        "pre_model_payload_rejection_count": budget.pre_model_payload_rejections,
        "child_codex_exec_process_start_count": budget.process_starts,
        "invocation_budget_remaining": budget.remaining,
        "existing_fixed_premium_control_unchanged": True,
    }
    report = build_r2_report(result, _root() / "runs" / "receipts")
    result["report_paths"] = write_r2_reports(report, _root() / "reports")
    write_json(_root() / "runs" / "receipts" / "r2" / "batch.json", result)
    return result


def correct_existing_r2_classifications() -> dict[str, Any]:
    receipt_root = _root() / "runs" / "receipts" / "r2"
    batch_path = receipt_root / "batch.json"
    batch = load_json(batch_path)
    corrections = []
    for lane in batch.get("lanes", []):
        for attempt in lane.get("attempts", []):
            execution = attempt["execution"]
            attempt_number = int(execution["attempt"])
            case_id = str(execution["case_id"])
            raw = _root() / "runs" / "raw" / "r2" / case_id / f"attempt-{attempt_number}"
            infrastructure = classify_infrastructure(
                (raw / "codex-events.jsonl").read_text(
                    encoding="utf-8", errors="replace"
                ),
                (raw / "stderr.log").read_text(
                    encoding="utf-8", errors="replace"
                ),
            )
            claim = load_json(raw / "final-result.json")
            claim_failure = classify_child_claim(claim)
            revised = (
                infrastructure.get("infrastructure_failure_class")
                or claim_failure
            )
            if revised != "HOST_POLICY_REJECTED_CHILD_FILESYSTEM_ACCESS":
                continue
            original = attempt["validation"].get("failure_class")
            execution.update(infrastructure)
            execution["infrastructure_failure_class"] = revised
            execution["host_policy_failure_count"] = max(
                1, int(execution.get("host_policy_failure_count") or 0)
            )
            execution["child_reported_read_only_sandbox"] = (
                claim_failure is not None
            )
            attempt["validation"]["failure_class"] = revised
            attempt["outcome"]["failure_class"] = revised
            attempt_dir = receipt_root / case_id / f"attempt-{attempt_number}"
            write_json(attempt_dir / "execution.json", execution)
            write_json(attempt_dir / "validation.json", attempt["validation"])
            write_json(attempt_dir / "outcome.json", attempt["outcome"])
            corrections.append(
                {
                    "case_id": case_id,
                    "attempt": attempt_number,
                    "original_failure_class": original,
                    "revised_failure_class": revised,
                    "stderr_sha256": hashlib.sha256(
                        (raw / "stderr.log").read_bytes()
                    ).hexdigest(),
                }
            )
        if lane.get("attempts"):
            lane["final_status"] = lane["attempts"][-1]["validation"][
                "failure_class"
            ]
    invalid_escalations = sum(
        bool(
            lane.get("escalation_count")
            and lane.get("attempts")
            and lane["attempts"][0]["validation"].get("failure_class")
            == "HOST_POLICY_REJECTED_CHILD_FILESYSTEM_ACCESS"
        )
        for lane in batch.get("lanes", [])
    )
    batch["classification_correction_applied"] = True
    batch["unauthorized_infrastructure_escalation_count"] = invalid_escalations
    batch["hard_stop_code"] = "HARNESS_REPAIR_TEST_FAILURE"
    write_json(batch_path, batch)
    correction = {
        "schema_version": "2.0.0",
        "route_id": ROUTE_ID,
        "corrections": corrections,
        "unauthorized_infrastructure_escalation_count": invalid_escalations,
        "new_child_codex_exec_process_starts": 0,
        "hard_stop_code": "HARNESS_REPAIR_TEST_FAILURE",
    }
    write_json(receipt_root / "classification-correction.json", correction)
    report = build_r2_report(batch, _root() / "runs" / "receipts")
    report["classification_correction_applied"] = True
    report["unauthorized_infrastructure_escalation_count"] = invalid_escalations
    report["hard_stop_code"] = "HARNESS_REPAIR_TEST_FAILURE"
    write_r2_reports(report, _root() / "reports")
    return correction
