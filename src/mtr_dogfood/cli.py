from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from .codex_runner import build_command, run_codex
from .concurrency import capture_process_metadata, measurement_quality
from .config import canonical_json_bytes, harness_root, json_digest, load_json
from .git_worktrees import (
    GitContractError,
    changed_paths,
    commit_exact_paths,
    create_worktree,
    diff_bytes,
    fast_forward,
    remove_worktree,
    repository_state,
    require_clean_baseline,
)
from .receipts import write_json
from .reporting import build_report, write_reports
from .router_adapter import assess_live, load_model_map, map_profile
from .task_selection import arm_order, eligible
from .validation import (
    freeze_validator_plan,
    paths_allowed,
    risk_allows_auto_merge,
    run_plan,
    summarize_validation,
)


CONTRACT_ID = "MODEL_TIER_ROUTER_CROSS_PRODUCT_AUTOMATED_DOGFOOD_R1_CONCURRENT_SAFE"
FORBIDDEN_ACTION_RE = re.compile(
    r"\bgit\s+(commit|merge|rebase|reset|clean|push|remote|tag|stash)\b|\b(publish|deploy)\b",
    re.I,
)


def _root() -> Path:
    return harness_root()


def _config(name: str) -> Any:
    return load_json(_root() / "config" / name)


def _json_print(value: Any) -> None:
    sys.stdout.buffer.write(canonical_json_bytes(value))


def _repository_table() -> dict[str, Any]:
    return _config("repositories.json")


def command_preflight(_: argparse.Namespace) -> int:
    settings = _repository_table()
    rows = []
    for repository_id, entry in settings["repositories"].items():
        state = repository_state(entry["path"])
        rows.append(
            {
                "repository": repository_id,
                "path": entry["path"],
                "branch": state["branch"],
                "head": state["head"],
                "expected_head": entry["baseline_head"],
                "head_matches": state["head"] == entry["baseline_head"],
                "clean": state["clean"],
                "locks": state["locks"],
                "active_operations": state["active_operations"],
                "remote_count": len(state["remotes"]),
                "tag_count": len(state["tags"]),
            }
        )
    known = {
        **{key: value["path"] for key, value in settings["repositories"].items()},
        **settings["known_external_repositories"],
    }
    concurrency = capture_process_metadata(known, set(settings["repositories"]))
    _json_print(
        {
            "schema_version": "1.0.0",
            "repositories": rows,
            "concurrency": concurrency,
            "harness_remote_count": len(repository_state(_root())["remotes"]),
        }
    )
    return 0 if all(row["head_matches"] and row["clean"] for row in rows) else 2


def _find_case(case_id: str) -> dict[str, Any]:
    pilot = _config("pilot-r1.json")
    for case in pilot.get("cases", []):
        if case.get("case_id") == case_id:
            ok, reasons = eligible(case)
            if not ok:
                raise ValueError(f"ineligible case: {reasons}")
            return case
    raise ValueError(f"unknown case: {case_id}")


def _known_paths(settings: dict[str, Any]) -> dict[str, str]:
    return {
        **{key: value["path"] for key, value in settings["repositories"].items()},
        **settings["known_external_repositories"],
    }


def _run_id(case_id: str, arm: str) -> str:
    return f"{case_id}--{arm.lower()}"


def _render_plan(plan: dict[str, Any], worktree: Path, run_temp: Path) -> dict[str, Any]:
    rendered = copy.deepcopy(plan)
    substitutions = {
        "{worktree}": str(worktree),
        "{run_temp}": str(run_temp),
    }
    for validator in rendered["commands"]:
        validator["command"] = [
            _replace(part, substitutions) for part in validator["command"]
        ]
        validator["env"] = {
            key: _replace(value, substitutions)
            for key, value in validator.get("env", {}).items()
        }
    return rendered


def _replace(value: Any, substitutions: dict[str, str]) -> str:
    result = str(value)
    for old, new in substitutions.items():
        result = result.replace(old, new)
    return result


def _prompt(case: dict[str, Any], arm: str) -> str:
    validators = [item["name"] for item in case["validator_plan"]["commands"]]
    return f"""You are the implementation child for one bounded private dogfood task.

Repository: {case['repository']}
Case: {case['case_id']}
Experiment arm: {arm}
Task: {case['title']}

Implement exactly this acceptance-scoped task:
{case['task_text']}

Allowed changed paths: {json.dumps(case['changed_path_patterns'])}
Frozen validators run by the parent after you finish: {json.dumps(validators)}

Hard rules:
- Work only in the current isolated worktree.
- Do not access any other repository, including qwen or trading-authority-OS.
- Use only source code, tests, public documentation, and synthetic fixtures already in this worktree.
- Do not read customer, company, confidential, credential, cookie, key, token, runtime delivery, or broker material.
- Do not use web search or any network/provider tool.
- Do not run git commit, merge, rebase, reset, clean, push, remote, tag, or stash.
- Do not deploy, publish, release, deliver, or modify persistent Git configuration.
- Do not weaken validators, safety boundaries, authority semantics, or compatibility guarantees.
- Make the smallest useful change and stop.
- Your final response must conform exactly to the supplied JSON schema and truthfully list changed paths and any tests you ran.
"""


def _forbidden_action_detected(events_path: Path) -> bool:
    if not events_path.exists():
        return False
    for line in events_path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        command = None
        item = event.get("item")
        if isinstance(item, dict) and item.get("type") == "command_execution":
            command = item.get("command")
        elif event.get("type") == "command_execution":
            command = event.get("command")
        if isinstance(command, str) and FORBIDDEN_ACTION_RE.search(command):
            return True
    return False


def execute_case(case: dict[str, Any], arm: str, *, defer_merge: bool) -> dict[str, Any]:
    settings = _repository_table()
    repository_entry = settings["repositories"][case["repository"]]
    repository = Path(repository_entry["path"])
    baseline = case["baseline_head"]
    require_clean_baseline(repository, repository, baseline)
    run_id = _run_id(case["case_id"], arm)
    receipt_dir = _root() / "runs" / "receipts" / run_id
    raw_dir = _root() / "runs" / "raw" / run_id
    run_temp = raw_dir / "tmp"
    receipt_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)
    run_temp.mkdir(parents=True, exist_ok=True)
    (run_temp / "validation" / "atomic").mkdir(parents=True, exist_ok=True)
    worktree = (
        Path(settings["worktree_pool"])
        / case["repository"]
        / case["case_id"]
        / f"{arm.lower()}-1"
    )
    branch = f"mtr-dogfood/{case['case_id']}/{arm.lower()}-1"
    create_worktree(repository, settings["worktree_pool"], worktree, branch, baseline)

    task_receipt = {
        "schema_version": "1.0.0",
        **{key: value for key, value in case.items() if key != "router_request"},
        "experiment_arm": arm,
        "validator_plan_digest": freeze_validator_plan(case["validator_plan"]),
    }
    write_json(receipt_dir / "task.json", task_receipt)
    authority = {
        "schema_version": "1.0.0",
        "contract_id": CONTRACT_ID,
        "case_id": case["case_id"],
        "target_repository": str(repository),
        "baseline_head": baseline,
        "allowed_worktree": str(worktree),
        "allowed_task": case["task_text"],
        "allowed_validation": [item["name"] for item in case["validator_plan"]["commands"]],
        "allowed_commit_behavior": "validated local commit; risk-gated merge",
        "external_push_authorized": False,
        "known_external_sessions_declared_active": True,
    }
    write_json(receipt_dir / "authority-receipt.json", authority)

    model_map = load_model_map(_root() / "config" / "model-map.json")
    if arm == "ROUTER_AUTO":
        decision = assess_live(
            settings["router_repository"],
            case["router_request"],
            set(model_map["logical_profiles"]),
        )
        if decision["status"] != "recommended":
            write_json(receipt_dir / "decision.json", decision)
            outcome = _empty_outcome(case, arm, branch, "router_non_execution")
            write_json(receipt_dir / "outcome.json", outcome)
            return outcome
        profile = decision["selected_profile"]
    else:
        profile = "premium"
        decision = {
            "schema_version": "1.0.0",
            "status": "recommended",
            "selected_profile": "premium",
            "execution_authorized": False,
            "authorized_write_scope": [],
            "control_arm": True,
        }
        decision["dogfood_decision_digest"] = json_digest(decision)
    model, effort = map_profile(model_map, profile)
    write_json(receipt_dir / "decision.json", decision)

    start_observation = capture_process_metadata(
        _known_paths(settings), set(settings["repositories"])
    )
    if start_observation.get("target_overlap") is True:
        raise RuntimeError("HARD_STOP_CONCURRENT_TARGET_REPOSITORY_SESSION_DETECTED")
    final_output = raw_dir / "final-result.json"
    command = build_command(
        worktree,
        model,
        effort,
        _root() / "schemas" / "execution-result.schema.json",
        final_output,
    )
    execution = run_codex(
        command,
        _prompt(case, arm),
        raw_dir,
        timeout_seconds=int(case.get("model_timeout_seconds", 1200)),
    )
    end_observation = capture_process_metadata(
        _known_paths(settings), set(settings["repositories"])
    )
    concurrency = {
        "schema_version": "1.0.0",
        "case_id": case["case_id"],
        "experiment_arm": arm,
        "start": start_observation,
        "end": end_observation,
        "known_qwen_declared_active": True,
        "known_trading_authority_os_declared_active": True,
        "measurement_quality": measurement_quality(True),
    }
    write_json(receipt_dir / "concurrency.json", concurrency)

    paths = changed_paths(worktree)
    patch = diff_bytes(worktree)
    (raw_dir / "diff.patch").write_bytes(patch)
    forbidden = _forbidden_action_detected(raw_dir / "codex-events.jsonl")
    execution.update(
        {
            "schema_version": "1.0.0",
            "case_id": case["case_id"],
            "repository": case["repository"],
            "baseline_head": baseline,
            "experiment_arm": arm,
            "router_profile": profile,
            "requested_codex_model": model,
            "requested_reasoning_effort": effort,
            "runtime_model_confirmation_status": "REQUEST_RECORDED_STRUCTURED_CONFIRMATION_UNAVAILABLE",
            "attempt": 1,
            "escalation_count": 0,
            "wall_time_measurement_quality": measurement_quality(True),
            "changed_path_count": len(paths),
            "changed_paths": paths,
            "diff_sha256": hashlib.sha256(patch).hexdigest(),
            "observable_external_codex_process_count_start": start_observation.get("other_observable_codex_process_count"),
            "observable_external_codex_process_count_end": end_observation.get("other_observable_codex_process_count"),
        }
    )
    write_json(receipt_dir / "execution.json", execution)

    infrastructure_failure = execution.get("infrastructure_failure_class")
    if execution["exit_code"] != 0 or infrastructure_failure or not paths:
        validation = summarize_validation(True, False, [], forbidden)
        validation["failure_class"] = infrastructure_failure or "IMPLEMENTATION_INCOMPLETE"
    else:
        plan = _render_plan(case["validator_plan"], worktree, run_temp)
        results = run_plan(worktree, plan, raw_dir)
        validation = summarize_validation(
            True,
            paths_allowed(paths, case["changed_path_patterns"]),
            results,
            forbidden,
        )
    validation.update(
        {
            "schema_version": "1.0.0",
            "case_id": case["case_id"],
            "experiment_arm": arm,
            "changed_paths": paths,
        }
    )
    write_json(receipt_dir / "validation.json", validation)

    commit_oid = None
    if validation["automated_acceptance"]:
        require_clean_baseline(repository, repository, baseline)
        commit_oid = commit_exact_paths(
            worktree,
            paths,
            f"Dogfood {case['case_id']}: {case['title']}",
            settings["commit_identity"]["name"],
            settings["commit_identity"]["email"],
        )
    commit_receipt = {
        "schema_version": "1.0.0",
        "case_id": case["case_id"],
        "experiment_arm": arm,
        "commit_created": commit_oid is not None,
        "commit_oid": commit_oid,
        "branch": branch,
        "auto_merge_eligible": bool(
            commit_oid
            and risk_allows_auto_merge(case["risk"], case["change_class"], arm)
        ),
    }
    write_json(receipt_dir / "commit.json", commit_receipt)
    outcome = {
        "schema_version": "1.0.0",
        "case_id": case["case_id"],
        "repository": case["repository"],
        "experiment_arm": arm,
        "commit_created": commit_oid is not None,
        "commit_oid": commit_oid,
        "branch": branch,
        "baseline_head": baseline,
        "auto_merge_eligible": commit_receipt["auto_merge_eligible"],
        "auto_merged": False,
        "merge_oid": None,
        "human_review_state": "pending_for_branch_only_or_not_required_for_auto_merge",
        "human_accepted": None,
        "rework_required": None,
        "rollback_within_7_days": None,
        "worktree": str(worktree),
    }
    if commit_oid and commit_receipt["auto_merge_eligible"] and not defer_merge:
        outcome["merge_oid"] = fast_forward(repository, baseline, commit_oid)
        outcome["auto_merged"] = True
    write_json(receipt_dir / "outcome.json", outcome)
    return outcome


def _empty_outcome(case: dict[str, Any], arm: str, branch: str, state: str) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "case_id": case["case_id"],
        "repository": case["repository"],
        "experiment_arm": arm,
        "commit_created": False,
        "commit_oid": None,
        "branch": branch,
        "auto_merged": False,
        "merge_oid": None,
        "human_review_state": state,
        "human_accepted": None,
        "rework_required": None,
        "rollback_within_7_days": None,
    }


def command_run(args: argparse.Namespace) -> int:
    result = execute_case(_find_case(args.case_id), args.arm, defer_merge=False)
    _json_print(result)
    return 0 if result.get("commit_created") else 1


def command_batch(_: argparse.Namespace) -> int:
    pilot = _config("pilot-r1.json")
    outcomes = []
    invocation_count = 0
    for case in pilot.get("cases", []):
        ok, reasons = eligible(case)
        if not ok:
            outcomes.append({"case_id": case.get("case_id"), "skipped": reasons})
            continue
        arms = case.get("arms", ["ROUTER_AUTO"])
        if sorted(arms) == ["FIXED_PREMIUM_CONTROL", "ROUTER_AUTO"]:
            arms = arm_order(case["case_id"])
        for arm in arms:
            if invocation_count >= 9:
                raise RuntimeError("CHILD_MODEL_RUN_LIMIT_REACHED")
            outcome = execute_case(case, arm, defer_merge=True)
            outcomes.append(outcome)
            invocation_count += 1
    settings = _repository_table()
    for outcome in outcomes:
        if not isinstance(outcome, dict) or not outcome.get("auto_merge_eligible"):
            continue
        if not outcome.get("commit_oid"):
            continue
        observation = capture_process_metadata(
            _known_paths(settings), set(settings["repositories"])
        )
        if observation.get("target_overlap") is not False:
            continue
        repository = settings["repositories"][outcome["repository"]]["path"]
        try:
            merge_oid = fast_forward(
                repository, outcome["baseline_head"], outcome["commit_oid"]
            )
        except GitContractError:
            continue
        outcome["auto_merged"] = True
        outcome["merge_oid"] = merge_oid
        write_json(
            _root() / "runs" / "receipts" / _run_id(outcome["case_id"], outcome["experiment_arm"]) / "outcome.json",
            outcome,
        )
    report = build_report(_root() / "runs" / "receipts")
    paths = write_reports(report, _root() / "reports")
    _json_print({"invocation_count": invocation_count, "outcomes": outcomes, "report_paths": paths})
    return 0 if any(item.get("commit_created") for item in outcomes if isinstance(item, dict)) else 1


def command_report(_: argparse.Namespace) -> int:
    report = build_report(_root() / "runs" / "receipts")
    paths = write_reports(report, _root() / "reports")
    _json_print({"report": report, "paths": paths})
    return 0


def command_record_outcome(args: argparse.Namespace) -> int:
    matches = sorted((_root() / "runs" / "receipts").glob(f"{args.case_id}--*/outcome.json"))
    if not matches:
        raise ValueError("outcome not found")
    for path in matches:
        value = load_json(path)
        value["human_review_state"] = args.state
        value["human_accepted"] = True if args.state == "accepted" else False if args.state == "rejected" else None
        write_json(path, value)
    _json_print({"updated": [str(path) for path in matches]})
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mtr-dogfood")
    subparsers = parser.add_subparsers(dest="command", required=True)
    preflight = subparsers.add_parser("preflight")
    preflight.set_defaults(function=command_preflight)
    run = subparsers.add_parser("run")
    run.add_argument("--case-id", required=True)
    run.add_argument("--arm", choices=["ROUTER_AUTO", "FIXED_PREMIUM_CONTROL"], default="ROUTER_AUTO")
    run.set_defaults(function=command_run)
    batch = subparsers.add_parser("batch")
    batch.set_defaults(function=command_batch)
    report = subparsers.add_parser("report")
    report.set_defaults(function=command_report)
    outcome = subparsers.add_parser("record-outcome")
    outcome.add_argument("--case-id", required=True)
    outcome.add_argument("--state", choices=["pending", "accepted", "rejected"], required=True)
    outcome.set_defaults(function=command_record_outcome)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.function(args))
    except Exception as exc:
        _json_print({"status": "error", "error_type": type(exc).__name__, "message": str(exc)})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
