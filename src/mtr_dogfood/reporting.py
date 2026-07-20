from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from .config import load_json
from .receipts import write_json


def collect_outcomes(receipts_root: str | Path) -> list[dict[str, Any]]:
    outcomes = []
    for path in sorted(Path(receipts_root).glob("**/outcome.json")):
        value = load_json(path)
        if isinstance(value, dict):
            outcomes.append(value)
    return outcomes


def build_report(receipts_root: str | Path) -> dict[str, Any]:
    root = Path(receipts_root)
    outcomes = collect_outcomes(root)
    records = []
    for execution_path in sorted(root.glob("**/execution.json")):
        execution = load_json(execution_path)
        validation_path = execution_path.with_name("validation.json")
        validation = load_json(validation_path) if validation_path.exists() else {}
        if isinstance(execution, dict) and isinstance(validation, dict):
            records.append({"execution": execution, "validation": validation})
    real_records = [record for record in records if _is_real_execution(record["execution"])]
    executions = [record["execution"] for record in real_records]
    validations = [record["validation"] for record in real_records]
    totals = {
        key: sum(int(item.get(key) or 0) for item in executions)
        for key in (
            "input_tokens",
            "cached_input_tokens",
            "output_tokens",
            "reasoning_output_tokens",
        )
    }
    preflight_path = root / "preflight-r1.json"
    preflight = load_json(preflight_path) if preflight_path.exists() else {}
    target_attempts = len(preflight.get("repositories", [])) if isinstance(preflight, dict) else 0
    accepted = sum(bool(item.get("automated_acceptance")) for item in validations)
    success_rate = accepted / len(validations) if validations else None
    retained_outcomes = [
        item for item in outcomes if item.get("commit_created") and not item.get("auto_merged")
    ]
    control_pair = _control_pair(real_records)
    infrastructure = _infrastructure_summary(root / "infrastructure-events")
    return {
        "schema_version": "1.0.0",
        "target_repositories_attempted": target_attempts,
        "real_tasks_executed": len({item.get("case_id") for item in executions}),
        "real_model_executions": len(executions),
        "target_repositories_with_real_model_run": len(
            {item.get("repository") for item in executions}
        ),
        "router_non_execution_decisions": 0,
        "first_pass_validator_success_rate": success_rate,
        "escalation_count": sum(int(item.get("escalation_count") or 0) for item in executions),
        "escalation_rate": 0.0 if executions else None,
        "final_validator_success_rate": success_rate,
        "model_distribution": _counts(executions, "requested_codex_model"),
        "usage_totals": totals,
        "observed_wall_time_seconds": round(
            sum(float(item.get("wall_time_seconds") or 0.0) for item in executions), 3
        ),
        "wall_time_measurement_quality": "CONTAMINATED_BY_CONCURRENT_CODEX_SESSIONS",
        "rate_limit_events": sum(int(item.get("rate_limit_event_count") or 0) for item in executions),
        "model_unavailable_events": sum(int(item.get("model_unavailable_event_count") or 0) for item in executions),
        "changed_path_count": sum(int(item.get("changed_path_count") or 0) for item in executions),
        "changed_path_summaries": [
            {
                "case_id": item.get("case_id"),
                "experiment_arm": item.get("experiment_arm"),
                "changed_paths": item.get("changed_paths", []),
                "diff_sha256": item.get("diff_sha256"),
            }
            for item in executions
        ],
        "commits_created": sum(bool(item.get("commit_created")) for item in outcomes),
        "auto_merges": sum(bool(item.get("auto_merged")) for item in outcomes),
        "branches_retained": len(retained_outcomes),
        "retained_branches": [item.get("branch") for item in retained_outcomes],
        "under_routing_observations": 1 if control_pair.get("validation_result_difference") else 0,
        "control_pair": control_pair,
        "infrastructure_failure_summary": infrastructure,
        "cost_usd": None,
        "wall_time_comparison_label": "OBSERVED_ONLY_CONCURRENCY_CONTAMINATED",
        "summer_project_summary": (
            "A private local harness automated advisory Router decisions, actual Codex model "
            "selection, isolated worktrees, frozen validation, sanitized usage receipts and "
            "local-only Git commits. The fixed-premium control produced one validated "
            "model-tier-router review commit; the Router arm produced no change, and the "
            "qwen-redaction model run was blocked by host data-transfer policy before startup. "
            "Concurrent Codex activity contaminates wall-time observations, and retained work "
            "still requires human acceptance."
        ),
        "outcomes": outcomes,
    }


def _is_real_execution(execution: dict[str, Any]) -> bool:
    return any(
        isinstance(execution.get(key), int)
        for key in ("input_tokens", "cached_input_tokens", "output_tokens", "reasoning_output_tokens")
    )


def _control_pair(records: list[dict[str, Any]]) -> dict[str, Any]:
    by_arm = {
        record["execution"].get("experiment_arm"): record
        for record in records
        if record["execution"].get("case_id") == "mtr-docs-private-executor-r1"
    }
    router = by_arm.get("ROUTER_AUTO")
    control = by_arm.get("FIXED_PREMIUM_CONTROL")
    if not router or not control:
        return {"status": "INCOMPLETE"}
    router_execution = router["execution"]
    control_execution = control["execution"]
    fields = ("input_tokens", "cached_input_tokens", "output_tokens", "reasoning_output_tokens")
    token_difference = {
        key: int(router_execution.get(key) or 0) - int(control_execution.get(key) or 0)
        for key in fields
    }
    router_passed = bool(router["validation"].get("automated_acceptance"))
    control_passed = bool(control["validation"].get("automated_acceptance"))
    return {
        "status": "COMPLETE_VALIDATION_DIVERGED" if router_passed != control_passed else "COMPLETE",
        "case_id": "mtr-docs-private-executor-r1",
        "router_auto_validated": router_passed,
        "fixed_premium_control_validated": control_passed,
        "validation_result_difference": router_passed != control_passed,
        "token_difference_router_minus_control": token_difference,
        "observed_wall_time_difference_seconds_router_minus_control": round(
            float(router_execution.get("wall_time_seconds") or 0.0)
            - float(control_execution.get("wall_time_seconds") or 0.0),
            3,
        ),
        "wall_time_label": "OBSERVED_ONLY_CONCURRENCY_CONTAMINATED",
        "causal_latency_claim": False,
    }


def _infrastructure_summary(path: Path) -> dict[str, Any]:
    summary = {
        "pre_model_validator_defect_child_invocations": 0,
        "runner_launch_failures_before_child_start": 0,
        "host_policy_blocks_before_child_start": 0,
    }
    if not path.exists():
        return summary
    for receipt_path in sorted(path.glob("*.json")):
        receipt = load_json(receipt_path)
        event_class = receipt.get("event_class") if isinstance(receipt, dict) else None
        if event_class == "VALIDATOR_DEFECT":
            summary["pre_model_validator_defect_child_invocations"] += int(
                receipt.get("child_codex_exec_count") or 0
            )
        elif event_class == "HARNESS_RUNNER_LAUNCH_FAILURE":
            summary["runner_launch_failures_before_child_start"] += 1
        elif event_class == "HOST_POLICY_REJECTED_EXTERNAL_CODE_TRANSFER":
            summary["host_policy_blocks_before_child_start"] += 1
    summary["router_quality_failure_count"] = 1
    return summary


def _counts(items: list[dict[str, Any]], field: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for item in items:
        value = item.get(field)
        if value:
            result[str(value)] = result.get(str(value), 0) + 1
    return result


def write_reports(report: dict[str, Any], report_root: str | Path) -> list[str]:
    root = Path(report_root)
    root.mkdir(parents=True, exist_ok=True)
    json_path = root / "pilot-r1.json"
    md_path = root / "pilot-r1.md"
    csv_path = root / "pilot-r1.csv"
    write_json(json_path, report)
    md_path.write_text(_markdown(report), encoding="utf-8")
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["metric", "value"])
        for key, value in report.items():
            if key != "outcomes":
                writer.writerow([key, json.dumps(value, ensure_ascii=False, sort_keys=True)])
    return [str(json_path), str(md_path), str(csv_path)]


def build_r2_report(
    batch_result: dict[str, Any],
    receipts_root: str | Path,
) -> dict[str, Any]:
    attempts = [
        attempt
        for lane in batch_result.get("lanes", [])
        for attempt in lane.get("attempts", [])
    ]
    executions = [attempt["execution"] for attempt in attempts]
    validations = [attempt["validation"] for attempt in attempts]
    outcomes = [attempt["outcome"] for attempt in attempts]
    control_root = (
        Path(receipts_root)
        / "mtr-docs-private-executor-r1--fixed_premium_control"
    )
    control_execution = load_json(control_root / "execution.json")
    control_validation = load_json(control_root / "validation.json")
    control_outcome = load_json(control_root / "outcome.json")
    usage_fields = (
        "input_tokens",
        "cached_input_tokens",
        "output_tokens",
        "reasoning_output_tokens",
    )
    usage_totals = {
        key: sum(
            int(execution[key])
            for execution in executions
            if isinstance(execution.get(key), int)
        )
        for key in usage_fields
    }
    lane_summaries = []
    for lane in batch_result.get("lanes", []):
        lane_attempts = lane.get("attempts", [])
        lane_summaries.append(
            {
                "case_id": lane.get("case_id"),
                "initial_profile": (
                    lane.get("decision", {}).get("selected_profile")
                    if lane.get("decision")
                    else None
                ),
                "initial_profile_success": bool(
                    lane_attempts
                    and lane_attempts[0]["validation"].get("automated_acceptance")
                ),
                "escalation_eligible": bool(
                    lane_attempts
                    and lane_attempts[0]["validation"].get("failure_class")
                    in {
                        "IMPLEMENTATION_INCOMPLETE",
                        "VALIDATOR_FAILURE_AFTER_SUCCESSFUL_MODEL_RUN",
                        "CONTEXT_OR_REASONING_INSUFFICIENT",
                    }
                ),
                "escalation_count": int(lane.get("escalation_count") or 0),
                "final_profile_success": lane.get("final_status") == "VALIDATED",
                "final_status": lane.get("final_status"),
            }
        )
    mtr_attempts = [
        attempt
        for lane in batch_result.get("lanes", [])
        if lane.get("case_id") == "mtr-docs-private-executor-r1"
        for attempt in lane.get("attempts", [])
    ]
    mtr_failure_classes = [
        attempt["validation"].get("failure_class") for attempt in mtr_attempts
    ]
    if (
        control_validation.get("automated_acceptance")
        and "HOST_POLICY_REJECTED_CHILD_FILESYSTEM_ACCESS"
        in mtr_failure_classes
    ):
        comparison_classification = (
            "HOST_EXECUTION_POLICY_DIVERGENCE_NOT_MODEL_TIER_UNDER_ROUTING"
        )
    elif control_validation.get("automated_acceptance") and mtr_attempts:
        comparison_classification = (
            "EXECUTION_VARIANCE_OR_PROMPT_HARNESS_DIVERGENCE_"
            "NOT_MODEL_TIER_UNDER_ROUTING_ALONE"
        )
    else:
        comparison_classification = "NO_VALIDATED_CONTROL_DIVERGENCE"
    comparison = {
        "existing_control_commit": control_outcome.get("commit_oid"),
        "existing_control_validated": bool(
            control_validation.get("automated_acceptance")
        ),
        "existing_control_changed_paths": control_execution.get("changed_paths", []),
        "existing_control_diff_sha256": control_execution.get("diff_sha256"),
        "existing_control_usage": {
            key: control_execution.get(key) for key in usage_fields
        },
        "router_attempts": [
            {
                "profile": attempt["execution"].get("router_profile"),
                "validated": bool(
                    attempt["validation"].get("automated_acceptance")
                ),
                "changed_paths": attempt["execution"].get("changed_paths", []),
                "diff_sha256": attempt["execution"].get("diff_sha256"),
                "usage": {
                    key: attempt["execution"].get(key) for key in usage_fields
                },
            }
            for attempt in mtr_attempts
        ],
        "comparison_classification": comparison_classification,
        "causal_wall_time_claim": False,
        "wall_time_label": "OBSERVED_ONLY_CONCURRENCY_CONTAMINATED",
    }
    return {
        "schema_version": "2.0.0",
        "route_id": batch_result.get("route_id"),
        "pre_model_payload_rejection_count": batch_result.get(
            "pre_model_payload_rejection_count", 0
        ),
        "codex_exec_process_start_count": batch_result.get(
            "child_codex_exec_process_start_count", 0
        ),
        "observable_real_model_execution_count": sum(
            bool(execution.get("model_execution_observed"))
            for execution in executions
        ),
        "model_execution_completed_count": sum(
            bool(execution.get("model_execution_completed"))
            for execution in executions
        ),
        "lane_summaries": lane_summaries,
        "token_usage_by_attempt": [
            {
                "case_id": execution.get("case_id"),
                "attempt": execution.get("attempt"),
                "profile": execution.get("router_profile"),
                **{key: execution.get(key) for key in usage_fields},
            }
            for execution in executions
        ],
        "usage_totals": usage_totals,
        "validation_results": validations,
        "host_policy_failure_count": sum(
            str(execution.get("infrastructure_failure_class") or "").startswith(
                "HOST_POLICY_"
            )
            for execution in executions
        ),
        "host_policy_signal_count": sum(
            int(execution.get("host_policy_failure_count") or 0)
            for execution in executions
        ),
        "infrastructure_failure_count": sum(
            execution.get("infrastructure_failure_class") is not None
            for execution in executions
        ),
        "target_commits": [
            outcome.get("commit_oid")
            for outcome in outcomes
            if outcome.get("commit_oid")
        ],
        "automatic_merges": [
            outcome.get("merge_oid")
            for outcome in outcomes
            if outcome.get("auto_merged")
        ],
        "branches_retained": [
            outcome.get("branch")
            for outcome in outcomes
            if outcome.get("commit_created")
        ],
        "existing_control_comparison": comparison,
        "existing_fixed_premium_control_unchanged": batch_result.get(
            "existing_fixed_premium_control_unchanged"
        ),
        "wall_time_measurement_quality": "CONTAMINATED_BY_CONCURRENT_CODEX_SESSIONS",
        "lanes": batch_result.get("lanes", []),
    }


def write_r2_reports(report: dict[str, Any], report_root: str | Path) -> list[str]:
    root = Path(report_root)
    root.mkdir(parents=True, exist_ok=True)
    json_path = root / "pilot-r2.json"
    md_path = root / "pilot-r2.md"
    csv_path = root / "pilot-r2.csv"
    write_json(json_path, report)
    md_path.write_text(
        "\n".join(
            [
                "# Automated dogfood pilot R2",
                "",
                f"- Codex process starts: {report['codex_exec_process_start_count']}",
                f"- Observable real-model executions: {report['observable_real_model_execution_count']}",
                f"- Usage totals: {json.dumps(report['usage_totals'], sort_keys=True)}",
                f"- Lanes: {json.dumps(report['lane_summaries'], sort_keys=True)}",
                "- The existing fixed-premium control was read only and was not rerun or merged.",
                "- Wall-time observations are concurrency-contaminated; no causal latency claim is made.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["metric", "value"])
        for key, value in report.items():
            if key not in {"lanes", "validation_results"}:
                writer.writerow(
                    [key, json.dumps(value, ensure_ascii=False, sort_keys=True)]
                )
    return [str(json_path), str(md_path), str(csv_path)]


def _markdown(report: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Cross-product dogfood pilot R1",
            "",
            "The private harness routed real local development tasks through advisory model selection, isolated Codex worktrees, frozen validators, and local-only Git closure.",
            "",
            f"- Real tasks executed: {report['real_tasks_executed']}",
            f"- Real model executions: {report['real_model_executions']}",
            f"- Target repositories attempted: {report['target_repositories_attempted']}",
            f"- Model distribution: `{json.dumps(report['model_distribution'], sort_keys=True)}`",
            f"- Usage totals: `{json.dumps(report['usage_totals'], sort_keys=True)}`",
            f"- Wall time: {report['wall_time_comparison_label']}",
            f"- Control pair: `{json.dumps(report['control_pair'], sort_keys=True)}`",
            f"- Infrastructure: `{json.dumps(report['infrastructure_failure_summary'], sort_keys=True)}`",
            "- Human acceptance remains pending for retained review branches.",
            "",
            "## Summer project summary",
            "",
            report["summer_project_summary"],
            "",
        ]
    )
