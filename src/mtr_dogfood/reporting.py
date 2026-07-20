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
    outcomes = collect_outcomes(receipts_root)
    executions = []
    validations = []
    for execution_path in sorted(Path(receipts_root).glob("**/execution.json")):
        value = load_json(execution_path)
        if isinstance(value, dict):
            executions.append(value)
    for validation_path in sorted(Path(receipts_root).glob("**/validation.json")):
        value = load_json(validation_path)
        if isinstance(value, dict):
            validations.append(value)
    totals = {
        key: sum(int(item.get(key) or 0) for item in executions)
        for key in (
            "input_tokens",
            "cached_input_tokens",
            "output_tokens",
            "reasoning_output_tokens",
        )
    }
    return {
        "schema_version": "1.0.0",
        "target_repositories_attempted": len({item.get("repository") for item in executions}),
        "real_tasks_executed": len(executions),
        "first_pass_validator_success_rate": (
            sum(bool(item.get("automated_acceptance")) for item in validations) / len(validations)
            if validations
            else None
        ),
        "final_validator_success_rate": (
            sum(bool(item.get("automated_acceptance")) for item in validations) / len(validations)
            if validations
            else None
        ),
        "model_distribution": _counts(executions, "requested_codex_model"),
        "usage_totals": totals,
        "rate_limit_events": sum(int(item.get("rate_limit_event_count") or 0) for item in executions),
        "model_unavailable_events": sum(int(item.get("model_unavailable_event_count") or 0) for item in executions),
        "commits_created": sum(bool(item.get("commit_created")) for item in outcomes),
        "auto_merges": sum(bool(item.get("auto_merged")) for item in outcomes),
        "branches_retained": sum(bool(item.get("branch")) and not item.get("auto_merged") for item in outcomes),
        "cost_usd": None,
        "wall_time_comparison_label": "OBSERVED_ONLY_CONCURRENCY_CONTAMINATED",
        "outcomes": outcomes,
    }


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


def _markdown(report: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Cross-product dogfood pilot R1",
            "",
            "The private harness routed real local development tasks through advisory model selection, isolated Codex worktrees, frozen validators, and local-only Git closure.",
            "",
            f"- Real model executions: {report['real_tasks_executed']}",
            f"- Target repositories attempted: {report['target_repositories_attempted']}",
            f"- Model distribution: `{json.dumps(report['model_distribution'], sort_keys=True)}`",
            f"- Usage totals: `{json.dumps(report['usage_totals'], sort_keys=True)}`",
            f"- Wall time: {report['wall_time_comparison_label']}",
            "- Human acceptance remains pending for retained review branches.",
            "",
        ]
    )
