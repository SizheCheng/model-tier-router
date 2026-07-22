from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any


def canonical(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def materialize_r5k_regression_packet(root: Path, repository_root: Path) -> Path:
    frozen = root / "frozen"
    frozen.mkdir(parents=True)
    pilot = json.loads(
        (repository_root / "config" / "pilot-r1.json").read_text(encoding="utf-8")
    )
    specifications = (
        (
            "mtr-docs-private-executor-r1",
            "model-tier-router",
            "runs/receipts/mtr-docs-private-executor-r1--router_auto/task.json",
            "runs/receipts/r2/mtr-docs-private-executor-r1/attempt-1/decision.json",
        ),
        (
            "qwen-docx-hidden-elements-r1",
            "qwen-redaction-standalone",
            "runs/receipts/qwen-docx-hidden-elements-r1--router_auto/task.json",
            "runs/receipts/r2/qwen-docx-hidden-elements-r1/attempt-1/decision.json",
        ),
    )
    lanes = []
    for ordinal, (lane_id, repository_id, task_relative, decision_relative) in enumerate(
        specifications, start=1
    ):
        task_name = f"task_router_lane_{ordinal}.json"
        decision_name = f"expected_decision_router_lane_{ordinal}.json"
        task_source = repository_root / task_relative
        decision_source = repository_root / decision_relative
        shutil.copyfile(task_source, frozen / task_name)
        shutil.copyfile(decision_source, frozen / decision_name)
        task = json.loads(task_source.read_text(encoding="utf-8"))
        decision = json.loads(decision_source.read_text(encoding="utf-8"))
        request = next(
            item["router_request"]
            for item in pilot["cases"]
            if item["case_id"] == lane_id
        )
        lanes.append({
            "lane_id": lane_id,
            "source_head": task["baseline_head"],
            "source_repository": repository_id,
            "routing_input": request,
            "selected_profile": decision["selected_profile"],
            "selected_model": "gpt-5.6-terra",
            "reasoning_effort": "medium",
            "task_snapshot": f"frozen/{task_name}",
            "decision_snapshot": f"frozen/{decision_name}",
            "timeout_seconds": task["model_timeout_seconds"],
        })
    manifest = {
        "schema_version": "1.0.0",
        "route_id": "R5K_TRACKED_REGRESSION_FIXTURE",
        "model_mapping": {
            "economy": {"model": "gpt-5.6-luna", "reasoning_effort": "low"},
            "balanced": {"model": "gpt-5.6-terra", "reasoning_effort": "medium"},
            "premium": {"model": "gpt-5.6-sol", "reasoning_effort": "high"},
        },
        "lanes": lanes,
    }
    (root / "EXECUTION_MANIFEST.json").write_bytes(canonical(manifest))
    files = sorted(path for path in root.rglob("*") if path.is_file())
    lines = [
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  "
        f"{path.relative_to(root).as_posix()}"
        for path in files
    ]
    (root / "PACKET_SHA256SUMS.txt").write_text(
        "\n".join(lines) + "\n", encoding="utf-8", newline="\n"
    )
    return root