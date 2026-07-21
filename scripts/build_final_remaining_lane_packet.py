from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


ROUTE_ID = "FINAL_REMAINING_QWEN_PRODUCT_LANE_EXECUTION_R1"
R5K_RELATIVE = (
    "runs/raw/r5k-two-product-lane-successor-campaign-3-packet-r1"
)


def canonical(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "GIT_FAILURE")
    return completed.stdout.strip()


def repository_state(path: Path) -> dict[str, Any]:
    return {
        "path": str(path.resolve()),
        "head": git(path, "rev-parse", "HEAD"),
        "branch": git(path, "branch", "--show-current"),
        "status": git(
            path, "status", "--porcelain=v2", "--untracked-files=all"
        ).splitlines(),
    }


def packet_files(root: Path) -> list[Path]:
    return [
        path
        for path in sorted(root.rglob("*"))
        if path.is_file()
        and path.name != "PACKET_SHA256SUMS.txt"
        and "results" not in path.relative_to(root).parts
    ]


def build(
    output_directory: Path,
    router_repository: Path,
    qwen_repository: Path,
) -> dict[str, Any]:
    root = Path(__file__).resolve().parents[1]
    r5k = root / R5K_RELATIVE
    if output_directory.exists() and any(output_directory.iterdir()):
        raise RuntimeError("FINAL_PACKET_OUTPUT_NOT_EMPTY")
    output_directory.mkdir(parents=True, exist_ok=True)

    r5k_manifest = json.loads(
        (r5k / "EXECUTION_MANIFEST.json").read_text(encoding="utf-8")
    )
    router_state = repository_state(router_repository)
    qwen_state = repository_state(qwen_repository)
    if router_state["status"] or qwen_state["status"]:
        raise RuntimeError("SOURCE_REPOSITORY_DIRTY")
    source_binding = next(
        item
        for item in r5k_manifest["lanes"]
        if item["lane_id"] == "qwen-docx-hidden-elements-r1"
    )
    lane_id = source_binding["lane_id"]
    frozen = output_directory / "frozen"
    frozen.mkdir()
    task_name = "task_lane_1.json"
    decision_name = "decision_lane_1.json"
    task_source = r5k / source_binding["task_snapshot"]
    decision_source = r5k / source_binding["decision_snapshot"]
    shutil.copyfile(task_source, frozen / task_name)
    shutil.copyfile(decision_source, frozen / decision_name)
    if qwen_state["head"] != source_binding["source_head"]:
        raise RuntimeError("SOURCE_HEAD_DRIFT")
    lanes = [{
        "lane_id": lane_id,
        "ordinal": 1,
        "successor_ordinal": 1,
        "prior_r5_ordinal_1_permanently_consumed": True,
        "source_repository": qwen_state["path"],
        "source_head": qwen_state["head"],
        "router_repository": router_state["path"],
        "routing_input": source_binding["routing_input"],
        "selected_profile": source_binding["selected_profile"],
        "selected_model": source_binding["selected_model"],
        "reasoning_effort": source_binding["reasoning_effort"],
        "task_snapshot": f"frozen/{task_name}",
        "task_sha256": sha256(frozen / task_name),
        "decision_snapshot": f"frozen/{decision_name}",
        "decision_sha256": sha256(frozen / decision_name),
        "timeout_seconds": source_binding["timeout_seconds"],
    }]

    build_artifact = subprocess.run(
        [
            sys.executable,
            "-B",
            str(root / "scripts" / "build_qualification_artifact.py"),
            "--output-directory",
            str(output_directory),
            "--entrypoint",
            "remaining-lane",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
    )
    if build_artifact.returncode != 0:
        raise RuntimeError(
            build_artifact.stderr.strip()
            or build_artifact.stdout.strip()
            or "FINAL_ARTIFACT_BUILD_FAILED"
        )
    artifact_manifest = json.loads(build_artifact.stdout)
    artifact = output_directory / "mtr-dogfood-remaining-lane.pyz"
    wrapper = output_directory / "RUN_FINAL_REMAINING_QWEN_LANE.ps1"
    manifest = {
        "schema_version": "1.0.0",
        "route_id": ROUTE_ID,
        "campaign_id": ROUTE_ID,
        "execution_order": [item["lane_id"] for item in lanes],
        "maximum_new_starts": 1,
        "no_retry": True,
        "stop_on_first_failure": True,
        "r5_ordinal_1_permanently_consumed": True,
        "r5_ordinal_1_reclaimed": False,
        "r5j_reuse_authorized": False,
        "r5k_reuse_authorized": False,
        "pre_reservation_failure_starts_consumed": 0,
        "reserved_failed_start_remains_consumed": True,
        "prior_campaign": "FINAL_TWO_PRODUCT_LANE_EXECUTION_R1",
        "prior_campaign_terminal": True,
        "prior_campaign_reused": False,
        "recovered_lane": "mtr-docs-private-executor-r1",
        "remaining_lane": "qwen-docx-hidden-elements-r1",
        "router_source_head": router_state["head"],
        "model_mapping": r5k_manifest["model_mapping"],
        "commit_identity": {
            "name": "SizheCheng",
            "email": "ChengSizhe@proton.me",
        },
        "runtime_release": {
            "source_head": artifact_manifest["source_head"],
            "source_dirty": artifact_manifest["source_dirty"],
            "artifact_path": str(artifact.resolve()),
            "artifact_sha256": sha256(artifact),
            "wrapper_path": str(wrapper.resolve()),
            "wrapper_sha256": sha256(wrapper),
        },
        "historical_input": {
            "r5k_packet_manifest_sha256": sha256(
                r5k / "PACKET_SHA256SUMS.txt"
            ),
            "r5k_used_as_regression_input_only": True,
            "r5k_campaign_reused": False,
        },
        "lanes": lanes,
    }
    (output_directory / "FINAL_EXECUTION_MANIFEST.json").write_bytes(
        canonical(manifest)
    )
    command = (
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File "
        f'\"{wrapper.resolve()}\"\n'
    )
    (output_directory / "EXTERNAL_LAUNCH_COMMAND.txt").write_text(
        command,
        encoding="utf-8",
        newline="\n",
    )
    lines = [
        f"{sha256(path)}  {path.relative_to(output_directory).as_posix()}"
        for path in packet_files(output_directory)
    ]
    (output_directory / "PACKET_SHA256SUMS.txt").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return {
        "schema_version": "1.0.0",
        "route_id": ROUTE_ID,
        "status": "prepared_no_model_execution",
        "packet_root": str(output_directory.resolve()),
        "packet_manifest_sha256": sha256(
            output_directory / "PACKET_SHA256SUMS.txt"
        ),
        "runtime_artifact_sha256": sha256(artifact),
        "runtime_source_head": artifact_manifest["source_head"],
        "runtime_source_dirty": artifact_manifest["source_dirty"],
        "real_model_process_starts": 0,
        "real_model_requests": 0,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-directory", required=True)
    parser.add_argument(
        "--router-repository",
        default=r"C:\Users\sizhe\Documents\model-tier-router",
    )
    parser.add_argument(
        "--qwen-repository",
        default=r"C:\Users\sizhe\Documents\qwen-redaction-standalone",
    )
    args = parser.parse_args(argv)
    value = build(
        Path(args.output_directory).resolve(),
        Path(args.router_repository).resolve(),
        Path(args.qwen_repository).resolve(),
    )
    sys.stdout.buffer.write(canonical(value))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())