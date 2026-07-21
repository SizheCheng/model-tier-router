from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any


DEFAULT_ROUTE_ID = "FINAL_REMAINING_QWEN_PRODUCT_LANE_EXECUTION_R1"
DEFAULT_SOURCE_LANE_ID = "qwen-docx-hidden-elements-r1"
DEFAULT_SOURCE_PACKET_RELATIVE = (
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


def verify_source_packet(root: Path) -> str:
    checksum_path = root / "PACKET_SHA256SUMS.txt"
    manifest_path = root / "EXECUTION_MANIFEST.json"
    if not checksum_path.is_file() or not manifest_path.is_file():
        raise RuntimeError("SOURCE_PACKET_INCOMPLETE")
    seen: set[str] = set()
    for raw_line in checksum_path.read_text(encoding="utf-8").splitlines():
        digest, separator, relative = raw_line.partition("  ")
        parts = PurePosixPath(relative).parts
        if (
            not separator
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or not relative
            or relative in seen
            or relative.startswith("/")
            or "\\" in relative
            or ":" in relative
            or ".." in parts
            or "results" in parts
        ):
            raise RuntimeError("SOURCE_PACKET_MANIFEST_INVALID")
        path = root.joinpath(*parts)
        if not path.is_file() or sha256(path) != digest:
            raise RuntimeError("SOURCE_PACKET_HASH_DRIFT")
        seen.add(relative)
    if "EXECUTION_MANIFEST.json" not in seen:
        raise RuntimeError("SOURCE_PACKET_MANIFEST_INVALID")
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
        and path.name != "PACKET_SHA256SUMS.txt"
        and "results" not in path.relative_to(root).parts
    }
    if actual != seen:
        raise RuntimeError("SOURCE_PACKET_FILE_SET_DRIFT")
    return sha256(checksum_path)


def build(
    output_directory: Path,
    router_repository: Path,
    source_repository: Path,
    *,
    source_packet: Path,
    source_lane_id: str,
    route_id: str,
    branch_prefix: str,
    historical_accounting: dict[str, Any],
    qualification_release_only: bool,
) -> dict[str, Any]:
    root = Path(__file__).resolve().parents[1]
    if (
        not route_id
        or any(
            character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
            for character in route_id
        )
        or not source_lane_id
        or any(character.isspace() for character in source_lane_id)
        or not isinstance(historical_accounting, dict)
        or any(not isinstance(key, str) or not key for key in historical_accounting)
        or not isinstance(qualification_release_only, bool)
    ):
        raise RuntimeError("PRODUCT_ROUTE_IDENTIFIER_INVALID")
    branch_check = subprocess.run(
        ["git", "check-ref-format", "--branch", f"{branch_prefix}-1"],
        capture_output=True,
        text=True,
        check=False,
    )
    if branch_check.returncode != 0:
        raise RuntimeError("PRODUCT_BRANCH_PREFIX_INVALID")
    source_packet_receipt = verify_source_packet(source_packet)
    if output_directory.exists() and any(output_directory.iterdir()):
        raise RuntimeError("FINAL_PACKET_OUTPUT_NOT_EMPTY")
    output_directory.mkdir(parents=True, exist_ok=True)

    source_manifest = json.loads(
        (source_packet / "EXECUTION_MANIFEST.json").read_text(encoding="utf-8")
    )
    router_state = repository_state(router_repository)
    source_state = repository_state(source_repository)
    if router_state["status"] or source_state["status"]:
        raise RuntimeError("SOURCE_REPOSITORY_DIRTY")
    source_binding = next(
        item
        for item in source_manifest["lanes"]
        if item["lane_id"] == source_lane_id
    )
    lane_id = source_binding["lane_id"]
    frozen = output_directory / "frozen"
    frozen.mkdir()
    task_name = "task_lane_1.json"
    decision_name = "decision_lane_1.json"
    task_source = source_packet / source_binding["task_snapshot"]
    decision_source = source_packet / source_binding["decision_snapshot"]
    shutil.copyfile(task_source, frozen / task_name)
    shutil.copyfile(decision_source, frozen / decision_name)
    task_value = json.loads(
        (frozen / task_name).read_text(encoding="utf-8")
    )
    if source_state["head"] != source_binding["source_head"]:
        raise RuntimeError("SOURCE_HEAD_DRIFT")
    lanes = [{
        "lane_id": lane_id,
        "ordinal": 1,
        "successor_ordinal": 1,
        "prior_r5_ordinal_1_permanently_consumed": True,
        "source_repository": source_state["path"],
        "repository_id": task_value["repository"],
        "source_branch": source_state["branch"],
        "branch_prefix": branch_prefix,
        "source_head": source_state["head"],
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
            "product-lane",
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
    artifact = output_directory / "mtr-dogfood-product-lane.pyz"
    wrapper = output_directory / "RUN_PRODUCT_LANE.ps1"
    manifest = {
        "schema_version": "1.0.0",
        "route_id": route_id,
        "campaign_id": route_id,
        "execution_order": [item["lane_id"] for item in lanes],
        "maximum_new_starts": 1,
        "no_retry": True,
        "stop_on_first_failure": True,
        "qualification_release_only": qualification_release_only,
        "pre_reservation_failure_starts_consumed": 0,
        "reserved_failed_start_remains_consumed": True,
        "historical_accounting": historical_accounting,
        "router_source_head": router_state["head"],
        "model_mapping": source_manifest["model_mapping"],
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
            "source_packet_manifest_sha256": source_packet_receipt,
            "source_packet": str(source_packet),
            "source_campaign_reused": False,
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
        "route_id": route_id,
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
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-directory", required=True)
    parser.add_argument(
        "--router-repository",
        default=r"C:\Users\sizhe\Documents\model-tier-router",
    )
    parser.add_argument(
        "--source-repository", "--qwen-repository",
        dest="source_repository",
        default=r"C:\Users\sizhe\Documents\qwen-redaction-standalone",
    )
    parser.add_argument(
        "--source-packet", default=str(root / DEFAULT_SOURCE_PACKET_RELATIVE)
    )
    parser.add_argument("--source-lane-id", default=DEFAULT_SOURCE_LANE_ID)
    parser.add_argument("--route-id", default=DEFAULT_ROUTE_ID)
    parser.add_argument("--branch-prefix", default="mtr-product")
    parser.add_argument(
        "--historical-accounting-json", default="{}"
    )
    parser.add_argument("--qualification-release-only", action="store_true")
    args = parser.parse_args(argv)
    historical_accounting = json.loads(args.historical_accounting_json)
    if not isinstance(historical_accounting, dict):
        raise RuntimeError("HISTORICAL_ACCOUNTING_INVALID")
    value = build(
        Path(args.output_directory).resolve(),
        Path(args.router_repository).resolve(),
        Path(args.source_repository).resolve(),
        source_packet=Path(args.source_packet).resolve(),
        source_lane_id=args.source_lane_id,
        route_id=args.route_id,
        branch_prefix=args.branch_prefix,
        historical_accounting=historical_accounting,
        qualification_release_only=args.qualification_release_only,
    )
    sys.stdout.buffer.write(canonical(value))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())