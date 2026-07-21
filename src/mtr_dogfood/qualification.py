from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path, PurePosixPath
from typing import Any

from .config import canonical_json_bytes, load_json
from .external_runner import (
    BOUNDED_WRITE_COMMAND_RE,
    BOUNDED_WRITE_POLICY_FILENAME,
    BOUNDED_WRITE_RECEIPT_DIRECTORY,
    _child_prompt,
    _exact_bounded_write_paths,
    _scan_child_commands,
    _target_aliases,
    _task_payload,
    _task_still_useful,
)
from .host_materialization import (
    alias_map as host_alias_map,
    lane_contract as host_lane_contract,
    load_lane_policy,
)
from .r2_contract import validate_child_transport, validate_launch_payloads
from .router_adapter import assess_live, verify_decision
from .writable_smoke import (
    build_external_codex_command,
    validate_external_command_shape,
)


QUALIFICATION_ID = "MODEL_TIER_ROUTER_DOGFOOD_ARTIFACT_QUALIFICATION_R1"
R5K_ROUTE_ID = (
    "MODEL_TIER_ROUTER_DOGFOOD_R5K_TWO_PRODUCT_LANE_SUCCESSOR_CAMPAIGN_3_PACKET_R1"
)
LANE_ORDER = (
    "mtr-docs-private-executor-r1",
    "qwen-docx-hidden-elements-r1",
)
ASSETS = {
    "authority-receipt.schema.json": "schemas/authority-receipt.schema.json",
    "bounded-writer-receipt.schema.json": "schemas/bounded-writer-receipt.schema.json",
    "bounded-writer.py": "src/mtr_dogfood/bounded_writer.py",
    "host-materialization-lanes.json": "config/host-materialization-lanes.json",
    "proposed-files-result.schema.json": "schemas/proposed-files-result.schema.json",
    "task.schema.json": "schemas/task.schema.json",
}


class QualificationError(RuntimeError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(canonical_json_bytes(value))
    os.replace(temporary, path)


def _resource_bytes(name: str) -> bytes:
    packaged = resources.files("mtr_dogfood").joinpath(
        "_qualification_assets", *PurePosixPath(name).parts
    )
    try:
        return packaged.read_bytes()
    except (FileNotFoundError, NotADirectoryError):
        root = Path(__file__).resolve().parents[2]
        return (root / ASSETS[name]).read_bytes()


def self_test() -> dict[str, Any]:
    assets = {
        name: {"bytes": len(raw), "sha256": _sha256(raw)}
        for name in sorted(ASSETS)
        for raw in [_resource_bytes(name)]
    }
    return {
        "schema_version": "1.0.0",
        "qualification_id": QUALIFICATION_ID,
        "status": "passed",
        "assets": assets,
        "real_model_process_starts": 0,
        "real_model_requests": 0,
    }


def _packet_files(root: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if (
            not path.is_file()
            or path.name == "PACKET_SHA256SUMS.txt"
            or "results" in path.relative_to(root).parts
            or "__pycache__" in path.relative_to(root).parts
        ):
            continue
        values[path.relative_to(root).as_posix()] = _sha256(path.read_bytes())
    return values


def verify_packet(root: str | Path) -> dict[str, Any]:
    packet = Path(root).resolve()
    manifest_path = packet / "PACKET_SHA256SUMS.txt"
    if not manifest_path.is_file():
        raise QualificationError("PACKET_MANIFEST_MISSING")
    expected: dict[str, str] = {}
    for line in manifest_path.read_text(encoding="utf-8").splitlines():
        digest, separator, relative = line.partition("  ")
        if (
            separator != "  "
            or len(digest) != 64
            or relative in expected
            or "\\" in relative
        ):
            raise QualificationError("PACKET_MANIFEST_INVALID")
        expected[relative] = digest
    actual = _packet_files(packet)
    if actual != expected:
        raise QualificationError("PACKET_HASH_DRIFT")
    return {
        "status": "passed",
        "file_count": len(actual),
        "manifest_sha256": _sha256(manifest_path.read_bytes()),
    }


def _run(
    command: list[str],
    *,
    cwd: Path | None = None,
    input_bytes: bytes | None = None,
    timeout: int = 120,
) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
        input=input_bytes,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        message = completed.stderr.decode("utf-8", "replace")[:1000]
        raise QualificationError(f"COMMAND_FAILED: {message}")
    return completed


def _repository_state(repository: Path) -> dict[str, Any]:
    def git(*arguments: str) -> str:
        return _run(
            ["git", "-C", str(repository), *arguments], timeout=60
        ).stdout.decode("utf-8", "replace").strip()

    return {
        "path": str(repository.resolve()),
        "head": git("rev-parse", "HEAD"),
        "branch": git("branch", "--show-current"),
        "status": git("status", "--porcelain=v2", "--untracked-files=all").splitlines(),
    }


def _archive(repository: Path, head: str) -> bytes:
    return _run(
        ["git", "-C", str(repository), "archive", "--format=tar", head],
        timeout=120,
    ).stdout


def _safe_extract(raw: bytes, target: Path) -> None:
    target.mkdir(parents=True, exist_ok=False)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        members = archive.getmembers()
        for member in members:
            path = PurePosixPath(member.name)
            if (
                path.is_absolute()
                or ".." in path.parts
                or member.issym()
                or member.islnk()
            ):
                raise QualificationError("SOURCE_ARCHIVE_UNSAFE")
        archive.extractall(target, members=members, filter="data")


def _initialize_disposable_repository(workspace: Path) -> str:
    _run(["git", "init", "-q"], cwd=workspace)
    _run(["git", "config", "user.name", "Qualification Fixture"], cwd=workspace)
    _run(
        ["git", "config", "user.email", "qualification-fixture.invalid"],
        cwd=workspace,
    )
    _run(["git", "config", "core.longpaths", "true"], cwd=workspace)
    _run(["git", "add", "--all"], cwd=workspace)
    _run(["git", "commit", "-q", "-m", "qualification baseline"], cwd=workspace)
    return _run(["git", "rev-parse", "HEAD"], cwd=workspace).stdout.decode().strip()


def _lane_assets(workspace: Path) -> dict[str, Path]:
    metadata = workspace / ".mtr-dogfood-r4"
    metadata.mkdir()
    paths = {
        "output_schema": metadata / "proposed-files-result.schema.json",
        "lane_policy": metadata / "host-materialization-lanes.json",
        "writer": metadata / "bounded-writer.py",
        "write_policy": metadata / BOUNDED_WRITE_POLICY_FILENAME,
        "final_output": metadata / "final-result.json",
        "events": metadata / "qualification-events.jsonl",
    }
    paths["output_schema"].write_bytes(
        _resource_bytes("proposed-files-result.schema.json")
    )
    paths["lane_policy"].write_bytes(
        _resource_bytes("host-materialization-lanes.json")
    )
    paths["writer"].write_bytes(_resource_bytes("bounded-writer.py"))
    paths["events"].write_bytes(b"")
    return paths


def _qualify_lane(
    packet_root: Path,
    manifest: dict[str, Any],
    binding: dict[str, Any],
    repositories: dict[str, Path],
    router_repository: Path,
    workspace_parent: Path,
) -> dict[str, Any]:
    lane_id = binding.get("lane_id")
    if lane_id not in LANE_ORDER:
        raise QualificationError("UNAUTHORIZED_QUALIFICATION_LANE")
    source = repositories[lane_id]
    if Path(str(binding.get("source_repository", ""))).resolve() != source:
        raise QualificationError("SOURCE_REPOSITORY_BINDING_DRIFT")
    if Path(str(binding.get("router_repository", ""))).resolve() != router_repository:
        raise QualificationError("ROUTER_REPOSITORY_BINDING_DRIFT")
    before = _repository_state(source)
    if before["head"] != binding.get("source_head") or before["status"]:
        raise QualificationError("SOURCE_REPOSITORY_BASELINE_DRIFT")

    task_path = packet_root / str(binding["task_snapshot"])
    decision_path = packet_root / str(binding["decision_snapshot"])
    if _sha256(task_path.read_bytes()) != binding.get("task_sha256"):
        raise QualificationError("TASK_SNAPSHOT_HASH_DRIFT")
    if _sha256(decision_path.read_bytes()) != binding.get("decision_sha256"):
        raise QualificationError("DECISION_SNAPSHOT_HASH_DRIFT")
    task = load_json(task_path)
    expected = load_json(decision_path)
    if task.get("case_id") != lane_id:
        raise QualificationError("TASK_LANE_BINDING_INVALID")
    _task_still_useful(task, source)

    known_profiles = set(manifest["model_mapping"])
    actual = assess_live(
        router_repository,
        binding["routing_input"],
        known_profiles,
    )
    decision = verify_decision(actual, expected, known_profiles)
    profile = decision.get("selected_profile")
    mapping = manifest["model_mapping"].get(profile, {})
    if (
        profile != binding.get("selected_profile")
        or mapping.get("model") != binding.get("selected_model")
        or mapping.get("reasoning_effort") != binding.get("reasoning_effort")
    ):
        raise QualificationError("MODEL_MAPPING_DRIFT")

    workspace_parent.mkdir(parents=True, exist_ok=True)
    lane_prefix = "mtrq-1-" if lane_id == LANE_ORDER[0] else "mtrq-2-"
    with tempfile.TemporaryDirectory(
        prefix=lane_prefix, dir=workspace_parent
    ) as temporary:
        workspace = Path(temporary) / "workspace"
        _safe_extract(_archive(source, before["head"]), workspace)
        disposable_head = _initialize_disposable_repository(workspace)
        assets = _lane_assets(workspace)
        lane_policy = load_lane_policy(assets["lane_policy"])
        lane = host_lane_contract(lane_policy, lane_id)
        allowed_paths = _exact_bounded_write_paths(task["changed_path_patterns"])
        aliases = _target_aliases(allowed_paths)
        if aliases != host_alias_map(lane):
            raise QualificationError("HOST_MATERIALIZATION_LANE_POLICY_MISMATCH")

        write_policy = {
            "schema_version": "2.0.0",
            "workspace": str(workspace.resolve(strict=True)),
            "target_aliases": aliases,
            "max_content_bytes": max(
                item["maximum_content_bytes"] for item in lane["aliases"]
            ),
        }
        assets["write_policy"].write_bytes(canonical_json_bytes(write_policy))
        authority = {
            "schema_version": "1.0.0",
            "contract_id": QUALIFICATION_ID,
            "case_id": lane_id,
            "target_repository": str(source),
            "baseline_head": before["head"],
            "allowed_worktree": str(workspace),
            "allowed_task": task["task_text"],
            "allowed_validation": [
                item["name"] for item in task["validator_plan"]["commands"]
            ],
            "allowed_commit_behavior": "qualification only; no execution or commit",
            "external_push_authorized": False,
            "known_external_sessions_declared_active": True,
            "execution_authority_source": (
                "artifact qualification only; campaign not started"
            ),
            "router_execution_authorized": False,
            "router_authorized_write_scope": [],
            "worktree_local_schema_path": str(assets["output_schema"]),
            "child_writable_roots": [],
        }
        output_schema = json.loads(
            assets["output_schema"].read_text(encoding="utf-8")
        )
        validate_launch_payloads(
            _task_payload(task),
            json.loads(_resource_bytes("task.schema.json").decode("utf-8")),
            authority,
            json.loads(
                _resource_bytes("authority-receipt.schema.json").decode("utf-8")
            ),
            decision,
            output_schema,
            known_profiles,
        )
        command = build_external_codex_command(
            "codex.exe",
            workspace,
            mapping["model"],
            mapping["reasoning_effort"],
            assets["output_schema"],
            assets["final_output"],
        )
        validate_external_command_shape(command, workspace)
        prompt = _child_prompt(task, workspace)
        forbidden_paths = [packet_root, *repositories.values()]
        validate_child_transport(
            workspace, command, prompt, forbidden_paths
        )
        scan = _scan_child_commands(
            assets["events"],
            forbidden_paths,
            worktree=workspace,
            target_aliases=aliases,
            verified_writer_receipts=[],
            model_read_only=True,
        )
        if any(
            bool(scan[key])
            for key in (
                "forbidden_action_detected",
                "external_path_access_detected",
                "credential_access_detected",
                "remote_operation_attempted",
                "unparseable_command_detected",
                "bounded_write_security_violation_detected",
                "model_direct_write_attempt_detected",
                "model_file_change_attempt_detected",
            )
        ):
            raise QualificationError("SCANNER_INITIALIZATION_FAILED")
        if (
            not assets["writer"].is_file()
            or not assets["write_policy"].is_file()
            or (workspace / ".mtr-dogfood-r4" / BOUNDED_WRITE_RECEIPT_DIRECTORY).exists()
            or not BOUNDED_WRITE_COMMAND_RE.pattern
        ):
            raise QualificationError("BOUNDED_WRITE_TRANSPORT_PRESTART_MISMATCH")

        fake_backend_receipt = {
            "status": "START_RESERVATION_REQUESTED",
            "fake_backend": True,
            "child_process_started": False,
            "model_request_sent": False,
            "command_shape_verified": True,
        }

    after = _repository_state(source)
    if after != before:
        raise QualificationError("SOURCE_REPOSITORY_CHANGED_DURING_QUALIFICATION")
    return {
        "lane_id": lane_id,
        "status": "passed",
        "qualification_state": "START_RESERVATION_REQUESTED",
        "source_repository": before,
        "source_repository_unchanged": True,
        "task_sha256": binding["task_sha256"],
        "decision_sha256": binding["decision_sha256"],
        "decision_digest": decision["dogfood_decision_digest"],
        "selected_profile": profile,
        "selected_model": mapping["model"],
        "reasoning_effort": mapping["reasoning_effort"],
        "workspace_kind": "git_archive_independent_disposable_repository",
        "disposable_baseline": disposable_head,
        "workspace_cleaned": True,
        "scanner_initialized": True,
        "fake_backend": fake_backend_receipt,
        "real_model_process_starts": 0,
        "real_model_requests": 0,
    }


def qualify(
    packet_root: str | Path,
    router_repository: str | Path,
    qwen_repository: str | Path,
    workspace_parent: str | Path,
) -> dict[str, Any]:
    packet = Path(packet_root).resolve()
    packet_receipt = verify_packet(packet)
    manifest = load_json(packet / "EXECUTION_MANIFEST.json")
    lanes = manifest.get("lanes", [])
    if (
        manifest.get("route_id") != R5K_ROUTE_ID
        or manifest.get("execution_order") != list(LANE_ORDER)
        or [item.get("lane_id") for item in lanes] != list(LANE_ORDER)
        or len(lanes) != 2
    ):
        raise QualificationError("R5K_REGRESSION_INPUT_INVALID")
    repositories = {
        LANE_ORDER[0]: Path(router_repository).resolve(),
        LANE_ORDER[1]: Path(qwen_repository).resolve(),
    }
    router = Path(router_repository).resolve()
    outcomes: list[dict[str, Any]] = []
    for binding in lanes:
        try:
            outcomes.append(
                _qualify_lane(
                    packet,
                    manifest,
                    binding,
                    repositories,
                    router,
                    Path(workspace_parent).resolve(),
                )
            )
        except Exception as exc:
            outcomes.append(
                {
                    "lane_id": binding.get("lane_id"),
                    "status": "failed",
                    "qualification_state": "QUALIFICATION_FAILED",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "real_model_process_starts": 0,
                    "real_model_requests": 0,
                }
            )
            break
    passed = len(outcomes) == 2 and all(
        item.get("qualification_state") == "START_RESERVATION_REQUESTED"
        for item in outcomes
    )
    artifact = Path(sys.argv[0]).resolve()
    return {
        "schema_version": "1.0.0",
        "qualification_id": QUALIFICATION_ID,
        "status": "passed" if passed else "failed",
        "campaign_started": False,
        "historical_packet_mutated": False,
        "packet": packet_receipt,
        "packet_root": str(packet),
        "runtime_artifact": {
            "path": str(artifact) if artifact.is_file() else None,
            "sha256": _sha256(artifact.read_bytes()) if artifact.is_file() else None,
        },
        "outcomes": outcomes,
        "fake_backend_calls": sum(
            int(item.get("qualification_state") == "START_RESERVATION_REQUESTED")
            for item in outcomes
        ),
        "real_model_process_starts": 0,
        "real_model_requests": 0,
        "completed_at": _utc_now(),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mtr-dogfood-qualification")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--packet-root")
    parser.add_argument("--router-repository")
    parser.add_argument("--qwen-repository")
    parser.add_argument("--workspace-parent")
    parser.add_argument("--receipt")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.self_test:
            result = self_test()
        else:
            missing = [
                name
                for name in (
                    "packet_root",
                    "router_repository",
                    "qwen_repository",
                    "workspace_parent",
                    "receipt",
                )
                if not getattr(args, name)
            ]
            if missing:
                raise QualificationError(
                    f"MISSING_ARGUMENTS: {','.join(sorted(missing))}"
                )
            result = qualify(
                args.packet_root,
                args.router_repository,
                args.qwen_repository,
                args.workspace_parent,
            )
            _write_json(Path(args.receipt).resolve(), result)
    except Exception as exc:
        result = {
            "schema_version": "1.0.0",
            "qualification_id": QUALIFICATION_ID,
            "status": "failed",
            "error_type": type(exc).__name__,
            "error": str(exc),
            "campaign_started": False,
            "real_model_process_starts": 0,
            "real_model_requests": 0,
        }
    sys.stdout.buffer.write(canonical_json_bytes(result))
    return 0 if result.get("status") == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
