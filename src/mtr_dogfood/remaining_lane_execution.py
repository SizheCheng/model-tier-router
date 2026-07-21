from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from .codex_runner import resolve_codex_executable
from .config import canonical_json_bytes, is_contained, load_json, same_path
from .external_runner import _run_attempt, default_launcher
from .host_materialization import lane_contract as host_lane_contract, load_lane_policy
from .process_ancestry import verify_standalone_powershell, windows_process_provider
from .qualification import ASSETS, _resource_bytes, verify_packet
from .router_adapter import assess_live, verify_decision
from .runtime_contract import ProcessAccounting


COMPONENT_ID = "MTR_GENERIC_SINGLE_PRODUCT_EXECUTION"
class FinalExecutionError(RuntimeError):
    pass


class ReservationBoundaryReached(RuntimeError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _packet_file(packet: Path, relative: Any) -> Path:
    if not isinstance(relative, str):
        raise FinalExecutionError("FROZEN_INPUT_PATH_INVALID")
    parts = PurePosixPath(relative).parts
    if (
        not relative
        or relative.startswith("/")
        or "\\" in relative
        or ":" in relative
        or ".." in parts
        or "results" in parts
    ):
        raise FinalExecutionError("FROZEN_INPUT_PATH_INVALID")
    target = packet.joinpath(*parts).resolve()
    if not is_contained(packet, target):
        raise FinalExecutionError("FROZEN_INPUT_PATH_INVALID")
    return target


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(canonical_json_bytes(value))
    os.replace(temporary, path)


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        raise FinalExecutionError(
            completed.stderr.strip() or completed.stdout.strip() or "GIT_FAILURE"
        )
    return completed.stdout.strip()


def _repository_state(repository: Path) -> dict[str, Any]:
    return {
        "path": str(repository.resolve()),
        "head": _git(repository, "rev-parse", "HEAD"),
        "branch": _git(repository, "branch", "--show-current"),
        "status": _git(
            repository, "status", "--porcelain=v2", "--untracked-files=all"
        ).splitlines(),
    }


def _clone_repository(source: Path, target: Path, head: str) -> Path:
    completed = subprocess.run(
        [
            "git",
            "clone",
            "--quiet",
            "--no-hardlinks",
            "--no-checkout",
            str(source),
            str(target),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        raise FinalExecutionError(
            completed.stderr.strip() or "QUALIFICATION_CLONE_FAILED"
        )
    _git(target, "checkout", "--quiet", "--detach", head)
    _git(target, "remote", "remove", "origin")
    _git(target, "config", "core.longpaths", "true")
    if _git(target, "rev-parse", "HEAD") != head:
        raise FinalExecutionError("QUALIFICATION_CLONE_HEAD_DRIFT")
    return target


class PacketCampaignLatch:
    """Persist one real start reservation across every invocation of a packet."""

    def __init__(self, path: Path, *, campaign_id: str) -> None:
        self.path = path
        self.campaign_id = campaign_id

    def reserve(self, lane_id: str) -> dict[str, Any]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "schema_version": "1.0.0",
            "campaign_id": self.campaign_id,
            "lane_id": lane_id,
            "maximum_real_starts": 1,
            "starts_consumed": 1,
            "no_retry": True,
            "reservation_state": "START_RESERVED",
            "reserved_at": _utc_now(),
            "process_started": False,
            "accepted": None,
            "terminal_status": "",
        }
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        try:
            descriptor = os.open(self.path, flags, 0o600)
        except FileExistsError as exc:
            raise FinalExecutionError("PACKET_CAMPAIGN_ALREADY_CONSUMED") from exc
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(canonical_json_bytes(record))
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            self.path.unlink(missing_ok=True)
            raise
        return record

    def finish(
        self,
        lane_id: str,
        *,
        process_started: bool,
        accepted: bool,
        terminal_status: str,
    ) -> None:
        if not self.path.is_file():
            raise FinalExecutionError("PACKET_CAMPAIGN_LATCH_MISSING")
        value = load_json(self.path)
        if (
            value.get("campaign_id") != self.campaign_id
            or value.get("lane_id") != lane_id
            or value.get("starts_consumed") != 1
            or value.get("reservation_state") != "START_RESERVED"
        ):
            raise FinalExecutionError("PACKET_CAMPAIGN_LATCH_INVALID")
        value.update(
            {
                "process_started": bool(process_started),
                "accepted": bool(accepted),
                "terminal_status": terminal_status,
                "reservation_state": "TERMINAL",
                "completed_at": _utc_now(),
            }
        )
        _write_json(self.path, value)


class CampaignLedger:
    def __init__(
        self,
        path: Path,
        *,
        qualification_only: bool,
        campaign_id: str = COMPONENT_ID,
        ceiling: int = 1,
        historical_accounting: dict[str, Any] | None = None,
    ) -> None:
        self.path = path
        self.qualification_only = qualification_only
        self.campaign_id = campaign_id
        self.ceiling = ceiling
        self.historical_accounting = dict(historical_accounting or {})
        self.records: list[dict[str, Any]] = []
        self._write()

    @property
    def starts_consumed(self) -> int:
        return sum(
            int(not item["qualification_only"])
            for item in self.records
        )

    def reserve(self, lane_id: str) -> dict[str, Any]:
        if any(item["lane_id"] == lane_id for item in self.records):
            raise FinalExecutionError("DUPLICATE_LANE_RESERVATION")
        if len(self.records) >= self.ceiling:
            raise FinalExecutionError("START_RESERVATION_LIMIT_REACHED")
        record = {
            "lane_id": lane_id,
            "successor_ordinal": len(self.records) + 1,
            "historical_accounting": self.historical_accounting,
            "qualification_only": self.qualification_only,
            "reservation_state": (
                "SIMULATED_START_RESERVATION_REQUESTED"
                if self.qualification_only
                else "START_RESERVED"
            ),
            "reserved_at": _utc_now(),
            "process_started": False,
            "accepted": None,
            "terminal_status": "",
        }
        self.records.append(record)
        self._write()
        return record

    def finish(
        self,
        lane_id: str,
        *,
        process_started: bool,
        accepted: bool,
        terminal_status: str,
    ) -> None:
        record = next(
            (item for item in self.records if item["lane_id"] == lane_id),
            None,
        )
        if record is None:
            raise FinalExecutionError("RESERVATION_RECORD_MISSING")
        record.update(
            {
                "process_started": bool(process_started),
                "accepted": bool(accepted),
                "terminal_status": terminal_status,
                "completed_at": _utc_now(),
            }
        )
        self._write()

    def _write(self) -> None:
        _write_json(
            self.path,
            {
                "schema_version": "1.0.0",
                "campaign_id": self.campaign_id,
                "ceiling": self.ceiling,
                "no_retry": True,
                "stop_on_first_failure": True,
                "historical_accounting": self.historical_accounting,
                "qualification_only": self.qualification_only,
                "starts_consumed": self.starts_consumed,
                "records": self.records,
            },
        )


def _release_metadata() -> dict[str, Any]:
    return json.loads(
        resources.files("mtr_dogfood")
        .joinpath("_release_metadata.json")
        .read_text(encoding="utf-8")
    )


def _materialize_support(root: Path, packet: Path, manifest: dict[str, Any]) -> None:
    for name, relative in ASSETS.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(_resource_bytes(name))
    policy_binding = manifest["lane_policy"]
    policy_source = packet / policy_binding["snapshot"]
    policy_target = root / "config" / "host-materialization-lanes.json"
    policy_target.write_bytes(policy_source.read_bytes())


def self_test() -> dict[str, Any]:
    assets = {
        name: {
            "bytes": len(_resource_bytes(name)),
            "sha256": hashlib.sha256(_resource_bytes(name)).hexdigest(),
        }
        for name in sorted(ASSETS)
    }
    return {
        "schema_version": "1.0.0",
        "component_id": COMPONENT_ID,
        "status": "passed",
        "no_retry": True,
        "stop_on_first_failure": True,
        "maximum_real_starts": 1,
        "packet_lifetime_maximum_real_starts": 1,
        "real_model_process_starts": 0,
        "real_model_requests": 0,
        "assets": assets,
    }


def _validate_manifest(
    packet: Path,
    manifest: dict[str, Any],
    artifact: Path,
    router_repository: Path,
    source_repository: Path,
    *,
    qualification_only: bool,
) -> None:
    lanes = manifest.get("lanes", [])
    route_id = manifest.get("route_id")
    lane_ids = [item.get("lane_id") for item in lanes if isinstance(item, dict)]
    if (
        manifest.get("schema_version") != "1.0.0"
        or not isinstance(route_id, str)
        or not route_id
        or manifest.get("campaign_id") != route_id
        or manifest.get("maximum_new_starts") != 1
        or manifest.get("no_retry") is not True
        or manifest.get("stop_on_first_failure") is not True
        or not isinstance(
            manifest.get("qualification_release_only", False), bool
        )
        or len(lanes) != 1
        or len(lane_ids) != 1
        or not isinstance(lane_ids[0], str)
        or not lane_ids[0]
        or manifest.get("execution_order") != lane_ids
        or not isinstance(lanes[0].get("repository_id"), str)
        or not lanes[0].get("repository_id")
        or not isinstance(lanes[0].get("source_branch"), str)
        or not lanes[0].get("source_branch")
        or not isinstance(lanes[0].get("branch_prefix"), str)
        or not lanes[0].get("branch_prefix")
        or not isinstance(manifest.get("lane_policy"), dict)
    ):
        raise FinalExecutionError("FINAL_EXECUTION_MANIFEST_INVALID")
    if not qualification_only and manifest.get("qualification_release_only", False):
        raise FinalExecutionError(
            "QUALIFICATION_RELEASE_REAL_EXECUTION_FORBIDDEN"
        )
    release = manifest.get("runtime_release", {})
    embedded_release = _release_metadata()
    if (
        release.get("source_head") != embedded_release.get("source_head")
        or release.get("source_dirty") is not embedded_release.get("source_dirty")
        or release.get("artifact_sha256") != _sha256(artifact)
        or not same_path(release.get("artifact_path", ""), artifact)
        or embedded_release.get("entrypoint") not in {"remaining-lane", "product-lane"}
        or (not qualification_only and embedded_release.get("source_dirty") is not False)
    ):
        raise FinalExecutionError("FINAL_EXECUTION_ARTIFACT_BINDING_DRIFT")
    for lane in lanes:
        source = Path(str(lane.get("source_repository", ""))).resolve()
        router = Path(str(lane.get("router_repository", ""))).resolve()
        if source != source_repository:
            raise FinalExecutionError("SOURCE_REPOSITORY_BINDING_DRIFT")
        if router != router_repository:
            raise FinalExecutionError("ROUTER_REPOSITORY_BINDING_DRIFT")
        for field in ("task_snapshot", "decision_snapshot"):
            path = _packet_file(packet, lane[field])
            digest_field = field.replace("snapshot", "sha256")
            if not path.is_file() or _sha256(path) != lane.get(digest_field):
                raise FinalExecutionError("FROZEN_INPUT_HASH_DRIFT")
    policy_binding = manifest["lane_policy"]
    policy_path = _packet_file(packet, policy_binding.get("snapshot"))
    if (
        not policy_path.is_file()
        or _sha256(policy_path) != policy_binding.get("sha256")
    ):
        raise FinalExecutionError("FROZEN_LANE_POLICY_HASH_DRIFT")
    policy = load_lane_policy(policy_path)
    if len(policy["lanes"]) != 1 or policy["lanes"][0]["lane_id"] != lane_ids[0]:
        raise FinalExecutionError("FROZEN_LANE_POLICY_BINDING_DRIFT")
    host_lane_contract(policy, lane_ids[0])


def _run_lanes(
    *,
    packet: Path,
    manifest: dict[str, Any],
    actual_repositories: dict[str, Path],
    execution_repositories: dict[str, Path],
    workspace_parent: Path,
    result_root: Path,
    runner_pid: int,
    qualification_only: bool,
    launcher: Callable[..., dict[str, Any]],
) -> dict[str, Any]:
    _materialize_support(result_root, packet, manifest)
    binding = manifest["lanes"][0]
    lane_id = binding["lane_id"]
    repository_id = binding["repository_id"]
    ledger = CampaignLedger(
        result_root / "campaign-ledger.json",
        qualification_only=qualification_only,
        campaign_id=manifest["campaign_id"],
        ceiling=manifest["maximum_new_starts"],
        historical_accounting=manifest.get("historical_accounting", {}),
    )
    packet_latch = (
        None
        if qualification_only
        else PacketCampaignLatch(
            packet / "results" / "campaign-state.json",
            campaign_id=manifest["campaign_id"],
        )
    )
    budget = ProcessAccounting(maximum=manifest["maximum_new_starts"])
    outcomes: list[dict[str, Any]] = []
    contract = {
        "route_id": manifest["route_id"],
        "repositories": {
            "model-tier-router": {
                "path": str(execution_repositories["model-tier-router"]),
                "baseline_head": manifest["router_source_head"],
                "branch": "main",
            },
            repository_id: {
                "path": str(execution_repositories[repository_id]),
                "baseline_head": binding["source_head"],
                "branch": binding["source_branch"],
            },
        },
        "reporting": {
            "receipt_root": "receipts",
            "raw_root": "raw",
        },
        "paths": {
            "worktree_pool": str(workspace_parent / "worktree-pool"),
        },
        "model_mapping": manifest["model_mapping"],
        "denylist": [str(packet), *[str(path) for path in actual_repositories.values()]],
        "commit_identity": manifest["commit_identity"],
    }

    def ancestry_guard() -> dict[str, Any]:
        if qualification_only:
            return {
                "status": "passed",
                "classification": "QUALIFICATION_FAKE_ANCESTRY",
                "ordinary_powershell_ancestor_verified": False,
            }
        return verify_standalone_powershell(
            runner_pid,
            windows_process_provider,
        )

    known_profiles = set(manifest["model_mapping"])
    for binding in manifest["lanes"]:
        lane_id = binding["lane_id"]
        task_path = packet / binding["task_snapshot"]
        decision_path = packet / binding["decision_snapshot"]
        task_bytes = task_path.read_bytes()
        case = json.loads(task_bytes.decode("utf-8"))
        expected = load_json(decision_path)
        actual = assess_live(
            actual_repositories["model-tier-router"],
            binding["routing_input"],
            known_profiles,
        )
        decision = verify_decision(actual, expected, known_profiles)
        profile = decision["selected_profile"]
        descriptor = {
            "branch_prefix": binding["branch_prefix"],
            "automatic_fast_forward_merge": False,
        }
        reserved = False
        starts_before_lane = budget.os_child_process_started

        def reserved_launcher(**kwargs: Any) -> dict[str, Any]:
            nonlocal reserved
            if packet_latch is not None:
                packet_latch.reserve(lane_id)
            ledger.reserve(lane_id)
            reserved = True
            if qualification_only:
                raise ReservationBoundaryReached(lane_id)
            return launcher(**kwargs)

        try:
            outcome = _run_attempt(
                contract,
                copy.deepcopy(case),
                descriptor,
                task_bytes,
                decision,
                profile,
                1,
                0,
                budget,
                reserved_launcher,
                ancestry_guard,
                (lambda: "codex.exe")
                if qualification_only
                else resolve_codex_executable,
                result_root,
            )
        except ReservationBoundaryReached:
            ledger.finish(
                lane_id,
                process_started=False,
                accepted=True,
                terminal_status="START_RESERVATION_REQUESTED",
            )
            outcomes.append(
                {
                    "lane_id": lane_id,
                    "status": "passed",
                    "qualification_state": "START_RESERVATION_REQUESTED",
                    "real_model_process_starts": 0,
                    "real_model_requests": 0,
                }
            )
            continue
        except Exception as exc:
            if reserved:
                process_started = (
                    budget.os_child_process_started > starts_before_lane
                )
                ledger.finish(
                    lane_id,
                    process_started=process_started,
                    accepted=False,
                    terminal_status=type(exc).__name__,
                )
                if packet_latch is not None:
                    packet_latch.finish(
                        lane_id,
                        process_started=process_started,
                        accepted=False,
                        terminal_status=type(exc).__name__,
                    )
            outcomes.append(
                {
                    "lane_id": lane_id,
                    "status": "failed",
                    "failure": str(exc),
                    "failure_type": type(exc).__name__,
                    "reserved": reserved,
                    "process_started": (
                        budget.os_child_process_started > starts_before_lane
                    ),
                }
            )
            break

        process_started = bool(outcome.get("child_process_started"))
        accepted = bool(outcome.get("accepted"))
        terminal_status = str(outcome.get("failure_class") or "accepted")
        ledger.finish(
            lane_id,
            process_started=process_started,
            accepted=accepted,
            terminal_status=terminal_status,
        )
        if packet_latch is not None:
            packet_latch.finish(
                lane_id,
                process_started=process_started,
                accepted=accepted,
                terminal_status=terminal_status,
            )
        outcomes.append(outcome)
        if not outcome.get("accepted"):
            break

    qualification_passed = bool(
        qualification_only
        and len(outcomes) == 1
        and all(
            item.get("qualification_state") == "START_RESERVATION_REQUESTED"
            for item in outcomes
        )
    )
    execution_passed = bool(
        not qualification_only
        and len(outcomes) == 1
        and all(item.get("accepted") for item in outcomes)
    )
    return {
        "schema_version": "1.0.0",
        "route_id": manifest["route_id"],
        "status": "passed" if qualification_passed or execution_passed else "failed",
        "qualification_only": qualification_only,
        "campaign_started": ledger.starts_consumed > 0,
        "maximum_new_starts": manifest["maximum_new_starts"],
        "starts_consumed": ledger.starts_consumed,
        "no_retry": True,
        "stop_on_first_failure": True,
        "historical_accounting": manifest.get("historical_accounting", {}),
        "outcomes": outcomes,
        "process_accounting": budget.as_dict(),
        "completed_at": _utc_now(),
    }


def run(
    *,
    packet_root: str | Path,
    router_repository: str | Path,
    source_repository: str | Path,
    workspace_parent: str | Path,
    result_root: str | Path,
    runner_pid: int,
    qualification_only: bool,
    launcher: Callable[..., dict[str, Any]] = default_launcher,
) -> dict[str, Any]:
    packet = Path(packet_root).resolve()
    result = Path(result_root).resolve()
    results_parent = (packet / "results").resolve()
    if not is_contained(results_parent, result) or same_path(results_parent, result):
        raise FinalExecutionError("RESULT_ROOT_OUTSIDE_PACKET_RESULTS")
    if result.exists() and any(result.iterdir()):
        raise FinalExecutionError("RESULT_ROOT_NOT_EMPTY")
    result.mkdir(parents=True, exist_ok=True)
    packet_receipt = verify_packet(packet)
    manifest = load_json(packet / "FINAL_EXECUTION_MANIFEST.json")
    artifact = Path(sys.argv[0]).resolve()
    router = Path(router_repository).resolve()
    source = Path(source_repository).resolve()
    binding = manifest["lanes"][0]
    repository_id = binding["repository_id"]
    actual_repositories = {
        "model-tier-router": router,
        repository_id: source,
    }
    _validate_manifest(
        packet,
        manifest,
        artifact,
        router,
        source,
        qualification_only=qualification_only,
    )
    before = {
        lane_id: _repository_state(path)
        for lane_id, path in actual_repositories.items()
    }
    if (
        before["model-tier-router"]["head"] != manifest["router_source_head"]
        or before["model-tier-router"]["status"]
    ):
        raise FinalExecutionError("ROUTER_REPOSITORY_BASELINE_DRIFT")
    state = before[repository_id]
    if state["head"] != binding["source_head"] or state["status"]:
        raise FinalExecutionError("SOURCE_REPOSITORY_BASELINE_DRIFT")

    workspace = Path(workspace_parent).resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    if qualification_only:
        with tempfile.TemporaryDirectory(
            prefix="final-remaining-qualification-",
            dir=workspace,
        ) as temporary:
            clone_root = Path(temporary)
            execution_repositories = {
                "model-tier-router": router,
                repository_id: _clone_repository(
                    source,
                    clone_root / "source-repository",
                    binding["source_head"],
                ),
            }
            closeout = _run_lanes(
                packet=packet,
                manifest=manifest,
                actual_repositories=actual_repositories,
                execution_repositories=execution_repositories,
                workspace_parent=clone_root / "workspaces",
                result_root=result,
                runner_pid=runner_pid,
                qualification_only=True,
                launcher=launcher,
            )
    else:
        closeout = _run_lanes(
            packet=packet,
            manifest=manifest,
            actual_repositories=actual_repositories,
            execution_repositories=actual_repositories,
            workspace_parent=workspace,
            result_root=result,
            runner_pid=runner_pid,
            qualification_only=False,
            launcher=launcher,
        )

    after = {
        lane_id: _repository_state(path)
        for lane_id, path in actual_repositories.items()
    }
    closeout.update(
        {
            "packet": packet_receipt,
            "runtime_artifact": {
                "path": str(artifact),
                "sha256": _sha256(artifact),
            },
            "source_repositories_unchanged": after == before,
        }
    )
    _write_json(result / "execution-closeout.json", closeout)
    return closeout


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mtr-dogfood-final-execution")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--qualification-only", action="store_true")
    parser.add_argument("--packet-root")
    parser.add_argument("--router-repository")
    parser.add_argument("--source-repository", "--qwen-repository", dest="source_repository")
    parser.add_argument("--workspace-parent")
    parser.add_argument("--result-root")
    parser.add_argument("--runner-pid", type=int, default=0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.self_test:
            value = self_test()
        else:
            required = (
                "packet_root",
                "router_repository",
                "source_repository",
                "workspace_parent",
                "result_root",
            )
            missing = [name for name in required if not getattr(args, name)]
            if missing:
                raise FinalExecutionError(
                    f"MISSING_ARGUMENTS: {','.join(sorted(missing))}"
                )
            if not args.qualification_only and args.runner_pid <= 0:
                raise FinalExecutionError("RUNNER_PID_REQUIRED")
            value = run(
                packet_root=args.packet_root,
                router_repository=args.router_repository,
                source_repository=args.source_repository,
                workspace_parent=args.workspace_parent,
                result_root=args.result_root,
                runner_pid=args.runner_pid,
                qualification_only=args.qualification_only,
            )
    except Exception as exc:
        value = {
            "schema_version": "1.0.0",
            "component_id": COMPONENT_ID,
            "status": "failed",
            "error_type": type(exc).__name__,
            "error": str(exc),
            "campaign_started": False,
            "real_model_process_starts": 0,
            "real_model_requests": 0,
        }
    sys.stdout.buffer.write(canonical_json_bytes(value))
    return 0 if value.get("status") == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())