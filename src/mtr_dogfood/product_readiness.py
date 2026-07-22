from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from .config import canonical_json_bytes, load_json
from .qualification import verify_packet


class ProductReadinessError(RuntimeError):
    pass


def _packet_path(packet: Path, relative: Any) -> Path:
    if not isinstance(relative, str):
        raise ProductReadinessError("PACKET_REFERENCE_INVALID")
    parts = PurePosixPath(relative).parts
    if (
        not relative
        or relative.startswith("/")
        or "\\" in relative
        or ":" in relative
        or ".." in parts
        or "results" in parts
    ):
        raise ProductReadinessError("PACKET_REFERENCE_INVALID")
    target = packet.joinpath(*parts).resolve()
    try:
        target.relative_to(packet)
    except ValueError as exc:
        raise ProductReadinessError("PACKET_REFERENCE_INVALID") from exc
    return target


def _media_family(media_type: str) -> str:
    if "/" not in media_type:
        return media_type.casefold()
    major, minor = media_type.casefold().split("/", 1)
    if major == "text":
        return minor.removeprefix("x-").split("+", 1)[0]
    return major


def canary_record(packet_root: str | Path) -> dict[str, Any]:
    packet = Path(packet_root).resolve()
    packet_receipt = verify_packet(packet)
    manifest = load_json(packet / "FINAL_EXECUTION_MANIFEST.json")
    candidates = []
    results = packet / "results"
    if results.is_dir():
        for path in results.rglob("execution-closeout.json"):
            value = load_json(path)
            if value.get("qualification_only") is False:
                candidates.append((path, value))
    if len(candidates) != 1:
        raise ProductReadinessError("REAL_EXECUTION_CLOSEOUT_CARDINALITY_INVALID")
    closeout_path, closeout = candidates[0]
    campaign_state_path = results / "campaign-state.json"
    if not campaign_state_path.is_file():
        raise ProductReadinessError("PACKET_CAMPAIGN_LATCH_MISSING")
    campaign_state = load_json(campaign_state_path)
    lanes = manifest.get("lanes", [])
    if len(lanes) != 1:
        raise ProductReadinessError("CANARY_MANIFEST_LANE_CARDINALITY_INVALID")
    lane = lanes[0]
    for snapshot_field, digest_field in (
        ("task_snapshot", "task_sha256"),
        ("decision_snapshot", "decision_sha256"),
        ("qualification_candidate_snapshot", "qualification_candidate_sha256"),
    ):
        frozen_path = _packet_path(packet, lane.get(snapshot_field))
        if hashlib.sha256(frozen_path.read_bytes()).hexdigest() != lane.get(
            digest_field
        ):
            raise ProductReadinessError("CANARY_FROZEN_INPUT_HASH_DRIFT")
    policy_binding = manifest.get("lane_policy", {})
    policy_path = _packet_path(packet, policy_binding.get("snapshot"))
    if hashlib.sha256(policy_path.read_bytes()).hexdigest() != policy_binding.get(
        "sha256"
    ):
        raise ProductReadinessError("CANARY_POLICY_HASH_DRIFT")
    policy = load_json(policy_path)
    policy_lanes = policy.get("lanes", [])
    if len(policy_lanes) != 1 or policy_lanes[0].get("lane_id") != lane.get(
        "lane_id"
    ):
        raise ProductReadinessError("CANARY_POLICY_BINDING_DRIFT")
    aliases = policy_lanes[0].get("aliases", [])
    expected_paths = {item.get("relative_path") for item in aliases}
    expected_aliases = {item.get("target_alias") for item in aliases}
    candidate = load_json(
        _packet_path(packet, lane["qualification_candidate_snapshot"])
    )
    proposed_files = candidate.get("proposed_files", [])
    proposed_aliases = {item.get("target_alias") for item in proposed_files}
    media_families = sorted(
        {
            _media_family(str(item.get("media_type", "")))
            for item in aliases
            if item.get("media_type")
        }
    )
    task = load_json(_packet_path(packet, lane["task_snapshot"]))
    release = manifest.get("runtime_release", {})
    artifact = packet / "mtr-dogfood-product-lane.pyz"
    if (
        manifest.get("qualification_release_only") is not False
        or release.get("source_dirty") is not False
        or release.get("source_materialization") != "git_object_database_head"
        or not artifact.is_file()
        or hashlib.sha256(artifact.read_bytes()).hexdigest()
        != release.get("artifact_sha256")
    ):
        raise ProductReadinessError("CANARY_RUNTIME_RELEASE_INVALID")
    historical = manifest.get("historical_input", {})
    contract_path = _packet_path(
        packet, historical.get("product_contract_snapshot")
    )
    contract = load_json(contract_path)
    if (
        historical.get("input_mode") != "declarative_product_contract_v2"
        or hashlib.sha256(contract_path.read_bytes()).hexdigest()
        != historical.get("product_contract_sha256")
        or contract.get("schema_version") != "2.0.0"
        or contract.get("qualification_release_only") is not False
        or contract.get("route_id") != manifest.get("route_id")
        or contract.get("repository_id") != lane.get("repository_id")
    ):
        raise ProductReadinessError("CANARY_PRODUCT_CONTRACT_BINDING_DRIFT")
    if (
        not expected_paths
        or None in expected_paths
        or None in expected_aliases
        or len(aliases) != len(expected_aliases)
        or len(proposed_files) != len(proposed_aliases)
        or proposed_aliases != expected_aliases
        or set(task.get("changed_path_patterns", [])) != expected_paths
        or len(task.get("changed_path_patterns", [])) != len(expected_paths)
    ):
        raise ProductReadinessError("CANARY_TARGET_BINDING_DRIFT")
    accounting = closeout.get("process_accounting", {})
    outcomes = closeout.get("outcomes", [])
    outcome = outcomes[0] if len(outcomes) == 1 else {}
    validation = outcome.get("validation", {})
    validator_results = validation.get("validator_results", [])
    planned_validators = task.get("validator_plan", {}).get("commands", [])
    planned_identities = [
        (item.get("name"), item.get("layer")) for item in planned_validators
    ]
    observed_identities = [
        (item.get("name"), item.get("layer")) for item in validator_results
    ]
    preflight = closeout.get("pre_reservation_qualification", {})
    accepted = bool(
        closeout.get("status") == "passed"
        and closeout.get("route_id") == manifest.get("route_id")
        and closeout.get("campaign_started") is True
        and closeout.get("starts_consumed") == 1
        and closeout.get("maximum_new_starts") == 1
        and closeout.get("no_retry") is True
        and closeout.get("stop_on_first_failure") is True
        and closeout.get("source_repositories_unchanged") is True
        and closeout.get("packet", {}).get("manifest_sha256")
        == packet_receipt.get("manifest_sha256")
        and closeout.get("runtime_artifact", {}).get("sha256")
        == manifest.get("runtime_release", {}).get("artifact_sha256")
        and len(outcomes) == 1
        and outcome.get("lane_id") == lane.get("lane_id")
        and outcome.get("accepted") is True
        and validation.get("automated_acceptance") is True
        and validation.get("validator_side_effect_free") is True
        and set(outcome.get("changed_paths", [])) == expected_paths
        and planned_validators
        and validation.get("required_validator_count") == len(planned_validators)
        and planned_identities == observed_identities
        and validator_results
        and all(item.get("passed") is True for item in validator_results)
        and accounting.get("os_child_process_started") == 1
        and accounting.get("model_execution_observed") == 1
        and accounting.get("model_execution_completed") == 1
        and accounting.get("final_output_validated") == 1
        and accounting.get("validator_completed") == len(validator_results)
        and preflight.get("status") == "passed"
        and preflight.get("qualification_state")
        == "POST_MATERIALIZATION_VALIDATED"
        and preflight.get("model_process_starts") == 0
        and preflight.get("model_requests") == 0
        and campaign_state.get("campaign_id") == manifest.get("campaign_id")
        and campaign_state.get("lane_id") == lane.get("lane_id")
        and campaign_state.get("maximum_real_starts") == 1
        and campaign_state.get("starts_consumed") == 1
        and campaign_state.get("no_retry") is True
        and campaign_state.get("process_started") is True
        and campaign_state.get("reservation_state") == "TERMINAL"
        and campaign_state.get("accepted") is True
        and campaign_state.get("terminal_status") == "accepted"
        and task.get("risk") == "LOW_RISK"
    )
    return {
        "schema_version": "1.0.0",
        "route_id": manifest.get("route_id"),
        "repository_id": lane.get("repository_id"),
        "lane_id": lane.get("lane_id"),
        "risk": task.get("risk"),
        "media_families": media_families,
        "runtime_source_head": manifest.get("runtime_release", {}).get(
            "source_head"
        ),
        "runtime_artifact_sha256": manifest.get("runtime_release", {}).get(
            "artifact_sha256"
        ),
        "qualification_release_only": manifest.get("qualification_release_only"),
        "accepted": accepted,
        "packet_manifest_sha256": packet_receipt["manifest_sha256"],
        "closeout_path": str(closeout_path),
        "campaign_state_path": str(campaign_state_path),
    }


def evaluate_canaries(
    records: Iterable[dict[str, Any]],
    *,
    minimum_heterogeneous_products: int = 3,
) -> dict[str, Any]:
    values = list(records)
    repositories = {
        item.get("repository_id") for item in values if item.get("repository_id")
    }
    routes = {item.get("route_id") for item in values if item.get("route_id")}
    lanes = {item.get("lane_id") for item in values if item.get("lane_id")}
    media_families = {
        family for item in values for family in item.get("media_families", [])
    }
    runtime_heads = {
        item.get("runtime_source_head")
        for item in values
        if item.get("runtime_source_head")
    }
    artifact_hashes = {
        item.get("runtime_artifact_sha256")
        for item in values
        if item.get("runtime_artifact_sha256")
    }
    failures: list[str] = []
    oid = re.compile(r"[0-9a-f]{40}")
    digest = re.compile(r"[0-9a-f]{64}")
    if any(
        not isinstance(item.get("route_id"), str)
        or not item.get("route_id")
        or not isinstance(item.get("repository_id"), str)
        or not item.get("repository_id")
        or not isinstance(item.get("lane_id"), str)
        or not item.get("lane_id")
        or item.get("risk") != "LOW_RISK"
        or oid.fullmatch(str(item.get("runtime_source_head", ""))) is None
        or digest.fullmatch(str(item.get("runtime_artifact_sha256", ""))) is None
        or digest.fullmatch(str(item.get("packet_manifest_sha256", ""))) is None
        or not item.get("media_families")
        for item in values
    ):
        failures.append("CANARY_RECORD_INVALID")
    if len(values) < minimum_heterogeneous_products:
        failures.append("INSUFFICIENT_CANARY_COUNT")
    if len(repositories) < minimum_heterogeneous_products:
        failures.append("INSUFFICIENT_REPOSITORY_DIVERSITY")
    if len(routes) != len(values) or len(lanes) != len(values):
        failures.append("CANARY_IDENTITY_REUSED")
    if len(media_families) < 2:
        failures.append("INSUFFICIENT_MEDIA_DIVERSITY")
    if len(runtime_heads) != 1 or len(artifact_hashes) != 1:
        failures.append("COMPONENT_RELEASE_DRIFT")
    if any(item.get("qualification_release_only") is not False for item in values):
        failures.append("QUALIFICATION_RELEASE_PRESENT")
    if any(item.get("risk") != "LOW_RISK" for item in values):
        failures.append("CANARY_RISK_NOT_LOW")
    if any(item.get("accepted") is not True for item in values):
        failures.append("CANARY_NOT_ACCEPTED")
    return {
        "schema_version": "1.0.0",
        "status": "passed" if not failures else "blocked",
        "eligible_for_default_product_development": not failures,
        "minimum_heterogeneous_products": minimum_heterogeneous_products,
        "canary_count": len(values),
        "distinct_repository_count": len(repositories),
        "distinct_media_family_count": len(media_families),
        "runtime_release_count": len(runtime_heads),
        "artifact_identity_count": len(artifact_hashes),
        "failure_codes": failures,
        "canaries": values,
        "real_model_process_starts_created_by_evaluator": 0,
        "real_model_requests_created_by_evaluator": 0,
    }


def evaluate_packets(packet_roots: Iterable[str | Path]) -> dict[str, Any]:
    return evaluate_canaries(canary_record(path) for path in packet_roots)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="evaluate-product-readiness")
    parser.add_argument("--packet-root", action="append", required=True)
    parser.add_argument("--output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = evaluate_packets(args.packet_root)
    except Exception as exc:
        result = {
            "schema_version": "1.0.0",
            "status": "failed",
            "eligible_for_default_product_development": False,
            "error_type": type(exc).__name__,
            "error": str(exc),
            "real_model_process_starts_created_by_evaluator": 0,
            "real_model_requests_created_by_evaluator": 0,
        }
    raw = canonical_json_bytes(result)
    if args.output:
        Path(args.output).resolve().write_bytes(raw)
    sys.stdout.buffer.write(raw)
    return 0 if result.get("status") == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
