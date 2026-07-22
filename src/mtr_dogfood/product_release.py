from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from .config import canonical_json_bytes, load_json
from .qualification import verify_packet


class ProductReleaseError(RuntimeError):
    pass


def _packet_path(packet: Path, relative: Any) -> Path:
    if not isinstance(relative, str):
        raise ProductReleaseError("PACKET_REFERENCE_INVALID")
    parts = PurePosixPath(relative).parts
    if (
        not relative
        or relative.startswith("/")
        or "\\" in relative
        or ":" in relative
        or ".." in parts
        or "results" in parts
    ):
        raise ProductReleaseError("PACKET_REFERENCE_INVALID")
    target = packet.joinpath(*parts).resolve()
    try:
        target.relative_to(packet)
    except ValueError as exc:
        raise ProductReleaseError("PACKET_REFERENCE_INVALID") from exc
    return target


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _media_family(media_type: str) -> str:
    if "/" not in media_type:
        return media_type.casefold()
    major, minor = media_type.casefold().split("/", 1)
    if major == "text":
        return minor.removeprefix("x-").split("+", 1)[0]
    return major


def _single_qualification_closeout(packet: Path) -> tuple[Path, dict[str, Any]]:
    results = packet / "results"
    closeouts: list[tuple[Path, dict[str, Any]]] = []
    if results.is_dir():
        for path in results.rglob("execution-closeout.json"):
            value = load_json(path)
            if value.get("qualification_only") is True:
                closeouts.append((path, value))
            else:
                raise ProductReleaseError("REAL_EXECUTION_EVIDENCE_PRESENT")
    if len(closeouts) != 1:
        raise ProductReleaseError("QUALIFICATION_CLOSEOUT_CARDINALITY_INVALID")
    return closeouts[0]


def qualification_record(packet_root: str | Path) -> dict[str, Any]:
    packet = Path(packet_root).resolve()
    packet_receipt = verify_packet(packet)
    manifest = load_json(packet / "FINAL_EXECUTION_MANIFEST.json")
    lanes = manifest.get("lanes", [])
    if (
        manifest.get("schema_version") != "1.0.0"
        or manifest.get("qualification_release_only") is not True
        or manifest.get("maximum_new_starts") != 1
        or manifest.get("no_retry") is not True
        or manifest.get("stop_on_first_failure") is not True
        or len(lanes) != 1
    ):
        raise ProductReleaseError("QUALIFICATION_MANIFEST_INVALID")
    if (packet / "results" / "campaign-state.json").exists():
        raise ProductReleaseError("QUALIFICATION_CAMPAIGN_LATCH_PRESENT")

    lane = lanes[0]
    route_id = manifest.get("route_id")
    lane_id = lane.get("lane_id")
    repository_id = lane.get("repository_id")
    if not all(
        isinstance(value, str) and value
        for value in (route_id, lane_id, repository_id)
    ):
        raise ProductReleaseError("QUALIFICATION_IDENTITY_INVALID")

    historical = manifest.get("historical_input", {})
    if historical.get("input_mode") != "declarative_product_contract_v2":
        raise ProductReleaseError("PRODUCT_CONTRACT_V2_REQUIRED")
    contract_path = _packet_path(
        packet, historical.get("product_contract_snapshot")
    )
    if _sha256(contract_path) != historical.get("product_contract_sha256"):
        raise ProductReleaseError("PRODUCT_CONTRACT_HASH_DRIFT")
    contract = load_json(contract_path)
    if (
        contract.get("schema_version") != "2.0.0"
        or contract.get("route_id") != route_id
        or contract.get("repository_id") != repository_id
        or contract.get("qualification_release_only") is not True
    ):
        raise ProductReleaseError("PRODUCT_CONTRACT_BINDING_DRIFT")

    task_path = _packet_path(packet, lane.get("task_snapshot"))
    if _sha256(task_path) != lane.get("task_sha256"):
        raise ProductReleaseError("QUALIFICATION_TASK_HASH_DRIFT")
    decision_path = _packet_path(packet, lane.get("decision_snapshot"))
    if _sha256(decision_path) != lane.get("decision_sha256"):
        raise ProductReleaseError("QUALIFICATION_DECISION_HASH_DRIFT")
    task = load_json(task_path)
    candidate_path = _packet_path(
        packet, lane.get("qualification_candidate_snapshot")
    )
    if _sha256(candidate_path) != lane.get("qualification_candidate_sha256"):
        raise ProductReleaseError("QUALIFICATION_CANDIDATE_HASH_DRIFT")
    candidate = load_json(candidate_path)
    policy_binding = manifest.get("lane_policy", {})
    policy_path = _packet_path(packet, policy_binding.get("snapshot"))
    if _sha256(policy_path) != policy_binding.get("sha256"):
        raise ProductReleaseError("QUALIFICATION_POLICY_HASH_DRIFT")
    policy = load_json(policy_path)
    policy_lanes = policy.get("lanes", [])
    if len(policy_lanes) != 1 or policy_lanes[0].get("lane_id") != lane_id:
        raise ProductReleaseError("QUALIFICATION_POLICY_BINDING_DRIFT")
    aliases = policy_lanes[0].get("aliases", [])
    expected_aliases = {item.get("target_alias") for item in aliases}
    expected_paths = {item.get("relative_path") for item in aliases}
    proposed_files = candidate.get("proposed_files", [])
    proposed_aliases = {item.get("target_alias") for item in proposed_files}
    if (
        len(aliases) != len(expected_aliases)
        or len(proposed_files) != len(proposed_aliases)
        or len(task.get("changed_path_patterns", [])) != len(expected_paths)
        or
        not expected_aliases
        or None in expected_aliases
        or None in expected_paths
        or proposed_aliases != expected_aliases
        or set(task.get("changed_path_patterns", [])) != expected_paths
    ):
        raise ProductReleaseError("QUALIFICATION_TARGET_BINDING_DRIFT")

    release = manifest.get("runtime_release", {})
    artifact = packet / "mtr-dogfood-product-lane.pyz"
    if (
        release.get("source_dirty") is not False
        or release.get("source_materialization") != "git_object_database_head"
        or not artifact.is_file()
        or _sha256(artifact) != release.get("artifact_sha256")
    ):
        raise ProductReleaseError("QUALIFICATION_RUNTIME_RELEASE_INVALID")

    closeout_path, closeout = _single_qualification_closeout(packet)
    outcomes = closeout.get("outcomes", [])
    accounting = closeout.get("process_accounting", {})
    if len(outcomes) != 1:
        raise ProductReleaseError("QUALIFICATION_OUTCOME_CARDINALITY_INVALID")
    outcome = outcomes[0]
    validation = outcome.get("validation", {})
    validator_results = validation.get("validator_results", [])
    planned_validators = task.get("validator_plan", {}).get("commands", [])
    planned_identities = [
        (item.get("name"), item.get("layer")) for item in planned_validators
    ]
    observed_identities = [
        (item.get("name"), item.get("layer")) for item in validator_results
    ]
    if (
        not planned_validators
        or closeout.get("status") != "passed"
        or closeout.get("qualification_only") is not True
        or closeout.get("campaign_started") is not False
        or closeout.get("starts_consumed") != 0
        or closeout.get("source_repositories_unchanged") is not True
        or closeout.get("packet", {}).get("manifest_sha256")
        != packet_receipt.get("manifest_sha256")
        or closeout.get("runtime_artifact", {}).get("sha256")
        != release.get("artifact_sha256")
        or accounting.get("os_child_process_started") != 0
        or accounting.get("model_execution_observed") != 0
        or accounting.get("model_execution_completed") != 0
        or accounting.get("final_output_validated") != 1
        or accounting.get("validator_completed") != len(planned_validators)
        or outcome.get("lane_id") != lane_id
        or outcome.get("accepted") is not True
        or outcome.get("qualification_fixture") is not True
        or outcome.get("qualification_state")
        != "POST_MATERIALIZATION_VALIDATED"
        or outcome.get("real_model_process_starts") != 0
        or outcome.get("real_model_requests") != 0
        or set(outcome.get("changed_paths", [])) != expected_paths
        or validation.get("automated_acceptance") is not True
        or validation.get("validator_side_effect_free") is not True
        or validation.get("validator_stage_passed") is not True
        or validation.get("required_validator_count") != len(planned_validators)
        or planned_identities != observed_identities
        or any(item.get("passed") is not True for item in validator_results)
    ):
        raise ProductReleaseError("QUALIFICATION_EVIDENCE_INVALID")

    media_families = sorted(
        {
            _media_family(str(item["media_type"]))
            for item in aliases
            if item.get("media_type")
        }
    )
    return {
        "schema_version": "1.0.0",
        "route_id": route_id,
        "repository_id": repository_id,
        "lane_id": lane_id,
        "media_families": media_families,
        "runtime_source_head": release.get("source_head"),
        "runtime_artifact_sha256": release.get("artifact_sha256"),
        "packet_manifest_sha256": packet_receipt.get("manifest_sha256"),
        "qualification_closeout_path": str(closeout_path),
        "validator_count": len(validator_results),
        "changed_paths": sorted(expected_paths),
        "accepted": True,
    }


def evaluate_qualifications(
    records: Iterable[dict[str, Any]],
    *,
    minimum_heterogeneous_products: int = 3,
) -> dict[str, Any]:
    values = list(records)
    repositories = {item.get("repository_id") for item in values}
    routes = {item.get("route_id") for item in values}
    lanes = {item.get("lane_id") for item in values}
    media_families = {
        family for item in values for family in item.get("media_families", [])
    }
    runtime_heads = {item.get("runtime_source_head") for item in values}
    artifact_hashes = {
        item.get("runtime_artifact_sha256") for item in values
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
        or oid.fullmatch(str(item.get("runtime_source_head", ""))) is None
        or digest.fullmatch(str(item.get("runtime_artifact_sha256", ""))) is None
        or digest.fullmatch(str(item.get("packet_manifest_sha256", ""))) is None
        or not item.get("media_families")
        or not isinstance(item.get("validator_count"), int)
        or item.get("validator_count", 0) < 1
        or not item.get("changed_paths")
        for item in values
    ):
        failures.append("QUALIFICATION_RECORD_INVALID")
    if len(values) < minimum_heterogeneous_products:
        failures.append("INSUFFICIENT_QUALIFICATION_COUNT")
    if len(repositories) < minimum_heterogeneous_products:
        failures.append("INSUFFICIENT_REPOSITORY_DIVERSITY")
    if len(routes) != len(values) or len(lanes) != len(values):
        failures.append("QUALIFICATION_IDENTITY_REUSED")
    if len(media_families) < 2:
        failures.append("INSUFFICIENT_MEDIA_DIVERSITY")
    if len(runtime_heads) != 1 or len(artifact_hashes) != 1:
        failures.append("COMPONENT_RELEASE_DRIFT")
    if any(item.get("accepted") is not True for item in values):
        failures.append("QUALIFICATION_NOT_ACCEPTED")
    return {
        "schema_version": "1.0.0",
        "status": "passed" if not failures else "blocked",
        "eligible_for_separately_authorized_real_canaries": not failures,
        "eligible_for_default_product_development": False,
        "minimum_heterogeneous_products": minimum_heterogeneous_products,
        "qualification_count": len(values),
        "distinct_repository_count": len(repositories),
        "distinct_media_family_count": len(media_families),
        "runtime_release_count": len(runtime_heads),
        "artifact_identity_count": len(artifact_hashes),
        "failure_codes": failures,
        "qualifications": values,
        "real_model_process_starts_created_by_evaluator": 0,
        "real_model_requests_created_by_evaluator": 0,
    }


def evaluate_packets(packet_roots: Iterable[str | Path]) -> dict[str, Any]:
    return evaluate_qualifications(
        qualification_record(path) for path in packet_roots
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="evaluate-product-release")
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
            "eligible_for_separately_authorized_real_canaries": False,
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
