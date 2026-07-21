from __future__ import annotations

import copy
import importlib
import sys
from pathlib import Path
from typing import Any, Mapping

from .config import json_digest, load_json


NON_EXECUTION_STATUSES = {
    "needs_input",
    "policy_blocked",
    "invalid_request",
    "integration_failure",
}
DIGEST_FIELD = "dogfood_decision_digest"


class RouterDecisionError(ValueError):
    pass


def decision_payload(decision: Mapping[str, Any]) -> dict[str, Any]:
    """Return the semantic Router decision without its integrity envelope."""
    payload = copy.deepcopy(dict(decision))
    payload.pop(DIGEST_FIELD, None)
    return payload


def compute_decision_digest(decision: Mapping[str, Any]) -> str:
    """Hash only semantic fields so digesting is idempotent and non-recursive."""
    return json_digest(decision_payload(decision))


def validate_decision(decision: dict[str, Any], known_profiles: set[str]) -> dict[str, Any]:
    if not isinstance(decision, dict):
        raise RouterDecisionError("router decision must be an object")
    payload = decision_payload(decision)
    if payload.get("execution_authorized") is not False:
        raise RouterDecisionError("router attempted to authorize execution")
    if "authorized_write_scope" in payload and payload["authorized_write_scope"] != []:
        raise RouterDecisionError("router returned a non-empty authorized_write_scope")
    status = payload.get("status")
    selected = payload.get("selected_profile")
    if status == "recommended":
        if selected not in known_profiles:
            raise RouterDecisionError(f"unknown router profile: {selected!r}")
    elif status not in NON_EXECUTION_STATUSES:
        raise RouterDecisionError(f"unknown router status: {status!r}")
    result = payload
    result[DIGEST_FIELD] = compute_decision_digest(payload)
    return result


def verify_decision(
    actual: Mapping[str, Any],
    expected: Mapping[str, Any],
    known_profiles: set[str],
) -> dict[str, Any]:
    """Verify live and frozen decisions without ever hashing a digest field."""
    actual_payload = decision_payload(actual)
    expected_payload = decision_payload(expected)
    if actual_payload != expected_payload:
        raise RouterDecisionError("ROUTER_DECISION_SEMANTIC_DRIFT")

    validated_actual = validate_decision(actual_payload, known_profiles)
    validated_expected = validate_decision(expected_payload, known_profiles)
    if actual.get(DIGEST_FIELD) != validated_actual[DIGEST_FIELD]:
        raise RouterDecisionError("LIVE_ROUTER_DECISION_DIGEST_INVALID")
    if expected.get(DIGEST_FIELD) != validated_expected[DIGEST_FIELD]:
        raise RouterDecisionError("FROZEN_ROUTER_DECISION_DIGEST_INVALID")
    if actual.get(DIGEST_FIELD) != expected.get(DIGEST_FIELD):
        raise RouterDecisionError("ROUTER_DECISION_DIGEST_DRIFT")
    return validated_actual


def assess_live(
    router_repository: str | Path,
    request: dict[str, Any],
    known_profiles: set[str],
) -> dict[str, Any]:
    source = str(Path(router_repository).resolve() / "src")
    if source not in sys.path:
        sys.path.insert(0, source)
    module = importlib.import_module("model_tier_router")
    assess = getattr(module, "assess", None)
    if not callable(assess):
        raise RouterDecisionError("live supported assess API unavailable")
    return validate_decision(assess(copy.deepcopy(request)), known_profiles)


def load_model_map(path: str | Path) -> dict[str, Any]:
    value = load_json(path)
    if not isinstance(value, dict) or not isinstance(value.get("logical_profiles"), dict):
        raise RouterDecisionError("invalid model map")
    return value


def map_profile(model_map: dict[str, Any], profile: str) -> tuple[str, str]:
    profiles = model_map.get("logical_profiles", {})
    if profile not in profiles:
        raise RouterDecisionError(f"unknown router profile: {profile}")
    entry = profiles[profile]
    model = entry.get("codex_model")
    effort = entry.get("model_reasoning_effort")
    if not isinstance(model, str) or not isinstance(effort, str):
        raise RouterDecisionError("invalid profile mapping")
    return model, effort
