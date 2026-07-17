"""Deterministic advisory selection and decision tracing."""

from __future__ import annotations

import hashlib
import unicodedata
from copy import deepcopy
from typing import Any, Mapping, Sequence

from ..strict_json import canonical_json_bytes

REQUEST_SCHEMA_VERSION = "model_tier_router_advisory_request_v1alpha1"
DECISION_SCHEMA_VERSION = "model_tier_router_advisory_decision_v1alpha1"
REQUEST_FIELDS = {
    "schema_version", "request_id", "requirements", "preferences", "evidence",
}
REQUIREMENT_FIELDS = {
    "reasoning_class", "min_context_window_class", "modalities", "tool_support",
    "structured_output_support", "maximum_latency_class", "maximum_cost_class",
    "privacy_class", "deployment_boundary",
}
EVIDENCE_FIELDS = {
    "context_window", "deployment_boundary", "modalities", "privacy",
    "structured_output", "tool_support",
}
PREFERENCES = {"lower_cost", "lower_latency", "higher_reasoning", "larger_context"}


class RequestValidationError(ValueError):
    """Raised for an invalid public advisory request."""


def validate_request(request: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(request, Mapping):
        raise RequestValidationError("request must be an object")
    if set(request) != REQUEST_FIELDS:
        raise RequestValidationError("request fields do not match the closed contract")
    if request["schema_version"] != REQUEST_SCHEMA_VERSION:
        raise RequestValidationError("unsupported request schema_version")
    if not isinstance(request["request_id"], str) or not request["request_id"]:
        raise RequestValidationError("request_id must be a non-empty string")
    requirements = request["requirements"]
    if not isinstance(requirements, Mapping) or set(requirements) - REQUIREMENT_FIELDS:
        raise RequestValidationError("requirements violate the closed contract")
    normalized_requirements = _normalize(dict(requirements))
    for field in (
        "reasoning_class", "min_context_window_class", "maximum_latency_class",
        "maximum_cost_class", "privacy_class", "deployment_boundary",
    ):
        if field in normalized_requirements and (
            not isinstance(normalized_requirements[field], str)
            or not normalized_requirements[field]
        ):
            raise RequestValidationError(f"{field} must be a non-empty string")
    for field in ("tool_support", "structured_output_support"):
        if field in normalized_requirements and type(normalized_requirements[field]) is not bool:
            raise RequestValidationError(f"{field} must be boolean")
    if "modalities" in normalized_requirements:
        modalities = normalized_requirements["modalities"]
        if (
            not isinstance(modalities, list)
            or not all(isinstance(item, str) and item for item in modalities)
            or len(modalities) != len(set(modalities))
        ):
            raise RequestValidationError("modalities must contain unique strings")
        normalized_requirements["modalities"] = sorted(modalities)
    preferences = request["preferences"]
    if (
        not isinstance(preferences, list)
        or not all(isinstance(item, str) and item in PREFERENCES for item in preferences)
        or len(preferences) != len(set(preferences))
    ):
        raise RequestValidationError("preferences must contain unique supported values")
    evidence = request["evidence"]
    if not isinstance(evidence, Mapping) or set(evidence) - EVIDENCE_FIELDS:
        raise RequestValidationError("evidence violates the closed contract")
    if not all(type(value) is bool for value in evidence.values()):
        raise RequestValidationError("evidence values must be boolean")
    normalized_request_id = unicodedata.normalize("NFC", request["request_id"])
    try:
        normalized_request_id.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise RequestValidationError("request_id must be valid Unicode") from exc
    return {
        "schema_version": REQUEST_SCHEMA_VERSION,
        "request_id": normalized_request_id,
        "requirements": normalized_requirements,
        "preferences": list(preferences),
        "evidence": {key: evidence[key] for key in sorted(evidence)},
    }


def decide(
    request: Mapping[str, Any],
    policy: Mapping[str, Any],
    profiles: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    normalized_request = validate_request(request)
    normalized_policy = deepcopy(dict(policy))
    normalized_profiles = deepcopy(list(profiles))
    request_digest = _digest(normalized_request)
    policy_digest = _digest(normalized_policy)
    catalog_digest = _digest(normalized_profiles)
    missing = sorted(
        key
        for key in normalized_policy["required_evidence"]
        if normalized_request["evidence"].get(key) is not True
    )
    constraint_results: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    candidates: list[Mapping[str, Any]] = []
    request_rules = _request_constraints(normalized_request["requirements"])
    all_rules = request_rules + list(normalized_policy["hard_constraints"])
    for profile in normalized_profiles:
        failures = []
        for rule in all_rules:
            passed = _matches(profile, rule, normalized_policy["class_orders"])
            constraint_results.append({
                "rule_id": rule["rule_id"],
                "profile_id": profile["profile_id"],
                "field": rule["field"],
                "operator": rule["operator"],
                "result": "pass" if passed else "reject",
            })
            if not passed:
                failures.append(rule["rule_id"])
        if failures:
            rejected.append({
                "profile_id": profile["profile_id"],
                "rule_ids": sorted(failures),
            })
        else:
            candidates.append(profile)
    status = "needs_input" if missing else "recommended"
    selected = None
    ranking: list[dict[str, Any]] = []
    preference_order = _preference_order(normalized_request, normalized_policy)
    if candidates:
        ranked = sorted(
            candidates,
            key=lambda profile: _rank_key(
                profile, preference_order, normalized_policy["class_orders"]
            ),
        )
        selected = ranked[0]["profile_id"]
        ranking = [
            {"profile_id": profile["profile_id"], "rank": index + 1}
            for index, profile in enumerate(ranked)
        ]
    elif not missing:
        status = "policy_blocked"
    maximum = normalized_policy["escalation"]["maximum_profile"]
    if maximum not in {profile["profile_id"] for profile in normalized_profiles}:
        raise ValueError("policy maximum_profile is absent from the profile catalog")
    decision: dict[str, Any] = {
        "schema_version": DECISION_SCHEMA_VERSION,
        "decision_id": "",
        "status": status,
        "selected_profile": selected,
        "initial_profile": selected,
        "maximum_profile": maximum,
        "constraints": constraint_results,
        "preferences": ranking,
        "evidence": {
            "required": sorted(normalized_policy["required_evidence"]),
            "observed": sorted(
                key for key, value in normalized_request["evidence"].items() if value
            ),
            "missing": missing,
            "completeness": "incomplete" if missing else "complete",
        },
        "escalation": {
            "initial_profile": selected,
            "maximum_profile": maximum,
            "maximum_attempts": normalized_policy["escalation"]["maximum_attempts"],
            "condition_codes": list(normalized_policy["escalation"]["condition_codes"]),
            "requires_new_assessment": True,
        },
        "trace": {
            "matched_rule_ids": sorted({
                item["rule_id"] for item in constraint_results if item["result"] == "pass"
            }),
            "constraint_results": constraint_results,
            "rejected_alternatives": rejected,
            "missing_evidence": missing,
            "evidence_completeness": "incomplete" if missing else "complete",
            "stable_tie_break": "preference_tuple_then_profile_id",
            "request_digest": request_digest,
            "policy_digest": policy_digest,
            "profile_catalog_digest": catalog_digest,
            "decision_digest": "",
        },
        "policy": {
            "policy_id": normalized_policy["policy_id"],
            "schema_version": normalized_policy["schema_version"],
            "policy_digest": policy_digest,
        },
        "execution_authorized": False,
        "authorized_write_scope": [],
    }
    view = deepcopy(decision)
    view["decision_id"] = None
    view["trace"]["decision_digest"] = None
    decision_digest = _digest(view)
    decision["decision_id"] = f"decision_{decision_digest}"
    decision["trace"]["decision_digest"] = decision_digest
    return decision


def failure_decision(status: str, code: str) -> dict[str, Any]:
    if status not in {"invalid_request", "integration_failure"}:
        raise ValueError("unsupported failure status")
    empty_digest = _digest({})
    value = {
        "schema_version": DECISION_SCHEMA_VERSION,
        "decision_id": "",
        "status": status,
        "selected_profile": None,
        "initial_profile": None,
        "maximum_profile": None,
        "constraints": [],
        "preferences": [],
        "evidence": {
            "required": [], "observed": [], "missing": [], "completeness": "incomplete",
        },
        "escalation": {
            "initial_profile": None,
            "maximum_profile": None,
            "maximum_attempts": 0,
            "condition_codes": [],
            "requires_new_assessment": True,
        },
        "trace": {
            "matched_rule_ids": [],
            "constraint_results": [],
            "rejected_alternatives": [],
            "missing_evidence": [],
            "evidence_completeness": "incomplete",
            "stable_tie_break": "preference_tuple_then_profile_id",
            "request_digest": empty_digest,
            "policy_digest": empty_digest,
            "profile_catalog_digest": empty_digest,
            "decision_digest": "",
            "error_code": code,
        },
        "policy": {
            "policy_id": "unavailable",
            "schema_version": "unavailable",
            "policy_digest": empty_digest,
        },
        "execution_authorized": False,
        "authorized_write_scope": [],
    }
    view = deepcopy(value)
    view["decision_id"] = None
    view["trace"]["decision_digest"] = None
    digest = _digest(view)
    value["decision_id"] = f"decision_{digest}"
    value["trace"]["decision_digest"] = digest
    return value


def _request_constraints(requirements: Mapping[str, Any]) -> list[dict[str, Any]]:
    mapping = {
        "reasoning_class": ("reasoning_class", "at_least"),
        "min_context_window_class": ("context_window_class", "at_least"),
        "modalities": ("modalities", "contains_all"),
        "tool_support": ("tool_support", "equals"),
        "structured_output_support": ("structured_output_support", "equals"),
        "maximum_latency_class": ("latency_class", "at_most"),
        "maximum_cost_class": ("cost_class", "at_most"),
        "privacy_class": ("privacy_classes", "contains"),
        "deployment_boundary": ("deployment_boundaries", "contains"),
    }
    return [{
        "rule_id": f"request.{name}",
        "field": mapping[name][0],
        "operator": mapping[name][1],
        "value": requirements[name],
    } for name in sorted(requirements)]


def _matches(
    profile: Mapping[str, Any], rule: Mapping[str, Any], orders: Mapping[str, list[str]]
) -> bool:
    actual = profile[rule["field"]]
    expected = rule["value"]
    operator = rule["operator"]
    if operator == "equals":
        return actual == expected
    if operator == "contains":
        return expected in actual
    if operator == "contains_all":
        return set(expected).issubset(actual)
    if operator in {"at_least", "at_most"}:
        order = orders.get(rule["field"])
        if order is None or actual not in order or expected not in order:
            return False
        relation = order.index(actual) - order.index(expected)
        return relation >= 0 if operator == "at_least" else relation <= 0
    return False


def _preference_order(request: Mapping[str, Any], policy: Mapping[str, Any]) -> list[str]:
    result = []
    for item in list(request["preferences"]) + list(policy["soft_preferences"]):
        if item not in result:
            result.append(item)
    return result


def _rank_key(
    profile: Mapping[str, Any], preferences: list[str], orders: Mapping[str, list[str]]
) -> tuple[Any, ...]:
    fields = {
        "lower_cost": ("cost_class", 1),
        "lower_latency": ("latency_class", 1),
        "higher_reasoning": ("reasoning_class", -1),
        "larger_context": ("context_window_class", -1),
    }
    values: list[Any] = []
    for preference in preferences:
        field, direction = fields[preference]
        values.append(direction * orders[field].index(profile[field]))
    values.append(profile["profile_id"])
    return tuple(values)


def _normalize(value: Any) -> Any:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    if isinstance(value, dict):
        return {key: _normalize(value[key]) for key in sorted(value)}
    return deepcopy(value)


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


__all__ = [
    "DECISION_SCHEMA_VERSION", "REQUEST_SCHEMA_VERSION", "RequestValidationError",
    "decide", "failure_decision", "validate_request",
]
