"""Closed declarative policy validation."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

POLICY_SCHEMA_VERSION = "model_tier_router_policy_v1alpha1"
PREFERENCE_IDS = {"lower_cost", "lower_latency", "higher_reasoning", "larger_context"}
PROFILE_FIELDS = {
    "reasoning_class", "context_window_class", "modalities", "tool_support",
    "structured_output_support", "latency_class", "cost_class",
    "privacy_classes", "deployment_boundaries",
}
OPERATORS = {"at_least", "at_most", "contains", "contains_all", "equals"}
EVIDENCE_KEYS = {
    "context_window", "deployment_boundary", "modalities", "privacy",
    "structured_output", "tool_support",
}
CLASS_ORDER_KEYS = {
    "reasoning_class", "context_window_class", "latency_class", "cost_class",
}

DEFAULT_POLICY: dict[str, Any] = {
    "schema_version": POLICY_SCHEMA_VERSION,
    "policy_id": "default-balanced-v1alpha1",
    "required_evidence": [],
    "hard_constraints": [],
    "soft_preferences": ["lower_cost", "lower_latency", "higher_reasoning"],
    "class_orders": {
        "reasoning_class": ["basic", "standard", "advanced"],
        "context_window_class": ["small", "medium", "large"],
        "latency_class": ["low", "medium", "high"],
        "cost_class": ["low", "medium", "high"],
    },
    "escalation": {
        "maximum_profile": "premium",
        "maximum_attempts": 2,
        "condition_codes": ["QUALITY_INSUFFICIENT", "CONTEXT_LIMIT_REACHED"],
    },
}


class PolicyValidationError(ValueError):
    """Raised for invalid declarative policy data."""


def validate_policy(policy: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(policy, Mapping):
        raise PolicyValidationError("policy must be an object")
    allowed = {
        "schema_version", "policy_id", "required_evidence", "hard_constraints",
        "soft_preferences", "class_orders", "escalation",
    }
    _closed(policy, allowed, "policy")
    _required(policy, allowed, "policy")
    if policy["schema_version"] != POLICY_SCHEMA_VERSION:
        raise PolicyValidationError("unsupported policy schema_version")
    _identifier(policy["policy_id"], "policy_id")
    _unique_strings(policy["required_evidence"], "required_evidence", EVIDENCE_KEYS)
    preferences = _unique_strings(
        policy["soft_preferences"], "soft_preferences", PREFERENCE_IDS
    )
    orders = policy["class_orders"]
    if not isinstance(orders, Mapping):
        raise PolicyValidationError("class_orders must be an object")
    _closed(orders, CLASS_ORDER_KEYS, "class_orders")
    _required(orders, CLASS_ORDER_KEYS, "class_orders")
    normalized_orders: dict[str, list[str]] = {}
    for name in sorted(CLASS_ORDER_KEYS):
        values = _unique_strings(orders[name], name, None)
        if not values:
            raise PolicyValidationError(f"{name} cannot be empty")
        normalized_orders[name] = values
    constraints = policy["hard_constraints"]
    if not isinstance(constraints, list):
        raise PolicyValidationError("hard_constraints must be an array")
    normalized_constraints = []
    rule_ids: set[str] = set()
    for item in constraints:
        if not isinstance(item, Mapping):
            raise PolicyValidationError("constraint must be an object")
        fields = {"rule_id", "field", "operator", "value"}
        _closed(item, fields, "constraint")
        _required(item, fields, "constraint")
        _identifier(item["rule_id"], "rule_id")
        if item["rule_id"] in rule_ids:
            raise PolicyValidationError("duplicate rule_id")
        rule_ids.add(item["rule_id"])
        if item["field"] not in PROFILE_FIELDS:
            raise PolicyValidationError("unsupported constraint field")
        if item["operator"] not in OPERATORS:
            raise PolicyValidationError("unsupported constraint operator")
        if isinstance(item["value"], (dict, float)):
            raise PolicyValidationError("constraint value is not declarative JSON data")
        normalized_constraints.append(deepcopy(dict(item)))
    escalation = policy["escalation"]
    if not isinstance(escalation, Mapping):
        raise PolicyValidationError("escalation must be an object")
    escalation_fields = {"maximum_profile", "maximum_attempts", "condition_codes"}
    _closed(escalation, escalation_fields, "escalation")
    _required(escalation, escalation_fields, "escalation")
    _identifier(escalation["maximum_profile"], "maximum_profile")
    attempts = escalation["maximum_attempts"]
    if type(attempts) is not int or not 0 <= attempts <= 10:
        raise PolicyValidationError("maximum_attempts must be an integer from 0 to 10")
    conditions = _unique_strings(escalation["condition_codes"], "condition_codes", None)
    return {
        "schema_version": POLICY_SCHEMA_VERSION,
        "policy_id": policy["policy_id"],
        "required_evidence": sorted(policy["required_evidence"]),
        "hard_constraints": normalized_constraints,
        "soft_preferences": preferences,
        "class_orders": normalized_orders,
        "escalation": {
            "maximum_profile": escalation["maximum_profile"],
            "maximum_attempts": attempts,
            "condition_codes": conditions,
        },
    }


def _closed(value: Mapping[str, Any], allowed: set[str], label: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise PolicyValidationError(f"{label} has unknown field {sorted(unknown)[0]}")


def _required(value: Mapping[str, Any], required: set[str], label: str) -> None:
    missing = required - set(value)
    if missing:
        raise PolicyValidationError(f"{label} is missing {sorted(missing)[0]}")


def _identifier(value: Any, label: str) -> None:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise PolicyValidationError(f"{label} must be a non-empty string")
    if any(not (character.isalnum() or character in "-_.") for character in value):
        raise PolicyValidationError(f"{label} contains an unsupported character")


def _unique_strings(value: Any, label: str, allowed: set[str] | None) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise PolicyValidationError(f"{label} must be an array of strings")
    if len(value) != len(set(value)):
        raise PolicyValidationError(f"{label} must contain unique values")
    if allowed is not None and any(item not in allowed for item in value):
        raise PolicyValidationError(f"{label} contains an unsupported value")
    return list(value)


__all__ = ["DEFAULT_POLICY", "POLICY_SCHEMA_VERSION", "PolicyValidationError", "validate_policy"]
