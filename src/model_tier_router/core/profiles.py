"""Logical capability-profile validation."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping, Sequence

PROFILE_SCHEMA_VERSION = "model_tier_router_capability_profile_v1alpha1"
PROFILE_FIELDS = {
    "schema_version", "profile_id", "reasoning_class", "context_window_class",
    "modalities", "tool_support", "structured_output_support", "latency_class",
    "cost_class", "privacy_classes", "deployment_boundaries",
}

DEFAULT_PROFILES: list[dict[str, Any]] = [
    {
        "schema_version": PROFILE_SCHEMA_VERSION,
        "profile_id": "economy",
        "reasoning_class": "basic",
        "context_window_class": "small",
        "modalities": ["text"],
        "tool_support": False,
        "structured_output_support": True,
        "latency_class": "low",
        "cost_class": "low",
        "privacy_classes": ["standard"],
        "deployment_boundaries": ["local", "managed"],
    },
    {
        "schema_version": PROFILE_SCHEMA_VERSION,
        "profile_id": "balanced",
        "reasoning_class": "standard",
        "context_window_class": "medium",
        "modalities": ["image", "text"],
        "tool_support": True,
        "structured_output_support": True,
        "latency_class": "medium",
        "cost_class": "medium",
        "privacy_classes": ["restricted", "standard"],
        "deployment_boundaries": ["local", "managed"],
    },
    {
        "schema_version": PROFILE_SCHEMA_VERSION,
        "profile_id": "premium",
        "reasoning_class": "advanced",
        "context_window_class": "large",
        "modalities": ["audio", "image", "text"],
        "tool_support": True,
        "structured_output_support": True,
        "latency_class": "high",
        "cost_class": "high",
        "privacy_classes": ["restricted", "standard"],
        "deployment_boundaries": ["local", "managed"],
    },
]


class ProfileValidationError(ValueError):
    """Raised for an invalid capability-profile catalog."""


def validate_profiles(profiles: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    if not isinstance(profiles, Sequence) or isinstance(profiles, (str, bytes)):
        raise ProfileValidationError("profiles must be an array")
    if not profiles:
        raise ProfileValidationError("profiles cannot be empty")
    normalized = []
    identifiers: set[str] = set()
    for raw in profiles:
        if not isinstance(raw, Mapping):
            raise ProfileValidationError("profile must be an object")
        if set(raw) != PROFILE_FIELDS:
            raise ProfileValidationError("profile fields do not match the closed contract")
        if raw["schema_version"] != PROFILE_SCHEMA_VERSION:
            raise ProfileValidationError("unsupported profile schema_version")
        identifier = raw["profile_id"]
        if not isinstance(identifier, str) or not identifier or len(identifier) > 128:
            raise ProfileValidationError("profile_id must be a non-empty string")
        if identifier in identifiers:
            raise ProfileValidationError("duplicate profile_id")
        identifiers.add(identifier)
        for field in (
            "reasoning_class", "context_window_class", "latency_class", "cost_class",
        ):
            if not isinstance(raw[field], str) or not raw[field]:
                raise ProfileValidationError(f"{field} must be a non-empty string")
        for field in ("tool_support", "structured_output_support"):
            if type(raw[field]) is not bool:
                raise ProfileValidationError(f"{field} must be boolean")
        item = deepcopy(dict(raw))
        for field in ("modalities", "privacy_classes", "deployment_boundaries"):
            values = item[field]
            if (
                not isinstance(values, list)
                or not values
                or not all(isinstance(value, str) and value for value in values)
                or len(values) != len(set(values))
            ):
                raise ProfileValidationError(f"{field} must contain unique strings")
            item[field] = sorted(values)
        normalized.append(item)
    return sorted(normalized, key=lambda item: item["profile_id"])


__all__ = ["DEFAULT_PROFILES", "PROFILE_SCHEMA_VERSION", "ProfileValidationError", "validate_profiles"]
