"""Public advisory API."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping, Sequence

from .core.decision import RequestValidationError, decide, failure_decision
from .core.policy import DEFAULT_POLICY, PolicyValidationError, validate_policy
from .core.profiles import DEFAULT_PROFILES, ProfileValidationError, validate_profiles


def assess(
    request: Mapping[str, Any],
    *,
    policy: Mapping[str, Any] | None = None,
    profiles: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return one deterministic, non-authorizing capability-profile decision."""

    try:
        normalized_policy = validate_policy(
            deepcopy(DEFAULT_POLICY if policy is None else policy)
        )
        normalized_profiles = validate_profiles(
            deepcopy(DEFAULT_PROFILES if profiles is None else profiles)
        )
    except (PolicyValidationError, ProfileValidationError, TypeError, ValueError):
        return failure_decision("integration_failure", "INVALID_CONFIGURATION")
    try:
        return decide(request, normalized_policy, normalized_profiles)
    except RequestValidationError:
        return failure_decision("invalid_request", "INVALID_REQUEST")
    except Exception:
        return failure_decision("integration_failure", "INTEGRATION_FAILURE")


__all__ = ["assess"]
