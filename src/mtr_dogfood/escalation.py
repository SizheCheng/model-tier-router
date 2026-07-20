from __future__ import annotations


ELIGIBLE_FAILURES = {
    "IMPLEMENTATION_INCOMPLETE",
    "VALIDATOR_FAILURE_AFTER_SUCCESSFUL_MODEL_RUN",
    "CONTEXT_OR_REASONING_INSUFFICIENT",
}

INFRASTRUCTURE_FAILURES = {
    "MODEL_UNAVAILABLE",
    "AUTHENTICATION_FAILURE",
    "RATE_LIMIT",
    "SHELL_COMMAND_NOT_FOUND",
    "DEPENDENCY_OR_ENVIRONMENT_FAILURE",
    "CONCURRENT_EXTERNAL_SESSION_RESOURCE_CONTENTION",
}

PROFILE_SEQUENCE = ("economy", "balanced", "premium")


def next_profile(profile: str, failure_class: str, escalation_count: int) -> str | None:
    if failure_class not in ELIGIBLE_FAILURES or escalation_count >= 1:
        return None
    try:
        index = PROFILE_SEQUENCE.index(profile)
    except ValueError:
        return None
    if index + 1 >= len(PROFILE_SEQUENCE):
        return None
    return PROFILE_SEQUENCE[index + 1]


def escalation_allowed(profile: str, failure_class: str, escalation_count: int) -> bool:
    return next_profile(profile, failure_class, escalation_count) is not None
