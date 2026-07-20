from __future__ import annotations

import copy
import importlib
import sys
from pathlib import Path
from typing import Any

from .config import json_digest, load_json


NON_EXECUTION_STATUSES = {
    "needs_input",
    "policy_blocked",
    "invalid_request",
    "integration_failure",
}


class RouterDecisionError(ValueError):
    pass


def validate_decision(decision: dict[str, Any], known_profiles: set[str]) -> dict[str, Any]:
    if not isinstance(decision, dict):
        raise RouterDecisionError("router decision must be an object")
    if decision.get("execution_authorized") is not False:
        raise RouterDecisionError("router attempted to authorize execution")
    if "authorized_write_scope" in decision and decision["authorized_write_scope"] != []:
        raise RouterDecisionError("router returned a non-empty authorized_write_scope")
    status = decision.get("status")
    selected = decision.get("selected_profile")
    if status == "recommended":
        if selected not in known_profiles:
            raise RouterDecisionError(f"unknown router profile: {selected!r}")
    elif status not in NON_EXECUTION_STATUSES:
        raise RouterDecisionError(f"unknown router status: {status!r}")
    result = copy.deepcopy(decision)
    result["dogfood_decision_digest"] = json_digest(decision)
    return result


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
