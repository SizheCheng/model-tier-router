from __future__ import annotations

from typing import Any


def eligible(task: dict[str, Any]) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if not task.get("useful_independent_of_experiment", False):
        reasons.append("not independently useful")
    if not task.get("validator_plan"):
        reasons.append("validator plan missing")
    if task.get("requires_confidential_payload", False):
        reasons.append("confidential payload required")
    if task.get("requires_network", False):
        reasons.append("network required")
    if task.get("requires_other_repository", False):
        reasons.append("another repository required")
    return not reasons, reasons


def arm_order(case_id: str) -> list[str]:
    import hashlib

    low_bit = hashlib.sha256(case_id.encode("utf-8")).digest()[-1] & 1
    if low_bit:
        return ["FIXED_PREMIUM_CONTROL", "ROUTER_AUTO"]
    return ["ROUTER_AUTO", "FIXED_PREMIUM_CONTROL"]
