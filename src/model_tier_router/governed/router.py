"""Optional fail-closed governed orchestration with no provider dispatch."""

from __future__ import annotations

import hashlib
import re
from typing import Any, Mapping

from ..compat.legacy import DECISION_SCHEMA_VERSION, project_envelope
from ..strict_json import canonical_json_bytes
from .contracts import (
    ApprovalResult,
    DispatchBindingResult,
    ReceiptResult,
    RouterPorts,
    ValidationResult,
)

_VALIDATION_RANK = {
    "not_required": 0,
    "conditional": 1,
    "conditional_supervised": 2,
    "required": 3,
}


class GovernedRouter:
    """Fail-closed verifier orchestration for the historical governed contract."""

    def __init__(self, ports: RouterPorts | None = None) -> None:
        self.ports = ports or RouterPorts()

    def route(self, envelope: Mapping[str, Any]) -> dict[str, Any]:
        try:
            projection = project_envelope(envelope)
        except Exception as exc:
            return _hard_stop(_safe_code(str(exc)))
        task_id = projection["task_id"]
        if projection["reviewer"] or projection["human"]:
            if self.ports.approval is None:
                return _hard_stop("APPROVAL_PORT_FAILURE", projection)
            try:
                approval = self.ports.approval.verify(
                    approval_reference=projection["approval_reference"],
                    task_id=task_id,
                    reviewer_required=projection["reviewer"],
                    human_required=projection["human"],
                )
            except Exception:
                return _hard_stop("APPROVAL_PORT_FAILURE", projection)
            if (
                type(approval) is not ApprovalResult
                or type(approval.verified) is not bool
                or not isinstance(approval.code, str)
            ):
                return _hard_stop("APPROVAL_PORT_FAILURE", projection)
            if not approval.verified:
                return _hard_stop(
                    approval.code if approval.code == "APPROVAL_NOT_VERIFIED"
                    else "APPROVAL_NOT_VERIFIED",
                    projection,
                )
            if approval.code:
                return _hard_stop("APPROVAL_PORT_FAILURE", projection)
        obligation = projection["validation"]
        supervised = projection["supervised"]
        if obligation != "not_required" or supervised:
            if self.ports.validation is None:
                return _hard_stop("VALIDATION_PORT_FAILURE", projection)
            try:
                validation = self.ports.validation.verify(
                    task_id=task_id,
                    obligation=obligation,
                    supervised_full_suite_required=supervised,
                )
            except Exception:
                return _hard_stop("VALIDATION_PORT_FAILURE", projection)
            if (
                type(validation) is not ValidationResult
                or type(validation.accepted) is not bool
                or type(validation.supervised_full_suite_required) is not bool
                or validation.obligation not in _VALIDATION_RANK
                or not isinstance(validation.code, str)
            ):
                return _hard_stop("VALIDATION_PORT_FAILURE", projection)
            if not validation.accepted:
                return _hard_stop(
                    validation.code if validation.code == "VALIDATION_NOT_ACCEPTED"
                    else "VALIDATION_NOT_ACCEPTED",
                    projection,
                )
            if validation.code:
                return _hard_stop("VALIDATION_PORT_FAILURE", projection)
            requested = (_VALIDATION_RANK[obligation], int(supervised))
            verified = (
                _VALIDATION_RANK[validation.obligation],
                int(validation.supervised_full_suite_required),
            )
            if verified[0] < requested[0] or verified[1] < requested[1]:
                if verified[0] > requested[0] or verified[1] > requested[1]:
                    return _hard_stop("VALIDATION_OBLIGATION_CONFLICT", projection)
                return _hard_stop("VALIDATION_OBLIGATION_DOWNGRADE", projection)
            obligation = validation.obligation
            supervised = validation.supervised_full_suite_required
        decision_id = _decision_id(projection, obligation, supervised)
        if self.ports.canonical_dispatch is None:
            return _hard_stop("CANONICAL_ROUTE_PORT_FAILURE", projection)
        try:
            binding = self.ports.canonical_dispatch.verify(
                task_id=task_id,
                decision_id=decision_id,
                direct_model_override=None,
            )
        except Exception:
            return _hard_stop("CANONICAL_ROUTE_PORT_FAILURE", projection)
        if (
            type(binding) is not DispatchBindingResult
            or type(binding.canonical) is not bool
            or not isinstance(binding.code, str)
        ):
            return _hard_stop("CANONICAL_ROUTE_PORT_FAILURE", projection)
        if not binding.canonical:
            return _hard_stop(
                binding.code if binding.code == "CANONICAL_PATH_NOT_VERIFIED"
                else "CANONICAL_PATH_NOT_VERIFIED",
                projection,
            )
        if binding.code:
            return _hard_stop("CANONICAL_ROUTE_PORT_FAILURE", projection)
        if self.ports.authority_receipt is None:
            return _hard_stop("RECEIPT_PORT_FAILURE", projection)
        try:
            receipt = self.ports.authority_receipt.verify(
                receipt_id=projection["authority_receipt_id"],
                decision_id=decision_id,
                budget_class=projection["budget_class"],
                mutation_scope=projection["scope"],
            )
        except Exception:
            return _hard_stop("RECEIPT_PORT_FAILURE", projection)
        if (
            type(receipt) is not ReceiptResult
            or type(receipt.valid) is not bool
            or not isinstance(receipt.authority_state, str)
            or not isinstance(receipt.code, str)
        ):
            return _hard_stop("RECEIPT_PORT_FAILURE", projection)
        if not receipt.valid:
            allowed = {
                "AUTHORITY_RECEIPT_MISMATCH", "AUTHORITY_RECEIPT_ALREADY_CONSUMED",
                "AUTHORITY_RECEIPT_REJECTED",
            }
            return _hard_stop(
                receipt.code if receipt.code in allowed else "AUTHORITY_RECEIPT_REJECTED",
                projection,
            )
        if receipt.authority_state != "valid_unconsumed" or receipt.code:
            return _hard_stop("RECEIPT_PORT_FAILURE", projection)
        return {
            "schema_version": DECISION_SCHEMA_VERSION,
            "decision_id": decision_id,
            "task_class": projection["task_class"],
            "risk_class": projection["risk_class"],
            "model_tier": projection["model_tier"],
            "reasoning_budget": projection["reasoning_budget"],
            "write_authority": {
                "allowed": bool(projection["scope"]),
                "scope": projection["scope"],
            },
            "approval": {
                "reviewer_required": projection["reviewer"],
                "human_required": projection["human"],
                "approval_reference": projection["approval_reference"],
            },
            "validation": {
                "obligation": obligation,
                "supervised_full_suite_required": supervised,
            },
            "fail_closed": {"status": "clear", "code": "OK"},
            "route_binding": {
                "canonical_path_required": True,
                "direct_model_override_allowed": False,
            },
            "accounting": {
                "budget_class": projection["budget_class"],
                "authority_receipt_id": projection["authority_receipt_id"],
                "authority_state": "valid_unconsumed",
            },
            "provider_or_model_call_count": 0,
            "network_request_count": 0,
        }


def route_mapping(
    envelope: Mapping[str, Any], ports: RouterPorts | None = None
) -> dict[str, Any]:
    try:
        return GovernedRouter(ports).route(envelope)
    except Exception:
        return _hard_stop("INTERNAL_DECISION_VALIDATION_FAILURE")


def _decision_id(
    projection: Mapping[str, Any], obligation: str, supervised: bool
) -> str:
    value = {
        "task_id": projection["task_id"],
        "task_class": projection["task_class"],
        "risk_class": projection["risk_class"],
        "model_tier": projection["model_tier"],
        "reasoning_budget": projection["reasoning_budget"],
        "scope": projection["scope"],
        "budget_class": projection["budget_class"],
        "reviewer": projection["reviewer"],
        "human": projection["human"],
        "validation": obligation,
        "supervised": supervised,
    }
    return "decision_" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _hard_stop(code: str, projection: Mapping[str, Any] | None = None) -> dict[str, Any]:
    item = projection or {}
    return {
        "schema_version": DECISION_SCHEMA_VERSION,
        "decision_id": "decision_" + hashlib.sha256(
            canonical_json_bytes({"code": _safe_code(code)})
        ).hexdigest(),
        "task_class": item.get("task_class", "unknown"),
        "risk_class": item.get("risk_class", "unknown"),
        "model_tier": "expensive",
        "reasoning_budget": "xhigh",
        "write_authority": {"allowed": False, "scope": []},
        "approval": {
            "reviewer_required": True,
            "human_required": True,
            "approval_reference": None,
        },
        "validation": {
            "obligation": "required",
            "supervised_full_suite_required": True,
        },
        "fail_closed": {"status": "hard_stop", "code": _safe_code(code)},
        "route_binding": {
            "canonical_path_required": True,
            "direct_model_override_allowed": False,
        },
        "accounting": {
            "budget_class": "locked",
            "authority_receipt_id": None,
            "authority_state": "unverified",
        },
        "provider_or_model_call_count": 0,
        "network_request_count": 0,
    }


def _safe_code(code: str) -> str:
    return (
        code if re.fullmatch(r"[A-Z][A-Z0-9_]*", code or "")
        else "INTERNAL_DECISION_VALIDATION_FAILURE"
    )


__all__ = ["GovernedRouter", "route_mapping"]
