"""Independent compatibility translation for the historical v1 envelope."""

from __future__ import annotations

import re
import unicodedata
from copy import deepcopy
from pathlib import PurePosixPath
from typing import Any, Mapping

TASK_SCHEMA_VERSION = "model_tier_router_task_envelope_v1"
DECISION_SCHEMA_VERSION = "model_tier_router_decision_v1"
ASSESSMENT_SCHEMA_VERSION = "model_tier_router_assessment_v1"
ASSESSMENT_ARTIFACT_TYPE = "model_tier_router_advisory_assessment"

_SAMPLES: dict[str, dict[str, Any]] = {
    "read_only_packet_summary": {
        "task_class": "packet_summary", "risk_class": "fast",
        "model_tier": "cheap", "reasoning_budget": "minimal",
        "budget_class": "small", "scope": [], "reviewer": False,
        "human": False, "validation": "not_required", "supervised": False,
    },
    "simple_docs_manifest": {
        "task_class": "simple_docs_manifest", "risk_class": "fast",
        "model_tier": "cheap", "reasoning_budget": "minimal",
        "budget_class": "small", "scope": [], "reviewer": False,
        "human": False, "validation": "not_required", "supervised": False,
    },
    "bounded_source_test_change": {
        "task_class": "bounded_source_test_change", "risk_class": "controlled",
        "model_tier": "medium", "reasoning_budget": "medium",
        "budget_class": "normal",
        "scope": ["src/model_tier_router/router.py", "tests/test_router_contract.py"],
        "reviewer": False, "human": False, "validation": "conditional",
        "supervised": True,
    },
    "ambiguous_command_status_unknown": {
        "task_class": "command_status_unknown", "risk_class": "controlled",
        "model_tier": "expensive", "reasoning_budget": "xhigh",
        "budget_class": "locked", "scope": [], "reviewer": True,
        "human": False, "validation": "not_required", "supervised": False,
    },
    "validation_supervisor_task": {
        "task_class": "validation_supervisor", "risk_class": "controlled",
        "model_tier": "expensive", "reasoning_budget": "high",
        "budget_class": "elevated", "scope": [], "reviewer": True,
        "human": False, "validation": "conditional_supervised", "supervised": True,
    },
    "live_deploy_capability_binding": {
        "task_class": "capability_binding", "risk_class": "locked",
        "model_tier": "expensive", "reasoning_budget": "xhigh",
        "budget_class": "locked", "scope": [], "reviewer": True,
        "human": True, "validation": "not_required", "supervised": False,
    },
}
_READ_ONLY = {
    "packet_summary", "log_summary", "read_only_extraction", "schema_validation",
    "json_schema_validation", "manifest_validation", "simple_docs_manifest",
    "deterministic_smoke",
}
_BOUNDED = {
    "bounded_source_change", "bounded_source_test_change", "focused_test_change",
    "source_test_change", "local_preview_tool",
}
_LIVE = {
    "capability_binding", "capability_gateway", "deploy", "live_action",
    "production_write", "publish", "release",
}
_WRITE_BOUNDARIES = {
    "bounded_local_write", "controlled_source_test_write", "explicit_bounded_write",
}
_VALIDATIONS = {"not_required", "conditional", "conditional_supervised", "required"}
_SAFE_PATH = re.compile(
    r"^(?!/)(?!.*:)(?!.*//)(?!\.{1,2}(?:/|$))(?!.*(?:/\.{1,2})(?:/|$))"
    r"(?!.*[\\*?\[\]{}])(?!.*[\x00-\x1f\x7f-\x9f])[^/]+(?:/[^/]+)*$"
)


def project_envelope(envelope: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(envelope, dict):
        raise ValueError("TASK_ENVELOPE_SCHEMA_INVALID")
    payload = deepcopy(envelope)
    if payload.get("schema_version") != TASK_SCHEMA_VERSION:
        raise ValueError("TASK_ENVELOPE_SCHEMA_INVALID")
    task_id = payload.get("task_id")
    if not isinstance(task_id, str) or not task_id.strip():
        raise ValueError("TASK_ENVELOPE_SCHEMA_INVALID")
    task_id.encode("utf-8", errors="strict")
    if "sample" in payload:
        if set(payload) != {"schema_version", "task_id", "sample"}:
            raise ValueError("CONFLICTING_SAMPLE_AND_EXPLICIT_FIELDS")
        if payload["sample"] not in _SAMPLES:
            raise ValueError("UNKNOWN_SAMPLE")
        result = deepcopy(_SAMPLES[payload["sample"]])
        result.update({
            "task_id": task_id,
            "approval_reference": (
                f"sample-approval-{payload['sample']}"
                if result["reviewer"] or result["human"] else None
            ),
            "authority_receipt_id": f"sample-receipt-{payload['sample']}",
        })
        return result
    required = {
        "task_class", "risk_class", "authority_boundary", "uncertainty_level",
        "reversibility", "mutation_scope", "validation_cost",
        "expected_failure_cost", "evidence_requirement", "command_status_risk",
        "security_or_secret_exposure_risk", "full_suite_expected",
        "human_approval_required", "approval_reference", "validation_obligation",
        "governed_mode", "direct_model_override", "authority_receipt_id",
    }
    allowed = required | {"schema_version", "task_id", "budget_class"}
    if not required.issubset(payload) or set(payload) - allowed:
        raise ValueError("TASK_ENVELOPE_SCHEMA_INVALID")
    if payload["governed_mode"] is not True:
        raise ValueError("CANONICAL_GOVERNED_MODE_REQUIRED")
    if payload["direct_model_override"] is not None:
        raise ValueError("DIRECT_MODEL_OVERRIDE_REJECTED")
    scope = _canonical_scope(payload["mutation_scope"])
    boundary = payload["authority_boundary"]
    if bool(scope) != (boundary in _WRITE_BOUNDARIES):
        raise ValueError("INVALID_MUTATION_SCOPE")
    task_class = payload["task_class"]
    risk = payload["risk_class"]
    reviewer = bool(
        risk == "locked"
        or payload["command_status_risk"] == "unknown"
        or payload["security_or_secret_exposure_risk"] in {"medium", "high"}
        or task_class in {"validation_supervisor", "security_boundary", "write_boundary_issue"}
    )
    human = bool(payload["human_approval_required"] or task_class in _LIVE)
    if reviewer or human:
        reference = payload["approval_reference"]
        if not isinstance(reference, str) or not reference.strip():
            raise ValueError("APPROVAL_REFERENCE_REQUIRED")
    else:
        reference = None
    if task_class in _LIVE or risk == "locked":
        model, reasoning, budget = "expensive", "xhigh", "locked"
    elif task_class == "validation_supervisor":
        model, reasoning, budget = "expensive", "high", "elevated"
    elif (
        payload["command_status_risk"] == "unknown"
        or payload["uncertainty_level"] in {"high", "unknown"}
        or payload["expected_failure_cost"] in {"high", "severe"}
    ):
        model, reasoning, budget = "expensive", "high", "elevated"
    elif task_class in _READ_ONLY:
        model, reasoning, budget = "cheap", "minimal", "small"
    else:
        model, reasoning, budget = "medium", "medium", "normal"
    validation = payload["validation_obligation"]
    if validation not in _VALIDATIONS:
        raise ValueError("TASK_ENVELOPE_SCHEMA_INVALID")
    supervised = validation in {"conditional_supervised", "required"}
    return {
        "task_id": task_id,
        "task_class": task_class,
        "risk_class": risk,
        "model_tier": model,
        "reasoning_budget": reasoning,
        "budget_class": budget,
        "scope": scope,
        "reviewer": reviewer,
        "human": human,
        "approval_reference": reference,
        "validation": validation,
        "supervised": supervised,
        "authority_receipt_id": payload["authority_receipt_id"],
    }


def assess_mapping(envelope: Mapping[str, Any]) -> dict[str, Any]:
    """Return the historical v1 advisory shape without creating authority."""

    try:
        projection = project_envelope(envelope)
    except Exception as exc:
        code = str(exc) if str(exc).isupper() else "TASK_ENVELOPE_SCHEMA_INVALID"
        return _hard_stop_assessment(code)
    unmet = []
    if projection["reviewer"] or projection["human"]:
        unmet.append("approval")
    if projection["validation"] != "not_required" or projection["supervised"]:
        unmet.append("validation")
    unmet.extend(["canonical_route", "authority_receipt"])
    return {
        "schema_version": ASSESSMENT_SCHEMA_VERSION,
        "artifact_type": ASSESSMENT_ARTIFACT_TYPE,
        "advisory_only": True,
        "execution_authorized": False,
        "write_allowed": False,
        "task_class": projection["task_class"],
        "risk_class": projection["risk_class"],
        "model_tier": projection["model_tier"],
        "reasoning_budget": projection["reasoning_budget"],
        "proposed_mutation_scope": projection["scope"],
        "authorized_write_scope": [],
        "budget_class": projection["budget_class"],
        "approval_obligation": {
            "reviewer_required": projection["reviewer"],
            "human_required": projection["human"],
        },
        "validation_obligation": {
            "obligation": projection["validation"],
            "supervised_full_suite_required": projection["supervised"],
        },
        "unmet_verifier_obligations": unmet,
        "fail_closed": {"status": "clear", "code": "ADVISORY_ONLY"},
        "provider_or_model_call_count": 0,
        "network_request_count": 0,
    }


def _hard_stop_assessment(code: str) -> dict[str, Any]:
    return {
        "schema_version": ASSESSMENT_SCHEMA_VERSION,
        "artifact_type": ASSESSMENT_ARTIFACT_TYPE,
        "advisory_only": True,
        "execution_authorized": False,
        "write_allowed": False,
        "task_class": "unknown",
        "risk_class": "unknown",
        "model_tier": "expensive",
        "reasoning_budget": "xhigh",
        "proposed_mutation_scope": [],
        "authorized_write_scope": [],
        "budget_class": "locked",
        "approval_obligation": {"reviewer_required": True, "human_required": True},
        "validation_obligation": {
            "obligation": "required", "supervised_full_suite_required": True,
        },
        "unmet_verifier_obligations": [
            "approval", "validation", "canonical_route", "authority_receipt",
        ],
        "fail_closed": {"status": "hard_stop", "code": _safe_code(code)},
        "provider_or_model_call_count": 0,
        "network_request_count": 0,
    }


def _canonical_scope(value: Any) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError("INVALID_MUTATION_SCOPE")
    normalized = []
    seen = set()
    for item in value:
        if (
            not item
            or item != unicodedata.normalize("NFC", item)
            or item.strip() != item
            or not _SAFE_PATH.match(item)
            or PurePosixPath(item).as_posix() != item
        ):
            raise ValueError("INVALID_MUTATION_SCOPE")
        folded = item.casefold()
        if folded in seen:
            raise ValueError("INVALID_MUTATION_SCOPE")
        seen.add(folded)
        normalized.append(item)
    return sorted(normalized, key=lambda item: (item.casefold(), item))


def _safe_code(code: str) -> str:
    return code if re.fullmatch(r"[A-Z][A-Z0-9_]*", code or "") else "TASK_ENVELOPE_SCHEMA_INVALID"


__all__ = [
    "ASSESSMENT_ARTIFACT_TYPE", "ASSESSMENT_SCHEMA_VERSION",
    "DECISION_SCHEMA_VERSION", "TASK_SCHEMA_VERSION", "assess_mapping",
    "project_envelope",
]
