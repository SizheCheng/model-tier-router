from __future__ import annotations

import copy
import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol

from .app_server_experiment import validate_outcome, validate_proposal
from .app_server_host_adapter import TURN_START_ALLOWED_FIELDS
from .config import json_digest


COMPONENT_ID = "MTR_CODEX_APP_SERVER_ATOMIC_HOST_LAUNCH_R1"
SCHEMA_VERSION = "1.0.0"
CAPABILITY_VERSION = "2.0.0"
MAX_CAPABILITY_BYTES = 65_536
MAX_CAPABILITY_LIFETIME_SECONDS = 600
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,160}")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")

HOST_BINDING_FIELDS = {
    "host_request_binding_sha256",
    "host_context_binding_sha256",
    "host_instance_sha256",
    "connection_sha256",
    "consent_grant_sha256",
    "budget_lease_sha256",
}
INTENT_FIELDS = {
    "schema_version",
    "component_id",
    "status",
    "proposal_sha256",
    "plan_sha256",
    "assignment_id",
    "client_info_name",
    "request",
    "selection",
    "host_bindings",
    "authority_boundary",
    "privacy",
    "intent_sha256",
}
INTENT_REQUEST_FIELDS = {
    "method",
    "request_id",
    "thread_id_sha256",
    "non_selection_params_preserved",
}
SELECTION_FIELDS = {"model", "effort"}
HOST_RESULT_FIELDS = {
    "capability_version",
    "status",
    "issuer",
    "audience",
    "issued_at_utc",
    "expires_at_utc",
    "launched_at_utc",
    "capability_id_sha256",
    "capability_envelope_sha256",
    "nonce_sha256",
    "launch_intent_sha256",
    "proposal_sha256",
    "plan_sha256",
    "assignment_id",
    "host_request_binding_sha256",
    "host_context_binding_sha256",
    "host_instance_sha256",
    "connection_sha256",
    "consent_grant_sha256",
    "budget_lease_sha256",
    "method",
    "request_id",
    "thread_id_sha256",
    "turn_id_sha256",
    "selected_model",
    "selected_effort",
    "capability_verified",
    "nonce_consumed",
    "request_binding_verified",
    "context_binding_verified",
    "transport_identity_validated",
    "attestation_validated",
    "permission_boundary_validated",
    "catalog_validated",
    "entitlement_validated",
    "consent_validated",
    "assignment_validated",
    "budget_consumed",
    "starts_consumed",
    "request_sent",
    "turn_started",
}
RECEIPT_FIELDS = {
    "schema_version",
    "component_id",
    "status",
    "proposal_sha256",
    "plan_sha256",
    "assignment_id",
    "launch_intent_sha256",
    "capability",
    "host",
    "request",
    "selection",
    "response",
    "authority_boundary",
    "privacy",
    "receipt_sha256",
}
CAPABILITY_RECEIPT_FIELDS = {
    "capability_version",
    "capability_id_sha256",
    "envelope_sha256",
    "issuer",
    "audience",
    "issued_at_utc",
    "expires_at_utc",
    "nonce_sha256",
    "verified",
    "nonce_consumed",
}
HOST_RECEIPT_FIELDS = HOST_BINDING_FIELDS | {
    "request_binding_verified",
    "context_binding_verified",
    "transport_identity_validated",
    "attestation_validated",
    "permission_boundary_validated",
    "catalog_validated",
    "entitlement_validated",
    "consent_validated",
    "assignment_validated",
    "budget_consumed",
}
REQUEST_RECEIPT_FIELDS = {
    "method",
    "request_id",
    "thread_id_sha256",
    "non_selection_params_preserved",
    "exact_request_sent",
}
RESPONSE_RECEIPT_FIELDS = {
    "turn_id_sha256",
    "turn_status",
    "turn_started",
    "starts_consumed",
    "launched_at_utc",
}
JOIN_FIELDS = {
    "schema_version",
    "component_id",
    "status",
    "launch_receipt_sha256",
    "outcome_sha256",
    "proposal_sha256",
    "assignment_id",
    "experiment_id",
    "arm",
    "turn_id_sha256",
    "requested_model",
    "requested_effort",
    "resolved_model",
    "outcome_class",
    "join_sha256",
}
INTENT_AUTHORITY_BOUNDARY = {
    "execution_authorized_by_router": False,
    "execution_authorized_by_intent": False,
    "host_atomic_launch_required": True,
    "permission_expansion_authorized": False,
    "approval_policy_override_authorized": False,
    "sandbox_override_authorized": False,
    "network_expansion_authorized": False,
    "authorized_write_scope": [],
}
RECEIPT_AUTHORITY_BOUNDARY = {
    "execution_authorized_by_router": False,
    "model_launch_authorized_and_performed_by_host": True,
    "host_atomic_launch_required": True,
    "permission_expansion_authorized": False,
    "approval_policy_override_authorized": False,
    "sandbox_override_authorized": False,
    "network_expansion_authorized": False,
    "authorized_write_scope": [],
}
PRIVACY_BOUNDARY = {
    "raw_capability_envelope_persisted": False,
    "raw_prompt_persisted": False,
    "raw_thread_id_persisted": False,
    "raw_turn_id_persisted": False,
    "raw_path_persisted": False,
    "raw_app_server_response_persisted": False,
    "raw_model_output_persisted": False,
    "raw_tool_output_persisted": False,
    "raw_error_text_persisted": False,
    "host_request_binding_must_be_keyed": True,
}


class AtomicHostLaunchError(RuntimeError):
    pass


class HostAtomicTurnLauncher(Protocol):
    """Host-owned atomic verification, nonce, budget, and send seam."""

    def launch(
        self,
        capability_envelope: bytes,
        request: Mapping[str, Any],
        launch_intent: Mapping[str, Any],
    ) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
        """Return the App Server response and authenticated host result."""


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8", errors="strict"))


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise AtomicHostLaunchError(f"{field}_INVALID")
    return value


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise AtomicHostLaunchError(f"{field}_INVALID")
    return value


def _opaque_identifier(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or any(ord(character) < 32 for character in value)
    ):
        raise AtomicHostLaunchError(f"{field}_INVALID")
    return value


def _bounded_text(value: Any, field: str, maximum: int = 200) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise AtomicHostLaunchError(f"{field}_INVALID")
    return value


def _request_id(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= 2_147_483_647:
        raise AtomicHostLaunchError("REQUEST_ID_INVALID")
    return value


def _utc(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise AtomicHostLaunchError(f"{field}_INVALID")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise AtomicHostLaunchError(f"{field}_INVALID") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise AtomicHostLaunchError(f"{field}_INVALID")
    return parsed


def _aware_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise AtomicHostLaunchError("NOW_INVALID")
    return value.astimezone(timezone.utc)


def _verified_proposal(value: dict[str, Any]) -> dict[str, Any]:
    try:
        return validate_proposal(value)
    except Exception:
        raise AtomicHostLaunchError("PROPOSAL_INVALID") from None


def _host_bindings(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != HOST_BINDING_FIELDS:
        raise AtomicHostLaunchError("HOST_BINDINGS_INVALID")
    return {
        field: _sha256(value.get(field), field.upper())
        for field in sorted(HOST_BINDING_FIELDS)
    }


def _turn_start_params(value: Any) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) - TURN_START_ALLOWED_FIELDS
        or "threadId" not in value
        or "input" not in value
    ):
        raise AtomicHostLaunchError("TURN_START_PARAMS_INVALID")
    _opaque_identifier(value.get("threadId"), "TURN_START_THREAD_ID")
    turn_input = value.get("input")
    if not isinstance(turn_input, list) or not 1 <= len(turn_input) <= 10_000:
        raise AtomicHostLaunchError("TURN_START_INPUT_INVALID")
    try:
        copied = copy.deepcopy(value)
        json_digest(copied)
    except Exception:
        raise AtomicHostLaunchError("TURN_START_PARAMS_INVALID") from None
    return copied


def build_atomic_launch_intent(
    proposal: dict[str, Any],
    base_params: dict[str, Any],
    host_bindings: dict[str, Any],
    *,
    request_id: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build a non-authorizing request and host capability binding target."""

    verified = _verified_proposal(proposal)
    normalized_request_id = _request_id(request_id)
    bindings = _host_bindings(host_bindings)
    original = _turn_start_params(base_params)
    non_selection_before = copy.deepcopy(original)
    non_selection_before.pop("model", None)
    non_selection_before.pop("effort", None)

    compiled = copy.deepcopy(original)
    compiled["model"] = verified["selection"]["requested_model"]
    compiled["effort"] = verified["selection"]["requested_effort"]
    non_selection_after = copy.deepcopy(compiled)
    non_selection_after.pop("model", None)
    non_selection_after.pop("effort", None)
    if non_selection_before != non_selection_after:
        raise AtomicHostLaunchError("NON_SELECTION_PARAMS_DRIFT")

    request = {
        "method": "turn/start",
        "id": normalized_request_id,
        "params": compiled,
    }
    intent: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "component_id": COMPONENT_ID,
        "status": "host_capability_required",
        "proposal_sha256": verified["proposal_sha256"],
        "plan_sha256": verified["plan_sha256"],
        "assignment_id": verified["assignment_id"],
        "client_info_name": verified["app_server_binding"][
            "client_info_name"
        ],
        "request": {
            "method": "turn/start",
            "request_id": normalized_request_id,
            "thread_id_sha256": _sha256_text(compiled["threadId"]),
            "non_selection_params_preserved": True,
        },
        "selection": {
            "model": verified["selection"]["requested_model"],
            "effort": verified["selection"]["requested_effort"],
        },
        "host_bindings": bindings,
        "authority_boundary": copy.deepcopy(INTENT_AUTHORITY_BOUNDARY),
        "privacy": copy.deepcopy(PRIVACY_BOUNDARY),
    }
    intent["intent_sha256"] = json_digest(intent)
    return copy.deepcopy(request), validate_atomic_launch_intent(
        intent,
        proposal=verified,
    )


def validate_atomic_launch_intent(
    value: Any,
    *,
    proposal: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != INTENT_FIELDS:
        raise AtomicHostLaunchError("LAUNCH_INTENT_SCHEMA_INVALID")
    digest = _sha256(value.get("intent_sha256"), "LAUNCH_INTENT_SHA256")
    view = copy.deepcopy(value)
    view.pop("intent_sha256", None)
    if json_digest(view) != digest:
        raise AtomicHostLaunchError("LAUNCH_INTENT_DIGEST_INVALID")
    if (
        value.get("schema_version") != SCHEMA_VERSION
        or value.get("component_id") != COMPONENT_ID
        or value.get("status") != "host_capability_required"
    ):
        raise AtomicHostLaunchError("LAUNCH_INTENT_SCHEMA_INVALID")
    _sha256(value.get("proposal_sha256"), "PROPOSAL_SHA256")
    _sha256(value.get("plan_sha256"), "PLAN_SHA256")
    _identifier(value.get("assignment_id"), "ASSIGNMENT_ID")
    _identifier(value.get("client_info_name"), "CLIENT_INFO_NAME")

    request = value.get("request")
    selection = value.get("selection")
    if (
        not isinstance(request, dict)
        or set(request) != INTENT_REQUEST_FIELDS
        or not isinstance(selection, dict)
        or set(selection) != SELECTION_FIELDS
    ):
        raise AtomicHostLaunchError("LAUNCH_INTENT_SCHEMA_INVALID")
    if (
        request.get("method") != "turn/start"
        or request.get("non_selection_params_preserved") is not True
    ):
        raise AtomicHostLaunchError("LAUNCH_INTENT_STATE_INVALID")
    _request_id(request.get("request_id"))
    _sha256(request.get("thread_id_sha256"), "THREAD_ID_SHA256")
    _identifier(selection.get("model"), "SELECTION_MODEL")
    _identifier(selection.get("effort"), "SELECTION_EFFORT")
    _host_bindings(value.get("host_bindings"))
    if value.get("authority_boundary") != INTENT_AUTHORITY_BOUNDARY:
        raise AtomicHostLaunchError("LAUNCH_INTENT_AUTHORITY_DRIFT")
    if value.get("privacy") != PRIVACY_BOUNDARY:
        raise AtomicHostLaunchError("LAUNCH_INTENT_PRIVACY_DRIFT")

    if proposal is not None:
        verified = _verified_proposal(proposal)
        if (
            value["proposal_sha256"] != verified["proposal_sha256"]
            or value["plan_sha256"] != verified["plan_sha256"]
            or value["assignment_id"] != verified["assignment_id"]
            or value["client_info_name"]
            != verified["app_server_binding"]["client_info_name"]
            or selection["model"]
            != verified["selection"]["requested_model"]
            or selection["effort"]
            != verified["selection"]["requested_effort"]
        ):
            raise AtomicHostLaunchError("LAUNCH_INTENT_PROPOSAL_BINDING_INVALID")
    return copy.deepcopy(value)


def _validate_request_against_intent(
    value: Any,
    intent: dict[str, Any],
) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != {"method", "id", "params"}
        or value.get("method") != "turn/start"
        or value.get("id") != intent["request"]["request_id"]
    ):
        raise AtomicHostLaunchError("TURN_START_REQUEST_INVALID")
    params = _turn_start_params(value.get("params"))
    non_selection = copy.deepcopy(params)
    non_selection.pop("model", None)
    non_selection.pop("effort", None)
    if (
        _sha256_text(params["threadId"])
        != intent["request"]["thread_id_sha256"]
        or params.get("model") != intent["selection"]["model"]
        or params.get("effort") != intent["selection"]["effort"]
        or intent["request"]["non_selection_params_preserved"] is not True
    ):
        raise AtomicHostLaunchError("TURN_START_REQUEST_BINDING_INVALID")
    try:
        json_digest(non_selection)
    except Exception:
        raise AtomicHostLaunchError("TURN_START_REQUEST_INVALID") from None
    return {
        "method": "turn/start",
        "id": _request_id(value["id"]),
        "params": params,
    }


def _turn_start_response(value: Any) -> tuple[dict[str, Any], str]:
    if not isinstance(value, Mapping):
        raise AtomicHostLaunchError("TURN_START_RESPONSE_INVALID")
    copied = copy.deepcopy(dict(value))
    if set(copied) != {"turn"} or not isinstance(copied.get("turn"), dict):
        raise AtomicHostLaunchError("TURN_START_RESPONSE_INVALID")
    turn = copied["turn"]
    allowed = {
        "completedAt",
        "durationMs",
        "error",
        "id",
        "items",
        "itemsView",
        "startedAt",
        "status",
    }
    if (
        not {"id", "items", "status"} <= set(turn)
        or set(turn) - allowed
        or turn.get("status") != "inProgress"
        or turn.get("items") != []
        or turn.get("error") not in (None,)
        or turn.get("completedAt") not in (None,)
        or turn.get("durationMs") not in (None,)
    ):
        raise AtomicHostLaunchError("TURN_START_RESPONSE_INVALID")
    if "itemsView" in turn and turn["itemsView"] not in (None, []):
        raise AtomicHostLaunchError("TURN_START_RESPONSE_INVALID")
    if "startedAt" in turn and (
        type(turn["startedAt"]) is not int or turn["startedAt"] < 0
    ):
        raise AtomicHostLaunchError("TURN_START_RESPONSE_INVALID")
    turn_id = _opaque_identifier(turn.get("id"), "TURN_ID")
    try:
        json_digest(copied)
    except Exception:
        raise AtomicHostLaunchError("TURN_START_RESPONSE_INVALID") from None
    return copied, turn_id


def _validated_host_result(
    value: Any,
    *,
    intent: dict[str, Any],
    capability_envelope: bytes,
    turn_id: str,
    now: datetime,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise AtomicHostLaunchError("HOST_LAUNCH_RESULT_INVALID")
    result = copy.deepcopy(dict(value))
    if set(result) != HOST_RESULT_FIELDS:
        raise AtomicHostLaunchError("HOST_LAUNCH_RESULT_INVALID")
    if (
        result.get("capability_version") != CAPABILITY_VERSION
        or result.get("status") != "turn_started"
    ):
        raise AtomicHostLaunchError("HOST_LAUNCH_RESULT_INVALID")
    _bounded_text(result.get("issuer"), "HOST_LAUNCH_ISSUER")
    if result.get("audience") != intent["client_info_name"]:
        raise AtomicHostLaunchError("HOST_LAUNCH_AUDIENCE_MISMATCH")

    issued = _utc(result.get("issued_at_utc"), "HOST_CAPABILITY_ISSUED_AT")
    expires = _utc(result.get("expires_at_utc"), "HOST_CAPABILITY_EXPIRES_AT")
    launched = _utc(result.get("launched_at_utc"), "HOST_LAUNCHED_AT")
    current = _aware_utc(now)
    if (
        issued > launched
        or launched > current
        or current > expires
        or expires <= issued
        or (expires - issued).total_seconds()
        > MAX_CAPABILITY_LIFETIME_SECONDS
    ):
        raise AtomicHostLaunchError("HOST_CAPABILITY_EXPIRED_OR_INVALID")

    expected = {
        "capability_envelope_sha256": _sha256_bytes(capability_envelope),
        "launch_intent_sha256": intent["intent_sha256"],
        "proposal_sha256": intent["proposal_sha256"],
        "plan_sha256": intent["plan_sha256"],
        "assignment_id": intent["assignment_id"],
        **intent["host_bindings"],
        "method": "turn/start",
        "request_id": intent["request"]["request_id"],
        "thread_id_sha256": intent["request"]["thread_id_sha256"],
        "turn_id_sha256": _sha256_text(turn_id),
        "selected_model": intent["selection"]["model"],
        "selected_effort": intent["selection"]["effort"],
    }
    for field, expected_value in expected.items():
        if result.get(field) != expected_value:
            raise AtomicHostLaunchError(
                f"HOST_LAUNCH_{field.upper()}_MISMATCH"
            )
    for field in (
        "capability_id_sha256",
        "capability_envelope_sha256",
        "nonce_sha256",
        "launch_intent_sha256",
        "proposal_sha256",
        "plan_sha256",
        "host_request_binding_sha256",
        "host_context_binding_sha256",
        "host_instance_sha256",
        "connection_sha256",
        "consent_grant_sha256",
        "budget_lease_sha256",
        "thread_id_sha256",
        "turn_id_sha256",
    ):
        _sha256(result.get(field), field.upper())
    _identifier(result.get("assignment_id"), "ASSIGNMENT_ID")
    _identifier(result.get("selected_model"), "SELECTED_MODEL")
    _identifier(result.get("selected_effort"), "SELECTED_EFFORT")
    _request_id(result.get("request_id"))
    if result.get("method") != "turn/start":
        raise AtomicHostLaunchError("HOST_LAUNCH_METHOD_INVALID")
    for field in (
        "capability_verified",
        "nonce_consumed",
        "request_binding_verified",
        "context_binding_verified",
        "transport_identity_validated",
        "attestation_validated",
        "permission_boundary_validated",
        "catalog_validated",
        "entitlement_validated",
        "consent_validated",
        "assignment_validated",
        "budget_consumed",
        "request_sent",
        "turn_started",
    ):
        if result.get(field) is not True:
            raise AtomicHostLaunchError(
                f"HOST_LAUNCH_{field.upper()}_REQUIRED"
            )
    if type(result.get("starts_consumed")) is not int or result[
        "starts_consumed"
    ] != 1:
        raise AtomicHostLaunchError("HOST_LAUNCH_START_BUDGET_INVALID")
    return result


def launch_atomic_turn_start(
    proposal: dict[str, Any],
    launch_intent: dict[str, Any],
    request: dict[str, Any],
    capability_envelope: bytes,
    launcher: HostAtomicTurnLauncher,
    *,
    now: datetime,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Have the trusted host atomically verify, consume, send, and attest."""

    verified_proposal = _verified_proposal(proposal)
    intent = validate_atomic_launch_intent(
        launch_intent,
        proposal=verified_proposal,
    )
    exact_request = _validate_request_against_intent(request, intent)
    if (
        not isinstance(capability_envelope, bytes)
        or not 1 <= len(capability_envelope) <= MAX_CAPABILITY_BYTES
    ):
        raise AtomicHostLaunchError("HOST_CAPABILITY_ENVELOPE_INVALID")
    launch = getattr(launcher, "launch", None)
    if not callable(launch):
        raise AtomicHostLaunchError("HOST_ATOMIC_LAUNCHER_REQUIRED")
    try:
        raw_result = launch(
            capability_envelope,
            copy.deepcopy(exact_request),
            copy.deepcopy(intent),
        )
    except Exception:
        raise AtomicHostLaunchError("HOST_ATOMIC_LAUNCH_FAILED") from None
    if not isinstance(raw_result, tuple) or len(raw_result) != 2:
        raise AtomicHostLaunchError("HOST_ATOMIC_LAUNCH_RESULT_INVALID")
    response, turn_id = _turn_start_response(raw_result[0])
    host_result = _validated_host_result(
        raw_result[1],
        intent=intent,
        capability_envelope=capability_envelope,
        turn_id=turn_id,
        now=now,
    )

    receipt: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "component_id": COMPONENT_ID,
        "status": "host_started",
        "proposal_sha256": intent["proposal_sha256"],
        "plan_sha256": intent["plan_sha256"],
        "assignment_id": intent["assignment_id"],
        "launch_intent_sha256": intent["intent_sha256"],
        "capability": {
            "capability_version": CAPABILITY_VERSION,
            "capability_id_sha256": host_result[
                "capability_id_sha256"
            ],
            "envelope_sha256": host_result[
                "capability_envelope_sha256"
            ],
            "issuer": host_result["issuer"],
            "audience": host_result["audience"],
            "issued_at_utc": host_result["issued_at_utc"],
            "expires_at_utc": host_result["expires_at_utc"],
            "nonce_sha256": host_result["nonce_sha256"],
            "verified": True,
            "nonce_consumed": True,
        },
        "host": {
            **copy.deepcopy(intent["host_bindings"]),
            "request_binding_verified": True,
            "context_binding_verified": True,
            "transport_identity_validated": True,
            "attestation_validated": True,
            "permission_boundary_validated": True,
            "catalog_validated": True,
            "entitlement_validated": True,
            "consent_validated": True,
            "assignment_validated": True,
            "budget_consumed": True,
        },
        "request": {
            "method": "turn/start",
            "request_id": intent["request"]["request_id"],
            "thread_id_sha256": intent["request"]["thread_id_sha256"],
            "non_selection_params_preserved": True,
            "exact_request_sent": True,
        },
        "selection": copy.deepcopy(intent["selection"]),
        "response": {
            "turn_id_sha256": host_result["turn_id_sha256"],
            "turn_status": "inProgress",
            "turn_started": True,
            "starts_consumed": 1,
            "launched_at_utc": host_result["launched_at_utc"],
        },
        "authority_boundary": copy.deepcopy(
            RECEIPT_AUTHORITY_BOUNDARY
        ),
        "privacy": copy.deepcopy(PRIVACY_BOUNDARY),
    }
    receipt["receipt_sha256"] = json_digest(receipt)
    return response, validate_atomic_launch_receipt(
        receipt,
        proposal=verified_proposal,
    )


def validate_atomic_launch_receipt(
    value: Any,
    *,
    proposal: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != RECEIPT_FIELDS:
        raise AtomicHostLaunchError("ATOMIC_LAUNCH_RECEIPT_SCHEMA_INVALID")
    digest = _sha256(
        value.get("receipt_sha256"),
        "ATOMIC_LAUNCH_RECEIPT_SHA256",
    )
    view = copy.deepcopy(value)
    view.pop("receipt_sha256", None)
    if json_digest(view) != digest:
        raise AtomicHostLaunchError("ATOMIC_LAUNCH_RECEIPT_DIGEST_INVALID")
    if (
        value.get("schema_version") != SCHEMA_VERSION
        or value.get("component_id") != COMPONENT_ID
        or value.get("status") != "host_started"
    ):
        raise AtomicHostLaunchError("ATOMIC_LAUNCH_RECEIPT_SCHEMA_INVALID")
    _sha256(value.get("proposal_sha256"), "PROPOSAL_SHA256")
    _sha256(value.get("plan_sha256"), "PLAN_SHA256")
    _identifier(value.get("assignment_id"), "ASSIGNMENT_ID")
    _sha256(value.get("launch_intent_sha256"), "LAUNCH_INTENT_SHA256")

    capability = value.get("capability")
    host = value.get("host")
    request = value.get("request")
    selection = value.get("selection")
    response = value.get("response")
    if (
        not isinstance(capability, dict)
        or set(capability) != CAPABILITY_RECEIPT_FIELDS
        or not isinstance(host, dict)
        or set(host) != HOST_RECEIPT_FIELDS
        or not isinstance(request, dict)
        or set(request) != REQUEST_RECEIPT_FIELDS
        or not isinstance(selection, dict)
        or set(selection) != SELECTION_FIELDS
        or not isinstance(response, dict)
        or set(response) != RESPONSE_RECEIPT_FIELDS
    ):
        raise AtomicHostLaunchError("ATOMIC_LAUNCH_RECEIPT_SCHEMA_INVALID")
    if capability.get("capability_version") != CAPABILITY_VERSION:
        raise AtomicHostLaunchError("ATOMIC_LAUNCH_RECEIPT_STATE_INVALID")
    for field in (
        "capability_id_sha256",
        "envelope_sha256",
        "nonce_sha256",
    ):
        _sha256(capability.get(field), f"CAPABILITY_{field.upper()}")
    _bounded_text(capability.get("issuer"), "CAPABILITY_ISSUER")
    _identifier(capability.get("audience"), "CAPABILITY_AUDIENCE")
    issued = _utc(capability.get("issued_at_utc"), "CAPABILITY_ISSUED_AT")
    expires = _utc(capability.get("expires_at_utc"), "CAPABILITY_EXPIRES_AT")
    if (
        capability.get("verified") is not True
        or capability.get("nonce_consumed") is not True
    ):
        raise AtomicHostLaunchError("ATOMIC_LAUNCH_RECEIPT_STATE_INVALID")

    _host_bindings(
        {field: host.get(field) for field in HOST_BINDING_FIELDS}
    )
    for field in HOST_RECEIPT_FIELDS - HOST_BINDING_FIELDS:
        if host.get(field) is not True:
            raise AtomicHostLaunchError("ATOMIC_LAUNCH_RECEIPT_STATE_INVALID")
    if (
        request.get("method") != "turn/start"
        or request.get("non_selection_params_preserved") is not True
        or request.get("exact_request_sent") is not True
    ):
        raise AtomicHostLaunchError("ATOMIC_LAUNCH_RECEIPT_STATE_INVALID")
    _request_id(request.get("request_id"))
    _sha256(request.get("thread_id_sha256"), "THREAD_ID_SHA256")
    model = _identifier(selection.get("model"), "SELECTION_MODEL")
    effort = _identifier(selection.get("effort"), "SELECTION_EFFORT")
    _sha256(response.get("turn_id_sha256"), "TURN_ID_SHA256")
    launched = _utc(response.get("launched_at_utc"), "LAUNCHED_AT")
    if (
        response.get("turn_status") != "inProgress"
        or response.get("turn_started") is not True
        or type(response.get("starts_consumed")) is not int
        or response["starts_consumed"] != 1
        or issued > launched
        or launched > expires
        or expires <= issued
        or (expires - issued).total_seconds()
        > MAX_CAPABILITY_LIFETIME_SECONDS
    ):
        raise AtomicHostLaunchError("ATOMIC_LAUNCH_RECEIPT_STATE_INVALID")
    if value.get("authority_boundary") != RECEIPT_AUTHORITY_BOUNDARY:
        raise AtomicHostLaunchError("ATOMIC_LAUNCH_RECEIPT_AUTHORITY_DRIFT")
    if value.get("privacy") != PRIVACY_BOUNDARY:
        raise AtomicHostLaunchError("ATOMIC_LAUNCH_RECEIPT_PRIVACY_DRIFT")

    if proposal is not None:
        verified = _verified_proposal(proposal)
        if (
            value["proposal_sha256"] != verified["proposal_sha256"]
            or value["plan_sha256"] != verified["plan_sha256"]
            or value["assignment_id"] != verified["assignment_id"]
            or capability["audience"]
            != verified["app_server_binding"]["client_info_name"]
            or model != verified["selection"]["requested_model"]
            or effort != verified["selection"]["requested_effort"]
        ):
            raise AtomicHostLaunchError(
                "ATOMIC_LAUNCH_RECEIPT_PROPOSAL_BINDING_INVALID"
            )
    return copy.deepcopy(value)


def build_launch_outcome_join(
    launch_receipt: dict[str, Any],
    outcome: dict[str, Any],
    *,
    proposal: dict[str, Any],
) -> dict[str, Any]:
    verified_proposal = _verified_proposal(proposal)
    receipt = validate_atomic_launch_receipt(
        launch_receipt,
        proposal=verified_proposal,
    )
    try:
        verified_outcome = validate_outcome(
            outcome,
            proposal=verified_proposal,
        )
    except Exception:
        raise AtomicHostLaunchError("OUTCOME_INVALID") from None
    if (
        receipt["proposal_sha256"] != verified_outcome["proposal_sha256"]
        or receipt["assignment_id"] != verified_outcome["assignment_id"]
        or receipt["response"]["turn_id_sha256"]
        != verified_outcome["identity"]["turn_id_sha256"]
        or receipt["selection"]["model"]
        != verified_outcome["model"]["requested_model"]
        or receipt["selection"]["effort"]
        != verified_outcome["model"]["requested_effort"]
    ):
        raise AtomicHostLaunchError("LAUNCH_OUTCOME_BINDING_INVALID")
    join: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "component_id": COMPONENT_ID,
        "status": "launch_outcome_joined",
        "launch_receipt_sha256": receipt["receipt_sha256"],
        "outcome_sha256": verified_outcome["outcome_sha256"],
        "proposal_sha256": receipt["proposal_sha256"],
        "assignment_id": receipt["assignment_id"],
        "experiment_id": verified_outcome["experiment"]["experiment_id"],
        "arm": verified_outcome["experiment"]["arm"],
        "turn_id_sha256": receipt["response"]["turn_id_sha256"],
        "requested_model": receipt["selection"]["model"],
        "requested_effort": receipt["selection"]["effort"],
        "resolved_model": verified_outcome["model"]["resolved_model"],
        "outcome_class": verified_outcome["terminal"]["outcome_class"],
    }
    join["join_sha256"] = json_digest(join)
    return validate_launch_outcome_join(
        join,
        launch_receipt=receipt,
        outcome=verified_outcome,
    )


def validate_launch_outcome_join(
    value: Any,
    *,
    launch_receipt: dict[str, Any] | None = None,
    outcome: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != JOIN_FIELDS:
        raise AtomicHostLaunchError("LAUNCH_OUTCOME_JOIN_SCHEMA_INVALID")
    digest = _sha256(value.get("join_sha256"), "LAUNCH_OUTCOME_JOIN_SHA256")
    view = copy.deepcopy(value)
    view.pop("join_sha256", None)
    if json_digest(view) != digest:
        raise AtomicHostLaunchError("LAUNCH_OUTCOME_JOIN_DIGEST_INVALID")
    if (
        value.get("schema_version") != SCHEMA_VERSION
        or value.get("component_id") != COMPONENT_ID
        or value.get("status") != "launch_outcome_joined"
    ):
        raise AtomicHostLaunchError("LAUNCH_OUTCOME_JOIN_SCHEMA_INVALID")
    for field in (
        "launch_receipt_sha256",
        "outcome_sha256",
        "proposal_sha256",
        "turn_id_sha256",
    ):
        _sha256(value.get(field), field.upper())
    for field in (
        "assignment_id",
        "experiment_id",
        "arm",
        "requested_model",
        "requested_effort",
        "resolved_model",
        "outcome_class",
    ):
        _identifier(value.get(field), field.upper())
    if value["arm"] not in {"ROUTER_AUTO", "FIXED_MODEL_CONTROL"}:
        raise AtomicHostLaunchError("LAUNCH_OUTCOME_JOIN_STATE_INVALID")
    if value["outcome_class"] not in {"success", "cancelled", "failure"}:
        raise AtomicHostLaunchError("LAUNCH_OUTCOME_JOIN_STATE_INVALID")
    if launch_receipt is not None:
        receipt = validate_atomic_launch_receipt(launch_receipt)
        if (
            value["launch_receipt_sha256"] != receipt["receipt_sha256"]
            or value["proposal_sha256"] != receipt["proposal_sha256"]
            or value["assignment_id"] != receipt["assignment_id"]
            or value["turn_id_sha256"]
            != receipt["response"]["turn_id_sha256"]
            or value["requested_model"] != receipt["selection"]["model"]
            or value["requested_effort"] != receipt["selection"]["effort"]
        ):
            raise AtomicHostLaunchError("LAUNCH_OUTCOME_JOIN_BINDING_INVALID")
    if outcome is not None:
        try:
            verified_outcome = validate_outcome(outcome)
        except Exception:
            raise AtomicHostLaunchError("OUTCOME_INVALID") from None
        if (
            value["outcome_sha256"] != verified_outcome["outcome_sha256"]
            or value["proposal_sha256"]
            != verified_outcome["proposal_sha256"]
            or value["assignment_id"] != verified_outcome["assignment_id"]
            or value["experiment_id"]
            != verified_outcome["experiment"]["experiment_id"]
            or value["arm"] != verified_outcome["experiment"]["arm"]
            or value["turn_id_sha256"]
            != verified_outcome["identity"]["turn_id_sha256"]
            or value["requested_model"]
            != verified_outcome["model"]["requested_model"]
            or value["requested_effort"]
            != verified_outcome["model"]["requested_effort"]
            or value["resolved_model"]
            != verified_outcome["model"]["resolved_model"]
            or value["outcome_class"]
            != verified_outcome["terminal"]["outcome_class"]
        ):
            raise AtomicHostLaunchError("LAUNCH_OUTCOME_JOIN_BINDING_INVALID")
    return copy.deepcopy(value)
