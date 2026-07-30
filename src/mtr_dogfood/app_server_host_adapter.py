from __future__ import annotations

import copy
import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol

from .app_server_experiment import validate_proposal
from .config import json_digest


COMPONENT_ID = "MTR_CODEX_APP_SERVER_HOST_ADAPTER_R1"
SCHEMA_VERSION = "1.0.0"
MAX_CAPABILITY_BYTES = 65_536
MAX_CAPABILITY_LIFETIME_SECONDS = 600
MAX_MODEL_CATALOG_ENTRIES = 256
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,160}")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")

TURN_START_ALLOWED_FIELDS = {
    "personality",
    "approvalPolicy",
    "approvalsReviewer",
    "clientUserMessageId",
    "serviceTier",
    "cwd",
    "effort",
    "sandboxPolicy",
    "input",
    "model",
    "threadId",
    "outputSchema",
    "summary",
}
CAPABILITY_CLAIM_FIELDS = {
    "capability_version",
    "capability_id",
    "issuer",
    "audience",
    "issued_at_utc",
    "expires_at_utc",
    "nonce_sha256",
    "proposal_sha256",
    "plan_sha256",
    "assignment_id",
    "protocol_schema_sha256",
    "model_list_response_sha256",
    "selected_model_entry_sha256",
    "authorized_method",
    "authorized_model",
    "authorized_effort",
    "maximum_model_starts",
    "host_catalog_validated",
    "host_entitlement_validated",
    "host_assignment_validated",
    "host_attestation_validated",
    "permission_expansion_authorized",
    "approval_policy_override_authorized",
    "sandbox_override_authorized",
    "network_expansion_authorized",
    "authorized_write_scope",
}
RECEIPT_FIELDS = {
    "schema_version",
    "component_id",
    "status",
    "proposal_sha256",
    "capability",
    "request",
    "selection",
    "authority_boundary",
    "privacy",
    "receipt_sha256",
}
CAPABILITY_RECEIPT_FIELDS = {
    "capability_id_sha256",
    "envelope_sha256",
    "issuer",
    "audience",
    "nonce_sha256",
    "expires_at_utc",
    "verifier_invoked",
    "nonce_consumed",
}
REQUEST_RECEIPT_FIELDS = {
    "method",
    "request_id",
    "thread_id_sha256",
    "non_selection_params_preserved",
    "request_sent",
    "model_started",
}
SELECTION_FIELDS = {"model", "effort"}
AUTHORITY_BOUNDARY = {
    "execution_authorized_by_router": False,
    "model_selection_authorized_by_verified_host_capability": True,
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
    "raw_model_output_persisted": False,
    "raw_tool_output_persisted": False,
    "raw_error_text_persisted": False,
}


class AppServerHostAdapterError(RuntimeError):
    pass


class HostCapabilityVerifier(Protocol):
    """Host-owned cryptographic and issuer verification seam."""

    def verify(self, envelope: bytes) -> Mapping[str, Any]:
        """Return authenticated claims or raise without exposing secret details."""


class HostNonceConsumer(Protocol):
    """Host-owned replay-prevention seam."""

    def consume(self, nonce_sha256: str, expires_at_utc: str) -> bool:
        """Atomically consume a nonce and return true only on first use."""


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8", errors="strict"))


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise AppServerHostAdapterError(f"{field}_INVALID")
    return value


def _bounded_text(value: Any, field: str, *, maximum: int = 200) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise AppServerHostAdapterError(f"{field}_INVALID")
    return value


def _opaque_identifier(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or any(ord(character) < 32 for character in value)
    ):
        raise AppServerHostAdapterError(f"{field}_INVALID")
    return value


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise AppServerHostAdapterError(f"{field}_INVALID")
    return value


def _request_id(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= 2_147_483_647:
        raise AppServerHostAdapterError("REQUEST_ID_INVALID")
    return value


def _utc(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise AppServerHostAdapterError(f"{field}_INVALID")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise AppServerHostAdapterError(f"{field}_INVALID") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise AppServerHostAdapterError(f"{field}_INVALID")
    return parsed


def _aware_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise AppServerHostAdapterError("NOW_INVALID")
    return value.astimezone(timezone.utc)


def build_initialize_request(
    *,
    client_info_name: str,
    client_title: str,
    client_version: str,
    request_id: int = 0,
) -> dict[str, Any]:
    """Build the stable App Server initialize request without starting a model."""

    return {
        "method": "initialize",
        "id": _request_id(request_id),
        "params": {
            "clientInfo": {
                "name": _identifier(client_info_name, "CLIENT_INFO_NAME"),
                "title": _bounded_text(client_title, "CLIENT_TITLE"),
                "version": _bounded_text(
                    client_version,
                    "CLIENT_VERSION",
                    maximum=80,
                ),
            },
            "capabilities": {
                "experimentalApi": False,
                "requestAttestation": True,
            },
        },
    }


def build_initialized_notification() -> dict[str, Any]:
    return {"method": "initialized", "params": {}}


def build_model_list_request(
    *,
    request_id: int,
    cursor: str | None = None,
    limit: int = MAX_MODEL_CATALOG_ENTRIES,
) -> dict[str, Any]:
    if type(limit) is not int or not 1 <= limit <= MAX_MODEL_CATALOG_ENTRIES:
        raise AppServerHostAdapterError("MODEL_LIST_LIMIT_INVALID")
    if cursor is not None:
        cursor = _opaque_identifier(cursor, "MODEL_LIST_CURSOR")
    return {
        "method": "model/list",
        "id": _request_id(request_id),
        "params": {
            "cursor": cursor,
            "includeHidden": False,
            "limit": limit,
        },
    }


def merge_model_list_pages(pages: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge ordered picker-visible pages into the complete R3 catalog input."""

    if not isinstance(pages, list) or not pages:
        raise AppServerHostAdapterError("MODEL_LIST_PAGES_INVALID")
    entries: list[dict[str, Any]] = []
    seen_models: set[str] = set()
    seen_cursors: set[str] = set()
    for index, page in enumerate(pages):
        if (
            not isinstance(page, dict)
            or set(page) - {"data", "nextCursor"}
            or not isinstance(page.get("data"), list)
        ):
            raise AppServerHostAdapterError("MODEL_LIST_PAGE_INVALID")
        cursor = page.get("nextCursor")
        is_last = index == len(pages) - 1
        if is_last:
            if cursor is not None:
                raise AppServerHostAdapterError("MODEL_CATALOG_INCOMPLETE")
        else:
            cursor = _opaque_identifier(cursor, "MODEL_LIST_NEXT_CURSOR")
            if cursor in seen_cursors:
                raise AppServerHostAdapterError("MODEL_LIST_CURSOR_REPLAY")
            seen_cursors.add(cursor)
        for entry in page["data"]:
            if not isinstance(entry, dict):
                raise AppServerHostAdapterError("MODEL_CATALOG_ENTRY_INVALID")
            model = _identifier(entry.get("model"), "MODEL_CATALOG_MODEL")
            if model in seen_models:
                raise AppServerHostAdapterError("MODEL_CATALOG_DUPLICATE")
            seen_models.add(model)
            entries.append(copy.deepcopy(entry))
            if len(entries) > MAX_MODEL_CATALOG_ENTRIES:
                raise AppServerHostAdapterError("MODEL_CATALOG_TOO_LARGE")
    if not entries:
        raise AppServerHostAdapterError("MODEL_CATALOG_EMPTY")
    return {"data": entries, "nextCursor": None}


def _verified_claims(
    proposal: dict[str, Any],
    envelope: bytes,
    verifier: HostCapabilityVerifier,
    *,
    now: datetime,
) -> dict[str, Any]:
    if (
        not isinstance(envelope, bytes)
        or not 1 <= len(envelope) <= MAX_CAPABILITY_BYTES
    ):
        raise AppServerHostAdapterError("HOST_CAPABILITY_ENVELOPE_INVALID")
    verify = getattr(verifier, "verify", None)
    if not callable(verify):
        raise AppServerHostAdapterError("HOST_CAPABILITY_VERIFIER_REQUIRED")
    try:
        raw_claims = verify(envelope)
    except Exception:
        raise AppServerHostAdapterError(
            "HOST_CAPABILITY_VERIFICATION_FAILED"
        ) from None
    if not isinstance(raw_claims, Mapping):
        raise AppServerHostAdapterError("HOST_CAPABILITY_CLAIMS_INVALID")
    claims = copy.deepcopy(dict(raw_claims))
    if set(claims) != CAPABILITY_CLAIM_FIELDS:
        raise AppServerHostAdapterError("HOST_CAPABILITY_CLAIMS_INVALID")

    if claims.get("capability_version") != SCHEMA_VERSION:
        raise AppServerHostAdapterError("HOST_CAPABILITY_VERSION_INVALID")
    _opaque_identifier(claims.get("capability_id"), "HOST_CAPABILITY_ID")
    _bounded_text(claims.get("issuer"), "HOST_CAPABILITY_ISSUER")
    audience = _identifier(claims.get("audience"), "HOST_CAPABILITY_AUDIENCE")
    issued = _utc(claims.get("issued_at_utc"), "HOST_CAPABILITY_ISSUED_AT")
    expires = _utc(claims.get("expires_at_utc"), "HOST_CAPABILITY_EXPIRES_AT")
    current = _aware_utc(now)
    if (
        issued > current
        or current > expires
        or expires <= issued
        or (expires - issued).total_seconds()
        > MAX_CAPABILITY_LIFETIME_SECONDS
    ):
        raise AppServerHostAdapterError("HOST_CAPABILITY_EXPIRED_OR_INVALID")
    _sha256(claims.get("nonce_sha256"), "HOST_CAPABILITY_NONCE_SHA256")

    expected_bindings = {
        "proposal_sha256": proposal["proposal_sha256"],
        "plan_sha256": proposal["plan_sha256"],
        "assignment_id": proposal["assignment_id"],
        "protocol_schema_sha256": proposal["app_server_binding"][
            "protocol_schema_sha256"
        ],
        "model_list_response_sha256": proposal["app_server_binding"][
            "model_list_response_sha256"
        ],
        "selected_model_entry_sha256": proposal["app_server_binding"][
            "selected_model_entry_sha256"
        ],
        "authorized_model": proposal["selection"]["requested_model"],
        "authorized_effort": proposal["selection"]["requested_effort"],
    }
    for field, expected in expected_bindings.items():
        if claims.get(field) != expected:
            raise AppServerHostAdapterError(
                f"HOST_CAPABILITY_{field.upper()}_MISMATCH"
            )
    if audience != proposal["app_server_binding"]["client_info_name"]:
        raise AppServerHostAdapterError("HOST_CAPABILITY_AUDIENCE_MISMATCH")
    maximum_model_starts = claims.get("maximum_model_starts")
    if (
        claims.get("authorized_method") != "turn/start"
        or type(maximum_model_starts) is not int
        or maximum_model_starts != 1
    ):
        raise AppServerHostAdapterError("HOST_CAPABILITY_SCOPE_INVALID")
    for field in (
        "host_catalog_validated",
        "host_entitlement_validated",
        "host_assignment_validated",
        "host_attestation_validated",
    ):
        if claims.get(field) is not True:
            raise AppServerHostAdapterError(
                f"HOST_CAPABILITY_{field.upper()}_REQUIRED"
            )
    for field in (
        "permission_expansion_authorized",
        "approval_policy_override_authorized",
        "sandbox_override_authorized",
        "network_expansion_authorized",
    ):
        if claims.get(field) is not False:
            raise AppServerHostAdapterError(
                f"HOST_CAPABILITY_{field.upper()}_FORBIDDEN"
            )
    if claims.get("authorized_write_scope") != []:
        raise AppServerHostAdapterError(
            "HOST_CAPABILITY_WRITE_SCOPE_FORBIDDEN"
        )
    return claims


def compile_turn_start_request(
    proposal: dict[str, Any],
    capability_envelope: bytes,
    verifier: HostCapabilityVerifier,
    nonce_consumer: HostNonceConsumer,
    base_params: dict[str, Any],
    *,
    request_id: int,
    now: datetime,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Compile, but never send, one host-authorized turn/start request."""

    try:
        verified_proposal = validate_proposal(proposal)
    except Exception:
        raise AppServerHostAdapterError("PROPOSAL_INVALID") from None
    normalized_request_id = _request_id(request_id)
    if (
        not isinstance(base_params, dict)
        or set(base_params) - TURN_START_ALLOWED_FIELDS
        or "threadId" not in base_params
        or "input" not in base_params
    ):
        raise AppServerHostAdapterError("TURN_START_PARAMS_INVALID")
    thread_id = _opaque_identifier(
        base_params.get("threadId"),
        "TURN_START_THREAD_ID",
    )
    turn_input = base_params.get("input")
    if not isinstance(turn_input, list) or not 1 <= len(turn_input) <= 10_000:
        raise AppServerHostAdapterError("TURN_START_INPUT_INVALID")
    try:
        original = copy.deepcopy(base_params)
        non_selection_before = copy.deepcopy(original)
        non_selection_before.pop("model", None)
        non_selection_before.pop("effort", None)
        json_digest(non_selection_before)
    except Exception:
        raise AppServerHostAdapterError("TURN_START_PARAMS_INVALID") from None

    claims = _verified_claims(
        verified_proposal,
        capability_envelope,
        verifier,
        now=now,
    )
    compiled_params = copy.deepcopy(original)
    compiled_params["model"] = claims["authorized_model"]
    compiled_params["effort"] = claims["authorized_effort"]
    non_selection_after = copy.deepcopy(compiled_params)
    non_selection_after.pop("model", None)
    non_selection_after.pop("effort", None)
    if non_selection_before != non_selection_after:
        raise AppServerHostAdapterError("NON_SELECTION_PARAMS_DRIFT")

    consume = getattr(nonce_consumer, "consume", None)
    if not callable(consume):
        raise AppServerHostAdapterError("HOST_NONCE_CONSUMER_REQUIRED")
    try:
        consumed = consume(
            claims["nonce_sha256"],
            claims["expires_at_utc"],
        )
    except Exception:
        raise AppServerHostAdapterError("HOST_NONCE_CONSUME_FAILED") from None
    if consumed is not True:
        raise AppServerHostAdapterError("HOST_CAPABILITY_REPLAYED")

    request = {
        "method": "turn/start",
        "id": normalized_request_id,
        "params": compiled_params,
    }
    receipt: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "component_id": COMPONENT_ID,
        "status": "compiled_not_sent",
        "proposal_sha256": verified_proposal["proposal_sha256"],
        "capability": {
            "capability_id_sha256": _sha256_text(
                claims["capability_id"]
            ),
            "envelope_sha256": _sha256_bytes(capability_envelope),
            "issuer": claims["issuer"],
            "audience": claims["audience"],
            "nonce_sha256": claims["nonce_sha256"],
            "expires_at_utc": claims["expires_at_utc"],
            "verifier_invoked": True,
            "nonce_consumed": True,
        },
        "request": {
            "method": "turn/start",
            "request_id": normalized_request_id,
            "thread_id_sha256": _sha256_text(thread_id),
            "non_selection_params_preserved": True,
            "request_sent": False,
            "model_started": False,
        },
        "selection": {
            "model": claims["authorized_model"],
            "effort": claims["authorized_effort"],
        },
        "authority_boundary": copy.deepcopy(AUTHORITY_BOUNDARY),
        "privacy": copy.deepcopy(PRIVACY_BOUNDARY),
    }
    receipt["receipt_sha256"] = json_digest(receipt)
    return request, validate_launch_receipt(
        receipt,
        proposal=verified_proposal,
    )


def validate_launch_receipt(
    value: Any,
    *,
    proposal: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != RECEIPT_FIELDS:
        raise AppServerHostAdapterError("LAUNCH_RECEIPT_SCHEMA_INVALID")
    digest = _sha256(value.get("receipt_sha256"), "LAUNCH_RECEIPT_SHA256")
    view = copy.deepcopy(value)
    view.pop("receipt_sha256", None)
    if json_digest(view) != digest:
        raise AppServerHostAdapterError("LAUNCH_RECEIPT_DIGEST_INVALID")
    if (
        value.get("schema_version") != SCHEMA_VERSION
        or value.get("component_id") != COMPONENT_ID
        or value.get("status") != "compiled_not_sent"
    ):
        raise AppServerHostAdapterError("LAUNCH_RECEIPT_SCHEMA_INVALID")
    _sha256(value.get("proposal_sha256"), "PROPOSAL_SHA256")

    capability = value.get("capability")
    request = value.get("request")
    selection = value.get("selection")
    if (
        not isinstance(capability, dict)
        or set(capability) != CAPABILITY_RECEIPT_FIELDS
        or not isinstance(request, dict)
        or set(request) != REQUEST_RECEIPT_FIELDS
        or not isinstance(selection, dict)
        or set(selection) != SELECTION_FIELDS
    ):
        raise AppServerHostAdapterError("LAUNCH_RECEIPT_SCHEMA_INVALID")
    for field in (
        "capability_id_sha256",
        "envelope_sha256",
        "nonce_sha256",
    ):
        _sha256(capability.get(field), f"CAPABILITY_{field.upper()}")
    _bounded_text(capability.get("issuer"), "CAPABILITY_ISSUER")
    _identifier(capability.get("audience"), "CAPABILITY_AUDIENCE")
    _utc(capability.get("expires_at_utc"), "CAPABILITY_EXPIRES_AT")
    if (
        capability.get("verifier_invoked") is not True
        or capability.get("nonce_consumed") is not True
        or request.get("method") != "turn/start"
        or request.get("non_selection_params_preserved") is not True
        or request.get("request_sent") is not False
        or request.get("model_started") is not False
    ):
        raise AppServerHostAdapterError("LAUNCH_RECEIPT_STATE_INVALID")
    _request_id(request.get("request_id"))
    _sha256(request.get("thread_id_sha256"), "THREAD_ID_SHA256")
    model = _identifier(selection.get("model"), "SELECTION_MODEL")
    effort = _identifier(selection.get("effort"), "SELECTION_EFFORT")
    if value.get("authority_boundary") != AUTHORITY_BOUNDARY:
        raise AppServerHostAdapterError("LAUNCH_RECEIPT_AUTHORITY_DRIFT")
    if value.get("privacy") != PRIVACY_BOUNDARY:
        raise AppServerHostAdapterError("LAUNCH_RECEIPT_PRIVACY_DRIFT")

    if proposal is not None:
        try:
            verified_proposal = validate_proposal(proposal)
        except Exception:
            raise AppServerHostAdapterError("PROPOSAL_INVALID") from None
        if (
            value["proposal_sha256"]
            != verified_proposal["proposal_sha256"]
            or capability["audience"]
            != verified_proposal["app_server_binding"]["client_info_name"]
            or model != verified_proposal["selection"]["requested_model"]
            or effort != verified_proposal["selection"]["requested_effort"]
        ):
            raise AppServerHostAdapterError(
                "LAUNCH_RECEIPT_PROPOSAL_BINDING_INVALID"
            )
    return copy.deepcopy(value)
