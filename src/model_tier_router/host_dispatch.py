"""Fail-closed host boundary for model-selected Codex app-server turns.

The advisory router never authorizes execution.  This module can prepare a
selection proposal and a standard ``turn/start`` request, but only a trusted
host driver can authenticate an out-of-band capability, consume its nonce and
start budget, send the exact request, and attest the result.
"""

from __future__ import annotations

import copy
import hashlib
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Protocol

from .schema_validation import (
    SchemaValidationError,
    validate_advisory_decision,
    validate_host_dispatch_intent as validate_intent_schema,
    validate_host_dispatch_proposal as validate_proposal_schema,
    validate_host_dispatch_receipt as validate_receipt_schema,
)
from .strict_json import canonical_json_bytes


MODEL_MAP_SCHEMA_VERSION = "model_tier_router_model_map_v1alpha1"
PROPOSAL_SCHEMA_VERSION = "model_tier_router_host_dispatch_proposal_v1alpha1"
INTENT_SCHEMA_VERSION = "model_tier_router_host_dispatch_intent_v1alpha1"
RECEIPT_SCHEMA_VERSION = "model_tier_router_host_dispatch_receipt_v1alpha1"
CAPABILITY_VERSION = "1.0.0"
MAX_CAPABILITY_BYTES = 65_536
MAX_CAPABILITY_LIFETIME_SECONDS = 600
MAX_HOST_LAUNCH_DELAY_SECONDS = 60

_IDENTIFIER = re.compile(r"[A-Za-z0-9._-]{1,160}")
_MODEL = re.compile(r"[A-Za-z0-9._:/+-]{1,200}")
_EFFORT = re.compile(r"[A-Za-z0-9._-]{1,64}")
_SHA256 = re.compile(r"[0-9a-f]{64}")

_MODEL_MAP_FIELDS = {"schema_version", "mapping_id", "profiles"}
_MODEL_MAP_ENTRY_FIELDS = {"model", "effort"}
_PROPOSAL_FIELDS = {
    "schema_version",
    "status",
    "advisory",
    "selection",
    "bindings",
    "authority_boundary",
    "privacy",
    "proposal_sha256",
}
_ADVISORY_FIELDS = {
    "decision_id",
    "decision_sha256",
    "selected_profile",
    "execution_authorized",
    "authorized_write_scope",
}
_SELECTION_FIELDS = {"model", "effort"}
_PROPOSAL_BINDING_FIELDS = {
    "mapping_id",
    "model_map_sha256",
    "model_catalog_sha256",
    "selected_model_entry_sha256",
    "origin_sha256",
    "protocol_schema_sha256",
}
_HOST_BINDING_FIELDS = {
    "host_request_binding_sha256",
    "host_context_binding_sha256",
    "host_instance_sha256",
    "connection_sha256",
    "consent_grant_sha256",
    "budget_lease_sha256",
}
_INTENT_FIELDS = {
    "schema_version",
    "status",
    "proposal_sha256",
    "request",
    "selection",
    "host_bindings",
    "authority_boundary",
    "privacy",
    "intent_sha256",
}
_INTENT_REQUEST_FIELDS = {
    "method",
    "request_id",
    "thread_id_sha256",
    "non_selection_params_sha256",
    "exact_request_sha256",
    "non_selection_params_preserved",
}
_TURN_START_ALLOWED_FIELDS = {
    "approvalPolicy",
    "approvalsReviewer",
    "clientUserMessageId",
    "collaborationMode",
    "cwd",
    "effort",
    "input",
    "model",
    "outputSchema",
    "personality",
    "sandboxPolicy",
    "serviceTier",
    "settings",
    "summary",
    "threadId",
}
_HOST_RESULT_FIELDS = {
    "capability_version",
    "capability_id_sha256",
    "capability_envelope_sha256",
    "issuer",
    "audience",
    "issued_at_utc",
    "expires_at_utc",
    "nonce_sha256",
    "proposal_sha256",
    "intent_sha256",
    "exact_request_sha256",
    "authorized_model",
    "authorized_effort",
    "maximum_model_starts",
    "starts_consumed",
    "capability_authenticated",
    "nonce_consumed",
    "catalog_validated",
    "entitlement_validated",
    "consent_validated",
    "budget_consumed",
    "request_binding_verified",
    "context_binding_verified",
    "permission_boundary_validated",
    "transport_identity_validated",
    "attestation_validated",
    "turn_id_sha256",
    "launched_at_utc",
}
_RECEIPT_FIELDS = {
    "schema_version",
    "status",
    "proposal_sha256",
    "intent_sha256",
    "capability",
    "host",
    "request",
    "selection",
    "response",
    "authority_boundary",
    "privacy",
    "receipt_sha256",
}
_CAPABILITY_RECEIPT_FIELDS = {
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
_HOST_RECEIPT_FIELDS = _HOST_BINDING_FIELDS | {
    "request_binding_verified",
    "context_binding_verified",
    "transport_identity_validated",
    "attestation_validated",
    "permission_boundary_validated",
    "catalog_validated",
    "entitlement_validated",
    "consent_validated",
    "budget_consumed",
}
_REQUEST_RECEIPT_FIELDS = {
    "method",
    "request_id",
    "thread_id_sha256",
    "non_selection_params_sha256",
    "exact_request_sha256",
    "non_selection_params_preserved",
    "exact_request_sent",
}
_RESPONSE_RECEIPT_FIELDS = {
    "turn_id_sha256",
    "turn_status",
    "turn_started",
    "starts_consumed",
    "launched_at_utc",
}

PROPOSAL_AUTHORITY_BOUNDARY = {
    "router_output_authorizes_launch": False,
    "host_capability_required": True,
    "host_catalog_revalidation_required": True,
    "host_entitlement_validation_required": True,
    "host_user_consent_required": True,
    "permission_expansion_authorized": False,
}
INTENT_AUTHORITY_BOUNDARY = {
    **PROPOSAL_AUTHORITY_BOUNDARY,
    "selection_only_override": True,
    "exact_request_binding_required": True,
}
RECEIPT_AUTHORITY_BOUNDARY = {
    "router_output_authorized_launch": False,
    "host_capability_authenticated": True,
    "host_nonce_consumed": True,
    "host_start_budget_consumed": True,
    "host_catalog_validated": True,
    "host_entitlement_validated": True,
    "host_user_consent_validated": True,
    "permission_expansion_authorized": False,
}
PRIVACY_BOUNDARY = {
    "prompt_persisted": False,
    "raw_request_persisted": False,
    "raw_capability_persisted": False,
    "raw_turn_id_persisted": False,
}


class HostDispatchError(ValueError):
    """A stable, non-sensitive host-dispatch contract failure."""


class HostAtomicTurnLauncher(Protocol):
    """Trusted host implementation of one verify-consume-send transaction."""

    def launch(
        self,
        capability_envelope: bytes,
        request: Mapping[str, Any],
        intent: Mapping[str, Any],
    ) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
        """Authenticate and consume the capability, send, and attest."""


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _closed_mapping(value: Any, fields: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise HostDispatchError(code)
    return copy.deepcopy(dict(value))


def _identifier(value: Any, code: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise HostDispatchError(code)
    return value


def _bounded_text(value: Any, code: str, maximum: int = 200) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise HostDispatchError(code)
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise HostDispatchError(code) from exc
    return value


def _sha256(value: Any, code: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise HostDispatchError(code)
    return value


def _request_id(value: Any) -> int:
    if (
        type(value) is not int
        or value < 0
        or value > 9_007_199_254_740_991
    ):
        raise HostDispatchError("TURN_START_REQUEST_ID_INVALID")
    return value


def _utc(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise HostDispatchError(code)
    try:
        result = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise HostDispatchError(code) from exc
    if result.tzinfo is None:
        raise HostDispatchError(code)
    return result.astimezone(timezone.utc)


def _aware_utc(value: Any, code: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise HostDispatchError(code)
    return value.astimezone(timezone.utc)


def _selection(value: Any, code: str) -> dict[str, str]:
    selection = _closed_mapping(value, _SELECTION_FIELDS, code)
    if not isinstance(selection["model"], str) or _MODEL.fullmatch(
        selection["model"]
    ) is None:
        raise HostDispatchError(code)
    if not isinstance(selection["effort"], str) or _EFFORT.fullmatch(
        selection["effort"]
    ) is None:
        raise HostDispatchError(code)
    return selection


def _validated_model_map(value: Any) -> tuple[dict[str, Any], str]:
    mapping = _closed_mapping(value, _MODEL_MAP_FIELDS, "MODEL_MAP_INVALID")
    if mapping["schema_version"] != MODEL_MAP_SCHEMA_VERSION:
        raise HostDispatchError("MODEL_MAP_SCHEMA_VERSION_INVALID")
    _identifier(mapping["mapping_id"], "MODEL_MAP_ID_INVALID")
    profiles = mapping["profiles"]
    if (
        not isinstance(profiles, Mapping)
        or not 1 <= len(profiles) <= 64
    ):
        raise HostDispatchError("MODEL_MAP_PROFILES_INVALID")
    normalized: dict[str, dict[str, str]] = {}
    for profile_id, raw_entry in profiles.items():
        profile = _identifier(profile_id, "MODEL_MAP_PROFILE_ID_INVALID")
        entry = _closed_mapping(
            raw_entry,
            _MODEL_MAP_ENTRY_FIELDS,
            "MODEL_MAP_ENTRY_INVALID",
        )
        if not isinstance(entry["model"], str) or _MODEL.fullmatch(
            entry["model"]
        ) is None:
            raise HostDispatchError("MODEL_MAP_MODEL_INVALID")
        if not isinstance(entry["effort"], str) or _EFFORT.fullmatch(
            entry["effort"]
        ) is None:
            raise HostDispatchError("MODEL_MAP_EFFORT_INVALID")
        normalized[profile] = entry
    mapping["profiles"] = {
        key: normalized[key] for key in sorted(normalized)
    }
    return mapping, _digest(mapping)


def _catalog_entry(
    catalog: Any,
    *,
    model: str,
    effort: str,
) -> tuple[str, str]:
    if not isinstance(catalog, Mapping):
        raise HostDispatchError("MODEL_CATALOG_INVALID")
    copied = copy.deepcopy(dict(catalog))
    try:
        catalog_sha256 = _digest(copied)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise HostDispatchError("MODEL_CATALOG_INVALID") from exc
    data = copied.get("data")
    if not isinstance(data, list) or not 1 <= len(data) <= 512:
        raise HostDispatchError("MODEL_CATALOG_INVALID")
    matches: list[dict[str, Any]] = []
    for raw_entry in data:
        if not isinstance(raw_entry, Mapping):
            raise HostDispatchError("MODEL_CATALOG_ENTRY_INVALID")
        entry = copy.deepcopy(dict(raw_entry))
        entry_model = entry.get("model", entry.get("id"))
        if entry_model == model:
            matches.append(entry)
    if len(matches) != 1:
        raise HostDispatchError("MODEL_CATALOG_SELECTION_INVALID")
    entry = matches[0]
    supported = entry.get("supportedReasoningEfforts")
    if not isinstance(supported, list) or not supported:
        raise HostDispatchError("MODEL_CATALOG_EFFORTS_INVALID")
    efforts: list[str] = []
    for item in supported:
        if not isinstance(item, Mapping):
            raise HostDispatchError("MODEL_CATALOG_EFFORTS_INVALID")
        candidate = item.get("reasoningEffort")
        if not isinstance(candidate, str) or _EFFORT.fullmatch(candidate) is None:
            raise HostDispatchError("MODEL_CATALOG_EFFORTS_INVALID")
        efforts.append(candidate)
    if len(efforts) != len(set(efforts)):
        raise HostDispatchError("MODEL_CATALOG_EFFORTS_INVALID")
    if effort not in efforts:
        raise HostDispatchError("MODEL_CATALOG_EFFORT_UNSUPPORTED")
    try:
        entry_sha256 = _digest(entry)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise HostDispatchError("MODEL_CATALOG_ENTRY_INVALID") from exc
    return entry_sha256, catalog_sha256


def build_dispatch_proposal(
    advisory_decision: Mapping[str, Any],
    model_map: Mapping[str, Any],
    model_catalog: Mapping[str, Any],
    *,
    origin_sha256: str,
    protocol_schema_sha256: str,
) -> dict[str, Any]:
    """Bind a non-authorizing Router recommendation to a host catalog entry."""

    try:
        decision = copy.deepcopy(dict(advisory_decision))
        validate_advisory_decision(decision)
    except (TypeError, ValueError, SchemaValidationError) as exc:
        raise HostDispatchError("ADVISORY_DECISION_INVALID") from exc
    if (
        decision.get("status") != "recommended"
        or decision.get("execution_authorized") is not False
        or decision.get("authorized_write_scope") != []
    ):
        raise HostDispatchError("ADVISORY_DECISION_NOT_DISPATCHABLE")
    profile = _identifier(
        decision.get("selected_profile"),
        "ADVISORY_SELECTED_PROFILE_INVALID",
    )
    trace = decision.get("trace")
    if not isinstance(trace, Mapping):
        raise HostDispatchError("ADVISORY_DECISION_DIGEST_INVALID")
    recorded_decision_sha256 = _sha256(
        trace.get("decision_digest"),
        "ADVISORY_DECISION_DIGEST_INVALID",
    )
    decision_view = copy.deepcopy(decision)
    decision_view["decision_id"] = None
    decision_view["trace"]["decision_digest"] = None
    decision_sha256 = _digest(decision_view)
    if (
        recorded_decision_sha256 != decision_sha256
        or decision.get("decision_id") != f"decision_{decision_sha256}"
    ):
        raise HostDispatchError("ADVISORY_DECISION_DIGEST_INVALID")
    mapping, mapping_sha256 = _validated_model_map(model_map)
    if profile not in mapping["profiles"]:
        raise HostDispatchError("MODEL_MAP_PROFILE_MISSING")
    selection = copy.deepcopy(mapping["profiles"][profile])
    catalog_entry_sha256, catalog_sha256 = _catalog_entry(
        model_catalog,
        model=selection["model"],
        effort=selection["effort"],
    )
    proposal: dict[str, Any] = {
        "schema_version": PROPOSAL_SCHEMA_VERSION,
        "status": "host_capability_required",
        "advisory": {
            "decision_id": _bounded_text(
                decision.get("decision_id"),
                "ADVISORY_DECISION_ID_INVALID",
            ),
            "decision_sha256": decision_sha256,
            "selected_profile": profile,
            "execution_authorized": False,
            "authorized_write_scope": [],
        },
        "selection": selection,
        "bindings": {
            "mapping_id": mapping["mapping_id"],
            "model_map_sha256": mapping_sha256,
            "model_catalog_sha256": catalog_sha256,
            "selected_model_entry_sha256": catalog_entry_sha256,
            "origin_sha256": _sha256(
                origin_sha256,
                "ORIGIN_DIGEST_INVALID",
            ),
            "protocol_schema_sha256": _sha256(
                protocol_schema_sha256,
                "PROTOCOL_SCHEMA_DIGEST_INVALID",
            ),
        },
        "authority_boundary": copy.deepcopy(PROPOSAL_AUTHORITY_BOUNDARY),
        "privacy": copy.deepcopy(PRIVACY_BOUNDARY),
    }
    proposal["proposal_sha256"] = _digest(proposal)
    return validate_dispatch_proposal(proposal)


def validate_dispatch_proposal(value: Any) -> dict[str, Any]:
    """Validate a closed proposal and its canonical SHA-256 binding."""

    proposal = _closed_mapping(
        value,
        _PROPOSAL_FIELDS,
        "DISPATCH_PROPOSAL_INVALID",
    )
    recorded = _sha256(
        proposal["proposal_sha256"],
        "DISPATCH_PROPOSAL_DIGEST_INVALID",
    )
    digest_view = copy.deepcopy(proposal)
    digest_view.pop("proposal_sha256")
    if recorded != _digest(digest_view):
        raise HostDispatchError("DISPATCH_PROPOSAL_DIGEST_INVALID")
    if (
        proposal["schema_version"] != PROPOSAL_SCHEMA_VERSION
        or proposal["status"] != "host_capability_required"
    ):
        raise HostDispatchError("DISPATCH_PROPOSAL_SCHEMA_INVALID")
    advisory = _closed_mapping(
        proposal["advisory"],
        _ADVISORY_FIELDS,
        "DISPATCH_PROPOSAL_ADVISORY_INVALID",
    )
    _bounded_text(advisory["decision_id"], "DISPATCH_PROPOSAL_ADVISORY_INVALID")
    _sha256(advisory["decision_sha256"], "DISPATCH_PROPOSAL_ADVISORY_INVALID")
    _identifier(
        advisory["selected_profile"],
        "DISPATCH_PROPOSAL_ADVISORY_INVALID",
    )
    if (
        advisory["execution_authorized"] is not False
        or advisory["authorized_write_scope"] != []
    ):
        raise HostDispatchError("DISPATCH_PROPOSAL_AUTHORITY_DRIFT")
    _selection(
        proposal["selection"],
        "DISPATCH_PROPOSAL_SELECTION_INVALID",
    )
    bindings = _closed_mapping(
        proposal["bindings"],
        _PROPOSAL_BINDING_FIELDS,
        "DISPATCH_PROPOSAL_BINDING_INVALID",
    )
    _identifier(bindings["mapping_id"], "DISPATCH_PROPOSAL_BINDING_INVALID")
    for field in _PROPOSAL_BINDING_FIELDS - {"mapping_id"}:
        _sha256(bindings[field], "DISPATCH_PROPOSAL_BINDING_INVALID")
    if proposal["authority_boundary"] != PROPOSAL_AUTHORITY_BOUNDARY:
        raise HostDispatchError("DISPATCH_PROPOSAL_AUTHORITY_DRIFT")
    if proposal["privacy"] != PRIVACY_BOUNDARY:
        raise HostDispatchError("DISPATCH_PROPOSAL_PRIVACY_DRIFT")
    try:
        validate_proposal_schema(proposal)
    except SchemaValidationError as exc:
        raise HostDispatchError("DISPATCH_PROPOSAL_SCHEMA_INVALID") from exc
    return proposal


def _turn_start_params(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise HostDispatchError("TURN_START_PARAMS_INVALID")
    params = copy.deepcopy(dict(value))
    if set(params) - _TURN_START_ALLOWED_FIELDS:
        raise HostDispatchError("TURN_START_PARAMS_UNSUPPORTED")
    if (
        not isinstance(params.get("threadId"), str)
        or not params["threadId"]
        or not isinstance(params.get("input"), list)
    ):
        raise HostDispatchError("TURN_START_PARAMS_INVALID")
    try:
        canonical_json_bytes(params)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise HostDispatchError("TURN_START_PARAMS_INVALID") from exc
    return params


def _host_bindings(value: Any) -> dict[str, str]:
    bindings = _closed_mapping(
        value,
        _HOST_BINDING_FIELDS,
        "HOST_BINDINGS_INVALID",
    )
    for field in _HOST_BINDING_FIELDS:
        _sha256(bindings[field], "HOST_BINDINGS_INVALID")
    return bindings


def build_atomic_launch_intent(
    proposal: Mapping[str, Any],
    base_params: Mapping[str, Any],
    host_bindings: Mapping[str, Any],
    *,
    request_id: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Prepare one standard turn/start request and a redacted binding intent."""

    verified = validate_dispatch_proposal(proposal)
    normalized_request_id = _request_id(request_id)
    bindings = _host_bindings(host_bindings)
    original = _turn_start_params(base_params)
    non_selection = copy.deepcopy(original)
    non_selection.pop("model", None)
    non_selection.pop("effort", None)
    compiled = copy.deepcopy(non_selection)
    compiled["model"] = verified["selection"]["model"]
    compiled["effort"] = verified["selection"]["effort"]
    if {
        key: value
        for key, value in compiled.items()
        if key not in {"model", "effort"}
    } != non_selection:
        raise HostDispatchError("NON_SELECTION_PARAMS_DRIFT")
    request = {
        "method": "turn/start",
        "id": normalized_request_id,
        "params": compiled,
    }
    intent: dict[str, Any] = {
        "schema_version": INTENT_SCHEMA_VERSION,
        "status": "host_capability_required",
        "proposal_sha256": verified["proposal_sha256"],
        "request": {
            "method": "turn/start",
            "request_id": normalized_request_id,
            "thread_id_sha256": hashlib.sha256(
                compiled["threadId"].encode("utf-8", errors="strict")
            ).hexdigest(),
            "non_selection_params_sha256": _digest(non_selection),
            "exact_request_sha256": _digest(request),
            "non_selection_params_preserved": True,
        },
        "selection": copy.deepcopy(verified["selection"]),
        "host_bindings": bindings,
        "authority_boundary": copy.deepcopy(INTENT_AUTHORITY_BOUNDARY),
        "privacy": copy.deepcopy(PRIVACY_BOUNDARY),
    }
    intent["intent_sha256"] = _digest(intent)
    return request, validate_atomic_launch_intent(intent, proposal=verified)


def validate_atomic_launch_intent(
    value: Any,
    *,
    proposal: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate a redacted launch intent and optional proposal binding."""

    intent = _closed_mapping(value, _INTENT_FIELDS, "LAUNCH_INTENT_INVALID")
    recorded = _sha256(intent["intent_sha256"], "LAUNCH_INTENT_DIGEST_INVALID")
    digest_view = copy.deepcopy(intent)
    digest_view.pop("intent_sha256")
    if recorded != _digest(digest_view):
        raise HostDispatchError("LAUNCH_INTENT_DIGEST_INVALID")
    if (
        intent["schema_version"] != INTENT_SCHEMA_VERSION
        or intent["status"] != "host_capability_required"
    ):
        raise HostDispatchError("LAUNCH_INTENT_SCHEMA_INVALID")
    _sha256(intent["proposal_sha256"], "LAUNCH_INTENT_PROPOSAL_INVALID")
    request = _closed_mapping(
        intent["request"],
        _INTENT_REQUEST_FIELDS,
        "LAUNCH_INTENT_REQUEST_INVALID",
    )
    if request["method"] != "turn/start":
        raise HostDispatchError("LAUNCH_INTENT_REQUEST_INVALID")
    _request_id(request["request_id"])
    for field in (
        "thread_id_sha256",
        "non_selection_params_sha256",
        "exact_request_sha256",
    ):
        _sha256(request[field], "LAUNCH_INTENT_REQUEST_INVALID")
    if request["non_selection_params_preserved"] is not True:
        raise HostDispatchError("LAUNCH_INTENT_NON_SELECTION_DRIFT")
    _selection(
        intent["selection"],
        "LAUNCH_INTENT_SELECTION_INVALID",
    )
    _host_bindings(intent["host_bindings"])
    if intent["authority_boundary"] != INTENT_AUTHORITY_BOUNDARY:
        raise HostDispatchError("LAUNCH_INTENT_AUTHORITY_DRIFT")
    if intent["privacy"] != PRIVACY_BOUNDARY:
        raise HostDispatchError("LAUNCH_INTENT_PRIVACY_DRIFT")
    try:
        validate_intent_schema(intent)
    except SchemaValidationError as exc:
        raise HostDispatchError("LAUNCH_INTENT_SCHEMA_INVALID") from exc
    if proposal is not None:
        verified = validate_dispatch_proposal(proposal)
        if (
            intent["proposal_sha256"] != verified["proposal_sha256"]
            or intent["selection"] != verified["selection"]
        ):
            raise HostDispatchError("LAUNCH_INTENT_PROPOSAL_DRIFT")
    return intent


def _validate_request_against_intent(
    value: Any,
    intent: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise HostDispatchError("TURN_START_REQUEST_INVALID")
    request = copy.deepcopy(dict(value))
    if set(request) != {"method", "id", "params"}:
        raise HostDispatchError("TURN_START_REQUEST_INVALID")
    if request["method"] != "turn/start":
        raise HostDispatchError("TURN_START_REQUEST_INVALID")
    if _request_id(request["id"]) != intent["request"]["request_id"]:
        raise HostDispatchError("TURN_START_REQUEST_BINDING_INVALID")
    params = _turn_start_params(request["params"])
    if {
        "model": params.get("model"),
        "effort": params.get("effort"),
    } != intent["selection"]:
        raise HostDispatchError("TURN_START_SELECTION_DRIFT")
    non_selection = copy.deepcopy(params)
    non_selection.pop("model", None)
    non_selection.pop("effort", None)
    thread_sha256 = hashlib.sha256(
        params["threadId"].encode("utf-8", errors="strict")
    ).hexdigest()
    if (
        _digest(non_selection)
        != intent["request"]["non_selection_params_sha256"]
        or _digest(request) != intent["request"]["exact_request_sha256"]
        or thread_sha256 != intent["request"]["thread_id_sha256"]
    ):
        raise HostDispatchError("TURN_START_REQUEST_BINDING_INVALID")
    return request


def _turn_start_response(value: Any) -> tuple[dict[str, Any], str]:
    if not isinstance(value, Mapping):
        raise HostDispatchError("TURN_START_RESPONSE_INVALID")
    response = copy.deepcopy(dict(value))
    if set(response) != {"turn"} or not isinstance(response["turn"], Mapping):
        raise HostDispatchError("TURN_START_RESPONSE_INVALID")
    turn = copy.deepcopy(dict(response["turn"]))
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
        raise HostDispatchError("TURN_START_RESPONSE_INVALID")
    if "itemsView" in turn and (
        not isinstance(turn["itemsView"], str)
        or turn["itemsView"] not in {
            "notLoaded",
            "summary",
            "full",
        }
    ):
        raise HostDispatchError("TURN_START_RESPONSE_INVALID")
    if (
        "startedAt" in turn
        and turn["startedAt"] is not None
        and (
            type(turn["startedAt"]) is not int
            or turn["startedAt"] < 0
        )
    ):
        raise HostDispatchError("TURN_START_RESPONSE_INVALID")
    turn_id = _bounded_text(turn.get("id"), "TURN_START_RESPONSE_INVALID")
    try:
        canonical_json_bytes(response)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise HostDispatchError("TURN_START_RESPONSE_INVALID") from exc
    return response, turn_id


def _validated_host_result(
    value: Any,
    *,
    proposal: Mapping[str, Any],
    intent: Mapping[str, Any],
    capability_envelope: bytes,
    turn_id: str,
    now: datetime,
) -> dict[str, Any]:
    result = _closed_mapping(
        value,
        _HOST_RESULT_FIELDS,
        "HOST_ATOMIC_LAUNCH_RESULT_INVALID",
    )
    if result["capability_version"] != CAPABILITY_VERSION:
        raise HostDispatchError("HOST_CAPABILITY_VERSION_INVALID")
    for field in (
        "capability_id_sha256",
        "capability_envelope_sha256",
        "nonce_sha256",
        "proposal_sha256",
        "intent_sha256",
        "exact_request_sha256",
        "turn_id_sha256",
    ):
        _sha256(result[field], "HOST_ATOMIC_LAUNCH_RESULT_INVALID")
    _bounded_text(result["issuer"], "HOST_ATOMIC_LAUNCH_RESULT_INVALID")
    _bounded_text(result["audience"], "HOST_ATOMIC_LAUNCH_RESULT_INVALID")
    issued = _utc(
        result["issued_at_utc"],
        "HOST_CAPABILITY_ISSUED_AT_INVALID",
    )
    expires = _utc(
        result["expires_at_utc"],
        "HOST_CAPABILITY_EXPIRES_AT_INVALID",
    )
    launched = _utc(
        result["launched_at_utc"],
        "HOST_LAUNCHED_AT_INVALID",
    )
    current = _aware_utc(now, "HOST_LAUNCH_TIME_INVALID")
    latest_launch = current + timedelta(seconds=MAX_HOST_LAUNCH_DELAY_SECONDS)
    if (
        expires <= issued
        or (expires - issued).total_seconds()
        > MAX_CAPABILITY_LIFETIME_SECONDS
        or not issued <= current < expires
        or not issued <= launched < expires
        or launched > latest_launch
    ):
        raise HostDispatchError("HOST_CAPABILITY_LIFETIME_INVALID")
    if result["capability_envelope_sha256"] != hashlib.sha256(
        capability_envelope
    ).hexdigest():
        raise HostDispatchError("HOST_CAPABILITY_ENVELOPE_DRIFT")
    if (
        result["proposal_sha256"] != proposal["proposal_sha256"]
        or result["intent_sha256"] != intent["intent_sha256"]
        or result["exact_request_sha256"]
        != intent["request"]["exact_request_sha256"]
        or result["authorized_model"] != intent["selection"]["model"]
        or result["authorized_effort"] != intent["selection"]["effort"]
        or result["turn_id_sha256"]
        != hashlib.sha256(turn_id.encode("utf-8", errors="strict")).hexdigest()
    ):
        raise HostDispatchError("HOST_ATOMIC_LAUNCH_BINDING_INVALID")
    if (
        type(result["maximum_model_starts"]) is not int
        or result["maximum_model_starts"] != 1
        or type(result["starts_consumed"]) is not int
        or result["starts_consumed"] != 1
    ):
        raise HostDispatchError("HOST_START_BUDGET_INVALID")
    required_true = _HOST_RESULT_FIELDS - {
        "capability_version",
        "capability_id_sha256",
        "capability_envelope_sha256",
        "issuer",
        "audience",
        "issued_at_utc",
        "expires_at_utc",
        "nonce_sha256",
        "proposal_sha256",
        "intent_sha256",
        "exact_request_sha256",
        "authorized_model",
        "authorized_effort",
        "maximum_model_starts",
        "starts_consumed",
        "turn_id_sha256",
        "launched_at_utc",
    }
    if any(result[field] is not True for field in required_true):
        raise HostDispatchError("HOST_ATOMIC_LAUNCH_ATTESTATION_INVALID")
    return result


def launch_atomic_turn_start(
    proposal: Mapping[str, Any],
    launch_intent: Mapping[str, Any],
    request: Mapping[str, Any],
    capability_envelope: bytes,
    launcher: HostAtomicTurnLauncher,
    *,
    now: datetime,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Delegate one authenticated, atomic turn/start transaction to the host."""

    current = _aware_utc(now, "HOST_LAUNCH_TIME_INVALID")
    verified_proposal = validate_dispatch_proposal(proposal)
    intent = validate_atomic_launch_intent(
        launch_intent,
        proposal=verified_proposal,
    )
    exact_request = _validate_request_against_intent(request, intent)
    if (
        not isinstance(capability_envelope, bytes)
        or not 1 <= len(capability_envelope) <= MAX_CAPABILITY_BYTES
    ):
        raise HostDispatchError("HOST_CAPABILITY_ENVELOPE_INVALID")
    launch = getattr(launcher, "launch", None)
    if not callable(launch):
        raise HostDispatchError("HOST_ATOMIC_LAUNCHER_REQUIRED")
    try:
        raw_result = launch(
            capability_envelope,
            copy.deepcopy(exact_request),
            copy.deepcopy(intent),
        )
    except Exception:
        raise HostDispatchError("HOST_ATOMIC_LAUNCH_FAILED") from None
    if not isinstance(raw_result, tuple) or len(raw_result) != 2:
        raise HostDispatchError("HOST_ATOMIC_LAUNCH_RESULT_INVALID")
    response, turn_id = _turn_start_response(raw_result[0])
    host_result = _validated_host_result(
        raw_result[1],
        proposal=verified_proposal,
        intent=intent,
        capability_envelope=capability_envelope,
        turn_id=turn_id,
        now=current,
    )
    receipt: dict[str, Any] = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "status": "host_started",
        "proposal_sha256": verified_proposal["proposal_sha256"],
        "intent_sha256": intent["intent_sha256"],
        "capability": {
            "capability_version": CAPABILITY_VERSION,
            "capability_id_sha256": host_result["capability_id_sha256"],
            "envelope_sha256": host_result["capability_envelope_sha256"],
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
            "budget_consumed": True,
        },
        "request": {
            **copy.deepcopy(intent["request"]),
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
        "authority_boundary": copy.deepcopy(RECEIPT_AUTHORITY_BOUNDARY),
        "privacy": copy.deepcopy(PRIVACY_BOUNDARY),
    }
    receipt["receipt_sha256"] = _digest(receipt)
    return response, validate_atomic_launch_receipt(
        receipt,
        proposal=verified_proposal,
        intent=intent,
    )


def validate_atomic_launch_receipt(
    value: Any,
    *,
    proposal: Mapping[str, Any] | None = None,
    intent: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate a redacted host launch receipt and optional causal bindings."""

    receipt = _closed_mapping(
        value,
        _RECEIPT_FIELDS,
        "HOST_LAUNCH_RECEIPT_INVALID",
    )
    recorded = _sha256(
        receipt["receipt_sha256"],
        "HOST_LAUNCH_RECEIPT_DIGEST_INVALID",
    )
    digest_view = copy.deepcopy(receipt)
    digest_view.pop("receipt_sha256")
    if recorded != _digest(digest_view):
        raise HostDispatchError("HOST_LAUNCH_RECEIPT_DIGEST_INVALID")
    if (
        receipt["schema_version"] != RECEIPT_SCHEMA_VERSION
        or receipt["status"] != "host_started"
    ):
        raise HostDispatchError("HOST_LAUNCH_RECEIPT_SCHEMA_INVALID")
    _sha256(receipt["proposal_sha256"], "HOST_LAUNCH_RECEIPT_INVALID")
    _sha256(receipt["intent_sha256"], "HOST_LAUNCH_RECEIPT_INVALID")
    capability = _closed_mapping(
        receipt["capability"],
        _CAPABILITY_RECEIPT_FIELDS,
        "HOST_LAUNCH_RECEIPT_CAPABILITY_INVALID",
    )
    if (
        capability["capability_version"] != CAPABILITY_VERSION
        or capability["verified"] is not True
        or capability["nonce_consumed"] is not True
    ):
        raise HostDispatchError("HOST_LAUNCH_RECEIPT_CAPABILITY_INVALID")
    for field in (
        "capability_id_sha256",
        "envelope_sha256",
        "nonce_sha256",
    ):
        _sha256(
            capability[field],
            "HOST_LAUNCH_RECEIPT_CAPABILITY_INVALID",
        )
    _bounded_text(
        capability["issuer"],
        "HOST_LAUNCH_RECEIPT_CAPABILITY_INVALID",
    )
    _bounded_text(
        capability["audience"],
        "HOST_LAUNCH_RECEIPT_CAPABILITY_INVALID",
    )
    _utc(
        capability["issued_at_utc"],
        "HOST_LAUNCH_RECEIPT_CAPABILITY_INVALID",
    )
    _utc(
        capability["expires_at_utc"],
        "HOST_LAUNCH_RECEIPT_CAPABILITY_INVALID",
    )
    host = _closed_mapping(
        receipt["host"],
        _HOST_RECEIPT_FIELDS,
        "HOST_LAUNCH_RECEIPT_HOST_INVALID",
    )
    for field in _HOST_BINDING_FIELDS:
        _sha256(host[field], "HOST_LAUNCH_RECEIPT_HOST_INVALID")
    if any(host[field] is not True for field in _HOST_RECEIPT_FIELDS - _HOST_BINDING_FIELDS):
        raise HostDispatchError("HOST_LAUNCH_RECEIPT_HOST_INVALID")
    request = _closed_mapping(
        receipt["request"],
        _REQUEST_RECEIPT_FIELDS,
        "HOST_LAUNCH_RECEIPT_REQUEST_INVALID",
    )
    if (
        request["method"] != "turn/start"
        or request["non_selection_params_preserved"] is not True
        or request["exact_request_sent"] is not True
    ):
        raise HostDispatchError("HOST_LAUNCH_RECEIPT_REQUEST_INVALID")
    _request_id(request["request_id"])
    for field in (
        "thread_id_sha256",
        "non_selection_params_sha256",
        "exact_request_sha256",
    ):
        _sha256(request[field], "HOST_LAUNCH_RECEIPT_REQUEST_INVALID")
    _selection(
        receipt["selection"],
        "HOST_LAUNCH_RECEIPT_SELECTION_INVALID",
    )
    response = _closed_mapping(
        receipt["response"],
        _RESPONSE_RECEIPT_FIELDS,
        "HOST_LAUNCH_RECEIPT_RESPONSE_INVALID",
    )
    _sha256(
        response["turn_id_sha256"],
        "HOST_LAUNCH_RECEIPT_RESPONSE_INVALID",
    )
    if (
        response["turn_status"] != "inProgress"
        or response["turn_started"] is not True
        or type(response["starts_consumed"]) is not int
        or response["starts_consumed"] != 1
    ):
        raise HostDispatchError("HOST_LAUNCH_RECEIPT_RESPONSE_INVALID")
    _utc(
        response["launched_at_utc"],
        "HOST_LAUNCH_RECEIPT_RESPONSE_INVALID",
    )
    if receipt["authority_boundary"] != RECEIPT_AUTHORITY_BOUNDARY:
        raise HostDispatchError("HOST_LAUNCH_RECEIPT_AUTHORITY_DRIFT")
    if receipt["privacy"] != PRIVACY_BOUNDARY:
        raise HostDispatchError("HOST_LAUNCH_RECEIPT_PRIVACY_DRIFT")
    try:
        validate_receipt_schema(receipt)
    except SchemaValidationError as exc:
        raise HostDispatchError("HOST_LAUNCH_RECEIPT_SCHEMA_INVALID") from exc
    if proposal is not None:
        verified_proposal = validate_dispatch_proposal(proposal)
        if (
            receipt["proposal_sha256"]
            != verified_proposal["proposal_sha256"]
            or receipt["selection"] != verified_proposal["selection"]
        ):
            raise HostDispatchError("HOST_LAUNCH_RECEIPT_PROPOSAL_DRIFT")
    if intent is not None:
        verified_intent = validate_atomic_launch_intent(
            intent,
            proposal=proposal,
        )
        if (
            receipt["intent_sha256"] != verified_intent["intent_sha256"]
            or receipt["request"]
            != {**verified_intent["request"], "exact_request_sent": True}
            or receipt["host"]
            != {
                **verified_intent["host_bindings"],
                "request_binding_verified": True,
                "context_binding_verified": True,
                "transport_identity_validated": True,
                "attestation_validated": True,
                "permission_boundary_validated": True,
                "catalog_validated": True,
                "entitlement_validated": True,
                "consent_validated": True,
                "budget_consumed": True,
            }
        ):
            raise HostDispatchError("HOST_LAUNCH_RECEIPT_INTENT_DRIFT")
    return receipt


__all__ = [
    "CAPABILITY_VERSION",
    "HostAtomicTurnLauncher",
    "HostDispatchError",
    "INTENT_SCHEMA_VERSION",
    "MODEL_MAP_SCHEMA_VERSION",
    "PROPOSAL_SCHEMA_VERSION",
    "RECEIPT_SCHEMA_VERSION",
    "build_atomic_launch_intent",
    "build_dispatch_proposal",
    "launch_atomic_turn_start",
    "validate_atomic_launch_intent",
    "validate_atomic_launch_receipt",
    "validate_dispatch_proposal",
]
