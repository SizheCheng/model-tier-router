from __future__ import annotations

import copy
import hashlib
import re
from collections import Counter
from typing import Any

from .authorized_dispatcher import (
    AuthorizedDispatchError,
    verify_plan,
)
from .config import json_digest


COMPONENT_ID = "MTR_CODEX_APP_SERVER_MODEL_EXPERIMENT_R1"
SCHEMA_VERSION = "1.0.0"
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,160}")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
ORIGIN_KINDS = {"product", "host_test", "integration_test"}
REROUTE_REASONS = {"highRiskCyberActivity"}
TERMINAL_STATUSES = {"completed", "interrupted", "failed"}
OUTCOME_CLASSES = {
    "completed": "success",
    "interrupted": "cancelled",
    "failed": "failure",
}

PROPOSAL_FIELDS = {
    "schema_version",
    "component_id",
    "status",
    "assignment_id",
    "plan_sha256",
    "experiment",
    "selection",
    "app_server_binding",
    "origin",
    "thread_start_override",
    "turn_start_override",
    "authority_boundary",
    "privacy",
    "proposal_sha256",
}
EXPERIMENT_FIELDS = {
    "experiment_id",
    "assignment_unit_sha256",
    "assignment_bucket",
    "arm",
}
SELECTION_FIELDS = {
    "router_profile",
    "requested_model",
    "requested_effort",
}
APP_SERVER_BINDING_FIELDS = {
    "protocol_version",
    "codex_cli_version",
    "protocol_schema_sha256",
    "model_list_response_sha256",
    "model_catalog_sha256",
    "selected_model_entry_sha256",
    "client_info_name",
    "catalog_complete",
}
ORIGIN_FIELDS = {
    "kind",
    "issuer",
    "attestation_requested",
    "attestation_evidence_sha256",
    "opaque_token_persisted",
}
AUTHORITY_BOUNDARY = {
    "execution_authorized": False,
    "host_catalog_and_entitlement_validation_required": True,
    "host_assignment_validation_required": True,
    "permission_expansion_authorized": False,
    "approval_policy_override_authorized": False,
    "sandbox_override_authorized": False,
    "network_expansion_authorized": False,
    "authorized_write_scope": [],
}
PRIVACY_BOUNDARY = {
    "raw_prompt_persisted": False,
    "raw_model_output_persisted": False,
    "raw_tool_output_persisted": False,
    "opaque_attestation_token_persisted": False,
}

OUTCOME_FIELDS = {
    "schema_version",
    "component_id",
    "status",
    "proposal_sha256",
    "assignment_id",
    "experiment",
    "origin",
    "identity",
    "model",
    "terminal",
    "usage",
    "items",
    "privacy",
    "outcome_sha256",
}
OUTCOME_EXPERIMENT_FIELDS = {"experiment_id", "arm"}
IDENTITY_FIELDS = {"thread_id_sha256", "turn_id_sha256"}
MODEL_OUTCOME_FIELDS = {
    "requested_model",
    "requested_effort",
    "resolved_model",
    "reroute_count",
    "reroutes",
}
REROUTE_FIELDS = {"from_model", "to_model", "reason"}
TERMINAL_FIELDS = {
    "turn_status",
    "outcome_class",
    "started_at_unix",
    "completed_at_unix",
    "duration_ms",
    "error_present",
}
USAGE_FIELDS = {
    "observed",
    "notification_count",
    "input_tokens",
    "cached_input_tokens",
    "output_tokens",
    "reasoning_output_tokens",
    "total_tokens",
    "model_context_window",
}
ITEM_FIELDS = {"count", "type_counts", "status_counts"}


class AppServerExperimentError(RuntimeError):
    pass


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="strict")).hexdigest()


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise AppServerExperimentError(f"{field}_INVALID")
    return value


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise AppServerExperimentError(f"{field}_INVALID")
    return value


def _nonnegative_integer(value: Any, field: str, *, nullable: bool = False) -> int | None:
    if nullable and value is None:
        return None
    if type(value) is not int or value < 0:
        raise AppServerExperimentError(f"{field}_INVALID")
    return value


def _safe_counter_key(value: Any) -> str:
    if isinstance(value, str) and IDENTIFIER_PATTERN.fullmatch(value) is not None:
        return value
    return "unknown"


def _validate_origin(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != ORIGIN_FIELDS:
        raise AppServerExperimentError("ORIGIN_SCHEMA_INVALID")
    if value.get("kind") not in ORIGIN_KINDS:
        raise AppServerExperimentError("ORIGIN_KIND_INVALID")
    issuer = value.get("issuer")
    if not isinstance(issuer, str) or not issuer.strip() or len(issuer) > 200:
        raise AppServerExperimentError("ORIGIN_ISSUER_INVALID")
    if value.get("attestation_requested") is not True:
        raise AppServerExperimentError("ORIGIN_ATTESTATION_REQUIRED")
    _sha256(
        value.get("attestation_evidence_sha256"),
        "ORIGIN_ATTESTATION_EVIDENCE_SHA256",
    )
    if value.get("opaque_token_persisted") is not False:
        raise AppServerExperimentError("ORIGIN_ATTESTATION_TOKEN_MUST_NOT_PERSIST")
    return copy.deepcopy(value)


def _normalized_model_catalog(value: Any) -> tuple[list[dict[str, Any]], str, str]:
    if (
        not isinstance(value, dict)
        or set(value) - {"data", "nextCursor"}
        or not isinstance(value.get("data"), list)
        or not 1 <= len(value["data"]) <= 256
    ):
        raise AppServerExperimentError("MODEL_LIST_RESPONSE_INVALID")
    if value.get("nextCursor") is not None:
        raise AppServerExperimentError("MODEL_CATALOG_INCOMPLETE")

    normalized: list[dict[str, Any]] = []
    seen_models: set[str] = set()
    for item in value["data"]:
        if not isinstance(item, dict):
            raise AppServerExperimentError("MODEL_CATALOG_ENTRY_INVALID")
        model = _identifier(item.get("model"), "MODEL_CATALOG_MODEL")
        entry_id = _identifier(item.get("id"), "MODEL_CATALOG_ID")
        if model in seen_models:
            raise AppServerExperimentError("MODEL_CATALOG_DUPLICATE")
        seen_models.add(model)
        hidden = item.get("hidden")
        is_default = item.get("isDefault")
        default_effort = item.get("defaultReasoningEffort")
        efforts = item.get("supportedReasoningEfforts")
        if type(hidden) is not bool or type(is_default) is not bool:
            raise AppServerExperimentError("MODEL_CATALOG_ENTRY_INVALID")
        default_effort = _identifier(
            default_effort, "MODEL_CATALOG_DEFAULT_EFFORT"
        )
        if (
            not isinstance(efforts, list)
            or not efforts
            or len(efforts) > 32
        ):
            raise AppServerExperimentError("MODEL_CATALOG_EFFORTS_INVALID")
        normalized_efforts: list[str] = []
        for effort in efforts:
            if not isinstance(effort, dict):
                raise AppServerExperimentError("MODEL_CATALOG_EFFORTS_INVALID")
            normalized_efforts.append(
                _identifier(
                    effort.get("reasoningEffort"),
                    "MODEL_CATALOG_EFFORT",
                )
            )
        if (
            len(set(normalized_efforts)) != len(normalized_efforts)
            or default_effort not in normalized_efforts
        ):
            raise AppServerExperimentError("MODEL_CATALOG_EFFORTS_INVALID")
        normalized.append(
            {
                "id": entry_id,
                "model": model,
                "hidden": hidden,
                "is_default": is_default,
                "default_reasoning_effort": default_effort,
                "supported_reasoning_efforts": sorted(normalized_efforts),
            }
        )
    normalized.sort(key=lambda item: item["model"])
    return normalized, json_digest(normalized), json_digest(value)


def build_app_server_proposal(
    plan: dict[str, Any],
    model_list_response: dict[str, Any],
    *,
    codex_cli_version: str,
    protocol_schema_sha256: str,
    client_info_name: str,
    origin_kind: str,
    origin_issuer: str,
    origin_attestation_sha256: str,
    attestation_requested: bool,
) -> dict[str, Any]:
    try:
        verified = verify_plan(plan)
    except AuthorizedDispatchError as exc:
        raise AppServerExperimentError("DISPATCH_PLAN_INVALID") from exc

    version = _identifier(codex_cli_version, "CODEX_CLI_VERSION")
    protocol_digest = _sha256(
        protocol_schema_sha256, "APP_SERVER_PROTOCOL_SCHEMA_SHA256"
    )
    client_name = _identifier(client_info_name, "APP_SERVER_CLIENT_INFO_NAME")
    if origin_kind not in ORIGIN_KINDS:
        raise AppServerExperimentError("ORIGIN_KIND_INVALID")
    if (
        not isinstance(origin_issuer, str)
        or not origin_issuer.strip()
        or len(origin_issuer) > 200
    ):
        raise AppServerExperimentError("ORIGIN_ISSUER_INVALID")
    attestation_digest = _sha256(
        origin_attestation_sha256, "ORIGIN_ATTESTATION_EVIDENCE_SHA256"
    )
    if attestation_requested is not True:
        raise AppServerExperimentError("ORIGIN_ATTESTATION_REQUIRED")

    catalog, catalog_digest, response_digest = _normalized_model_catalog(
        model_list_response
    )
    execution = verified.get("execution")
    experiment = verified.get("experiment")
    advisory = verified.get("router_advisory")
    if not all(
        isinstance(value, dict)
        for value in (execution, experiment, advisory)
    ):
        raise AppServerExperimentError("DISPATCH_PLAN_INVALID")
    selected_model = _identifier(
        execution.get("selected_model"), "SELECTED_MODEL"
    )
    selected_effort = _identifier(
        execution.get("reasoning_effort"), "SELECTED_EFFORT"
    )
    matching = [item for item in catalog if item["model"] == selected_model]
    if len(matching) != 1:
        raise AppServerExperimentError("SELECTED_MODEL_NOT_IN_HOST_CATALOG")
    catalog_entry = matching[0]
    if catalog_entry["hidden"] is not False:
        raise AppServerExperimentError("SELECTED_MODEL_HIDDEN")
    if selected_effort not in catalog_entry["supported_reasoning_efforts"]:
        raise AppServerExperimentError("SELECTED_EFFORT_NOT_SUPPORTED")

    proposal: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "component_id": COMPONENT_ID,
        "status": "host_review_required",
        "assignment_id": _identifier(
            verified.get("assignment_id"), "ASSIGNMENT_ID"
        ),
        "plan_sha256": _sha256(verified.get("plan_sha256"), "PLAN_SHA256"),
        "experiment": {
            "experiment_id": _identifier(
                experiment.get("experiment_id"), "EXPERIMENT_ID"
            ),
            "assignment_unit_sha256": _sha256(
                experiment.get("assignment_unit_sha256"),
                "ASSIGNMENT_UNIT_SHA256",
            ),
            "assignment_bucket": _nonnegative_integer(
                experiment.get("assignment_bucket"), "ASSIGNMENT_BUCKET"
            ),
            "arm": _identifier(experiment.get("arm"), "ASSIGNMENT_ARM"),
        },
        "selection": {
            "router_profile": _identifier(
                advisory.get("selected_profile"), "ROUTER_PROFILE"
            ),
            "requested_model": selected_model,
            "requested_effort": selected_effort,
        },
        "app_server_binding": {
            "protocol_version": "v2",
            "codex_cli_version": version,
            "protocol_schema_sha256": protocol_digest,
            "model_list_response_sha256": response_digest,
            "model_catalog_sha256": catalog_digest,
            "selected_model_entry_sha256": json_digest(catalog_entry),
            "client_info_name": client_name,
            "catalog_complete": True,
        },
        "origin": {
            "kind": origin_kind,
            "issuer": origin_issuer,
            "attestation_requested": True,
            "attestation_evidence_sha256": attestation_digest,
            "opaque_token_persisted": False,
        },
        "thread_start_override": {"model": selected_model},
        "turn_start_override": {
            "model": selected_model,
            "effort": selected_effort,
        },
        "authority_boundary": copy.deepcopy(AUTHORITY_BOUNDARY),
        "privacy": copy.deepcopy(PRIVACY_BOUNDARY),
    }
    proposal["proposal_sha256"] = json_digest(proposal)
    return validate_proposal(proposal)


def validate_proposal(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != PROPOSAL_FIELDS:
        raise AppServerExperimentError("PROPOSAL_SCHEMA_INVALID")
    recorded_digest = _sha256(value.get("proposal_sha256"), "PROPOSAL_SHA256")
    view = copy.deepcopy(value)
    view.pop("proposal_sha256", None)
    if json_digest(view) != recorded_digest:
        raise AppServerExperimentError("PROPOSAL_DIGEST_INVALID")
    if (
        value.get("schema_version") != SCHEMA_VERSION
        or value.get("component_id") != COMPONENT_ID
        or value.get("status") != "host_review_required"
    ):
        raise AppServerExperimentError("PROPOSAL_SCHEMA_INVALID")
    _identifier(value.get("assignment_id"), "ASSIGNMENT_ID")
    _sha256(value.get("plan_sha256"), "PLAN_SHA256")

    experiment = value.get("experiment")
    selection = value.get("selection")
    binding = value.get("app_server_binding")
    if (
        not isinstance(experiment, dict)
        or set(experiment) != EXPERIMENT_FIELDS
        or not isinstance(selection, dict)
        or set(selection) != SELECTION_FIELDS
        or not isinstance(binding, dict)
        or set(binding) != APP_SERVER_BINDING_FIELDS
    ):
        raise AppServerExperimentError("PROPOSAL_SCHEMA_INVALID")
    _identifier(experiment.get("experiment_id"), "EXPERIMENT_ID")
    _sha256(
        experiment.get("assignment_unit_sha256"), "ASSIGNMENT_UNIT_SHA256"
    )
    bucket = _nonnegative_integer(
        experiment.get("assignment_bucket"), "ASSIGNMENT_BUCKET"
    )
    if bucket is None or bucket > 9_999:
        raise AppServerExperimentError("ASSIGNMENT_BUCKET_INVALID")
    _identifier(experiment.get("arm"), "ASSIGNMENT_ARM")
    _identifier(selection.get("router_profile"), "ROUTER_PROFILE")
    model = _identifier(selection.get("requested_model"), "REQUESTED_MODEL")
    effort = _identifier(selection.get("requested_effort"), "REQUESTED_EFFORT")
    if binding.get("protocol_version") != "v2":
        raise AppServerExperimentError("APP_SERVER_PROTOCOL_VERSION_INVALID")
    _identifier(binding.get("codex_cli_version"), "CODEX_CLI_VERSION")
    _identifier(binding.get("client_info_name"), "APP_SERVER_CLIENT_INFO_NAME")
    for field in (
        "protocol_schema_sha256",
        "model_list_response_sha256",
        "model_catalog_sha256",
        "selected_model_entry_sha256",
    ):
        _sha256(binding.get(field), f"APP_SERVER_{field.upper()}")
    if binding.get("catalog_complete") is not True:
        raise AppServerExperimentError("MODEL_CATALOG_INCOMPLETE")
    _validate_origin(value.get("origin"))
    if value.get("thread_start_override") != {"model": model}:
        raise AppServerExperimentError("THREAD_START_OVERRIDE_DRIFT")
    if value.get("turn_start_override") != {
        "model": model,
        "effort": effort,
    }:
        raise AppServerExperimentError("TURN_START_OVERRIDE_DRIFT")
    if value.get("authority_boundary") != AUTHORITY_BOUNDARY:
        raise AppServerExperimentError("PROPOSAL_AUTHORITY_DRIFT")
    if value.get("privacy") != PRIVACY_BOUNDARY:
        raise AppServerExperimentError("PROPOSAL_PRIVACY_DRIFT")
    return copy.deepcopy(value)


def _token_breakdown(value: Any) -> dict[str, int]:
    fields = {
        "inputTokens",
        "cachedInputTokens",
        "outputTokens",
        "reasoningOutputTokens",
        "totalTokens",
    }
    if not isinstance(value, dict) or not fields <= set(value):
        raise AppServerExperimentError("TOKEN_USAGE_INVALID")
    normalized = {
        field: _nonnegative_integer(value.get(field), "TOKEN_USAGE")
        for field in fields
    }
    if normalized["cachedInputTokens"] > normalized["inputTokens"]:
        raise AppServerExperimentError("TOKEN_USAGE_INVALID")
    return normalized  # type: ignore[return-value]


def summarize_app_server_outcome(
    proposal: dict[str, Any],
    notifications: list[dict[str, Any]],
) -> dict[str, Any]:
    verified = validate_proposal(proposal)
    if (
        not isinstance(notifications, list)
        or not notifications
        or len(notifications) > 10_000
    ):
        raise AppServerExperimentError("APP_SERVER_NOTIFICATIONS_INVALID")

    requested_model = verified["selection"]["requested_model"]
    resolved_model = requested_model
    reroutes: list[dict[str, str]] = []
    thread_id: str | None = None
    turn_id: str | None = None
    completed_turn: dict[str, Any] | None = None
    usage: dict[str, Any] | None = None
    usage_notification_count = 0

    def bind_identity(params: dict[str, Any], *, nested_turn: bool = False) -> None:
        nonlocal thread_id, turn_id
        candidate_thread = params.get("threadId")
        candidate_turn = (
            params.get("turn", {}).get("id")
            if nested_turn and isinstance(params.get("turn"), dict)
            else params.get("turnId")
        )
        if (
            not isinstance(candidate_thread, str)
            or not candidate_thread
            or not isinstance(candidate_turn, str)
            or not candidate_turn
        ):
            raise AppServerExperimentError("APP_SERVER_IDENTITY_INVALID")
        if thread_id is not None and thread_id != candidate_thread:
            raise AppServerExperimentError("APP_SERVER_THREAD_ID_DRIFT")
        if turn_id is not None and turn_id != candidate_turn:
            raise AppServerExperimentError("APP_SERVER_TURN_ID_DRIFT")
        thread_id = candidate_thread
        turn_id = candidate_turn

    for notification in notifications:
        if (
            not isinstance(notification, dict)
            or set(notification) != {"method", "params"}
            or not isinstance(notification.get("params"), dict)
        ):
            raise AppServerExperimentError("APP_SERVER_NOTIFICATION_INVALID")
        method = notification.get("method")
        params = notification["params"]
        if method == "model/rerouted":
            if set(params) != {
                "threadId",
                "turnId",
                "fromModel",
                "toModel",
                "reason",
            }:
                raise AppServerExperimentError("MODEL_REROUTE_INVALID")
            bind_identity(params)
            from_model = _identifier(
                params.get("fromModel"), "MODEL_REROUTE_FROM"
            )
            to_model = _identifier(params.get("toModel"), "MODEL_REROUTE_TO")
            reason = params.get("reason")
            if reason not in REROUTE_REASONS:
                raise AppServerExperimentError("MODEL_REROUTE_REASON_INVALID")
            if from_model != resolved_model:
                raise AppServerExperimentError("MODEL_REROUTE_CHAIN_INVALID")
            reroutes.append(
                {
                    "from_model": from_model,
                    "to_model": to_model,
                    "reason": reason,
                }
            )
            resolved_model = to_model
        elif method == "thread/tokenUsage/updated":
            if set(params) != {"threadId", "turnId", "tokenUsage"}:
                raise AppServerExperimentError("TOKEN_USAGE_INVALID")
            bind_identity(params)
            token_usage = params.get("tokenUsage")
            if (
                not isinstance(token_usage, dict)
                or not {"last", "total"} <= set(token_usage)
            ):
                raise AppServerExperimentError("TOKEN_USAGE_INVALID")
            last = _token_breakdown(token_usage.get("last"))
            _token_breakdown(token_usage.get("total"))
            model_context = _nonnegative_integer(
                token_usage.get("modelContextWindow"),
                "MODEL_CONTEXT_WINDOW",
                nullable=True,
            )
            usage = {
                "input_tokens": last["inputTokens"],
                "cached_input_tokens": last["cachedInputTokens"],
                "output_tokens": last["outputTokens"],
                "reasoning_output_tokens": last["reasoningOutputTokens"],
                "total_tokens": last["totalTokens"],
                "model_context_window": model_context,
            }
            usage_notification_count += 1
        elif method == "turn/completed":
            if set(params) != {"threadId", "turn"}:
                raise AppServerExperimentError("TURN_COMPLETED_INVALID")
            bind_identity(params, nested_turn=True)
            if completed_turn is not None:
                raise AppServerExperimentError("TURN_COMPLETED_DUPLICATE")
            completed_turn = params["turn"]
        else:
            raise AppServerExperimentError("APP_SERVER_NOTIFICATION_NOT_ALLOWED")

    if completed_turn is None or thread_id is None or turn_id is None:
        raise AppServerExperimentError("TURN_COMPLETED_MISSING")
    turn_status = completed_turn.get("status")
    if turn_status not in TERMINAL_STATUSES:
        raise AppServerExperimentError("TURN_STATUS_INVALID")
    error = completed_turn.get("error")
    if turn_status == "failed":
        if not isinstance(error, dict):
            raise AppServerExperimentError("TURN_FAILURE_ERROR_MISSING")
    elif error is not None:
        raise AppServerExperimentError("TURN_ERROR_STATUS_DRIFT")

    items = completed_turn.get("items")
    if not isinstance(items, list) or len(items) > 100_000:
        raise AppServerExperimentError("TURN_ITEMS_INVALID")
    type_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    for item in items:
        if not isinstance(item, dict):
            raise AppServerExperimentError("TURN_ITEMS_INVALID")
        type_counts[_safe_counter_key(item.get("type"))] += 1
        if "status" in item:
            status_counts[_safe_counter_key(item.get("status"))] += 1

    usage_value = {
        "observed": usage is not None,
        "notification_count": usage_notification_count,
        "input_tokens": usage["input_tokens"] if usage is not None else None,
        "cached_input_tokens": (
            usage["cached_input_tokens"] if usage is not None else None
        ),
        "output_tokens": usage["output_tokens"] if usage is not None else None,
        "reasoning_output_tokens": (
            usage["reasoning_output_tokens"] if usage is not None else None
        ),
        "total_tokens": usage["total_tokens"] if usage is not None else None,
        "model_context_window": (
            usage["model_context_window"] if usage is not None else None
        ),
    }
    outcome: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "component_id": COMPONENT_ID,
        "status": "observed",
        "proposal_sha256": verified["proposal_sha256"],
        "assignment_id": verified["assignment_id"],
        "experiment": {
            "experiment_id": verified["experiment"]["experiment_id"],
            "arm": verified["experiment"]["arm"],
        },
        "origin": copy.deepcopy(verified["origin"]),
        "identity": {
            "thread_id_sha256": _sha256_text(thread_id),
            "turn_id_sha256": _sha256_text(turn_id),
        },
        "model": {
            "requested_model": requested_model,
            "requested_effort": verified["selection"]["requested_effort"],
            "resolved_model": resolved_model,
            "reroute_count": len(reroutes),
            "reroutes": reroutes,
        },
        "terminal": {
            "turn_status": turn_status,
            "outcome_class": OUTCOME_CLASSES[turn_status],
            "started_at_unix": _nonnegative_integer(
                completed_turn.get("startedAt"),
                "TURN_STARTED_AT",
                nullable=True,
            ),
            "completed_at_unix": _nonnegative_integer(
                completed_turn.get("completedAt"),
                "TURN_COMPLETED_AT",
                nullable=True,
            ),
            "duration_ms": _nonnegative_integer(
                completed_turn.get("durationMs"),
                "TURN_DURATION",
                nullable=True,
            ),
            "error_present": error is not None,
        },
        "usage": usage_value,
        "items": {
            "count": len(items),
            "type_counts": dict(sorted(type_counts.items())),
            "status_counts": dict(sorted(status_counts.items())),
        },
        "privacy": copy.deepcopy(PRIVACY_BOUNDARY),
    }
    outcome["outcome_sha256"] = json_digest(outcome)
    return validate_outcome(outcome, proposal=verified)


def validate_outcome(
    value: Any, *, proposal: dict[str, Any] | None = None
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != OUTCOME_FIELDS:
        raise AppServerExperimentError("OUTCOME_SCHEMA_INVALID")
    recorded_digest = _sha256(value.get("outcome_sha256"), "OUTCOME_SHA256")
    view = copy.deepcopy(value)
    view.pop("outcome_sha256", None)
    if json_digest(view) != recorded_digest:
        raise AppServerExperimentError("OUTCOME_DIGEST_INVALID")
    if (
        value.get("schema_version") != SCHEMA_VERSION
        or value.get("component_id") != COMPONENT_ID
        or value.get("status") != "observed"
    ):
        raise AppServerExperimentError("OUTCOME_SCHEMA_INVALID")
    _sha256(value.get("proposal_sha256"), "PROPOSAL_SHA256")
    _identifier(value.get("assignment_id"), "ASSIGNMENT_ID")

    experiment = value.get("experiment")
    identity = value.get("identity")
    model = value.get("model")
    terminal = value.get("terminal")
    usage = value.get("usage")
    items = value.get("items")
    if (
        not isinstance(experiment, dict)
        or set(experiment) != OUTCOME_EXPERIMENT_FIELDS
        or not isinstance(identity, dict)
        or set(identity) != IDENTITY_FIELDS
        or not isinstance(model, dict)
        or set(model) != MODEL_OUTCOME_FIELDS
        or not isinstance(terminal, dict)
        or set(terminal) != TERMINAL_FIELDS
        or not isinstance(usage, dict)
        or set(usage) != USAGE_FIELDS
        or not isinstance(items, dict)
        or set(items) != ITEM_FIELDS
    ):
        raise AppServerExperimentError("OUTCOME_SCHEMA_INVALID")
    _identifier(experiment.get("experiment_id"), "EXPERIMENT_ID")
    _identifier(experiment.get("arm"), "ASSIGNMENT_ARM")
    for field in IDENTITY_FIELDS:
        _sha256(identity.get(field), field.upper())
    requested_model = _identifier(
        model.get("requested_model"), "REQUESTED_MODEL"
    )
    _identifier(model.get("requested_effort"), "REQUESTED_EFFORT")
    resolved_model = _identifier(model.get("resolved_model"), "RESOLVED_MODEL")
    reroutes = model.get("reroutes")
    if (
        not isinstance(reroutes, list)
        or type(model.get("reroute_count")) is not int
        or model["reroute_count"] != len(reroutes)
    ):
        raise AppServerExperimentError("OUTCOME_REROUTES_INVALID")
    current_model = requested_model
    for reroute in reroutes:
        if not isinstance(reroute, dict) or set(reroute) != REROUTE_FIELDS:
            raise AppServerExperimentError("OUTCOME_REROUTES_INVALID")
        if reroute.get("reason") not in REROUTE_REASONS:
            raise AppServerExperimentError("OUTCOME_REROUTES_INVALID")
        if reroute.get("from_model") != current_model:
            raise AppServerExperimentError("OUTCOME_REROUTES_INVALID")
        current_model = _identifier(
            reroute.get("to_model"), "MODEL_REROUTE_TO"
        )
    if current_model != resolved_model:
        raise AppServerExperimentError("OUTCOME_RESOLVED_MODEL_DRIFT")

    turn_status = terminal.get("turn_status")
    if (
        turn_status not in TERMINAL_STATUSES
        or terminal.get("outcome_class") != OUTCOME_CLASSES[turn_status]
        or type(terminal.get("error_present")) is not bool
    ):
        raise AppServerExperimentError("OUTCOME_TERMINAL_INVALID")
    for field in ("started_at_unix", "completed_at_unix", "duration_ms"):
        _nonnegative_integer(
            terminal.get(field), f"OUTCOME_{field.upper()}", nullable=True
        )
    if (turn_status == "failed") is not terminal["error_present"]:
        raise AppServerExperimentError("OUTCOME_TERMINAL_INVALID")

    if (
        type(usage.get("observed")) is not bool
        or type(usage.get("notification_count")) is not int
        or usage["notification_count"] < 0
        or usage["observed"] != (usage["notification_count"] > 0)
    ):
        raise AppServerExperimentError("OUTCOME_USAGE_INVALID")
    token_fields = (
        "input_tokens",
        "cached_input_tokens",
        "output_tokens",
        "reasoning_output_tokens",
        "total_tokens",
        "model_context_window",
    )
    for field in token_fields:
        _nonnegative_integer(
            usage.get(field), f"OUTCOME_{field.upper()}", nullable=True
        )
    if usage["observed"]:
        if any(usage.get(field) is None for field in token_fields[:-1]):
            raise AppServerExperimentError("OUTCOME_USAGE_INVALID")
        if usage["cached_input_tokens"] > usage["input_tokens"]:
            raise AppServerExperimentError("OUTCOME_USAGE_INVALID")
    elif any(usage.get(field) is not None for field in token_fields):
        raise AppServerExperimentError("OUTCOME_USAGE_INVALID")

    if (
        type(items.get("count")) is not int
        or items["count"] < 0
        or not isinstance(items.get("type_counts"), dict)
        or not isinstance(items.get("status_counts"), dict)
    ):
        raise AppServerExperimentError("OUTCOME_ITEMS_INVALID")
    for counter in (items["type_counts"], items["status_counts"]):
        for key, count in counter.items():
            _identifier(key, "OUTCOME_ITEM_COUNTER_KEY")
            _nonnegative_integer(count, "OUTCOME_ITEM_COUNTER")
    if sum(items["type_counts"].values()) != items["count"]:
        raise AppServerExperimentError("OUTCOME_ITEMS_INVALID")
    if sum(items["status_counts"].values()) > items["count"]:
        raise AppServerExperimentError("OUTCOME_ITEMS_INVALID")
    _validate_origin(value.get("origin"))
    if value.get("privacy") != PRIVACY_BOUNDARY:
        raise AppServerExperimentError("OUTCOME_PRIVACY_DRIFT")

    if proposal is not None:
        verified_proposal = validate_proposal(proposal)
        if (
            value["proposal_sha256"] != verified_proposal["proposal_sha256"]
            or value["assignment_id"] != verified_proposal["assignment_id"]
            or value["experiment"]
            != {
                "experiment_id": verified_proposal["experiment"][
                    "experiment_id"
                ],
                "arm": verified_proposal["experiment"]["arm"],
            }
            or value["origin"] != verified_proposal["origin"]
            or requested_model
            != verified_proposal["selection"]["requested_model"]
        ):
            raise AppServerExperimentError("OUTCOME_PROPOSAL_BINDING_INVALID")
    return copy.deepcopy(value)
