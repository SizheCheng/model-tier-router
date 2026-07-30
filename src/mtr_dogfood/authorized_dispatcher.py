from __future__ import annotations

import argparse
import copy
import hashlib
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .codex_runner import build_command, run_codex
from .config import (
    canonical_json_bytes,
    is_contained,
    json_digest,
    load_json,
    normalized_path,
    same_path,
)
from .router_adapter import (
    DIGEST_FIELD,
    RouterDecisionError,
    map_profile,
    validate_decision,
)


COMPONENT_ID = "MTR_CODEX_AUTHORIZED_MODEL_DISPATCH_R2"
SCHEMA_VERSION = "1.0.0"
AUTHORIZATION_FIELDS = {
    "schema_version",
    "component_id",
    "authorization_id",
    "authorized_by",
    "issued_at_utc",
    "expires_at_utc",
    "experiment_id",
    "allowed_repository_roots",
    "allowed_models",
    "control_model",
    "control_reasoning_effort",
    "router_share_basis_points",
    "maximum_model_starts",
    "model_selection_authorized",
    "new_process_launch_authorized",
    "permission_expansion_authorized",
    "authorized_write_scope",
    "network_access_authorized",
    "model_service_data_export_authorized",
}
SAFE_RESULT_FIELDS = {
    "exit_code",
    "wall_time_seconds",
    "child_process_started",
    "model_execution_observed",
    "model_execution_completed",
    "timed_out",
    "cancelled",
    "command_count",
    "file_change_event_count",
    "input_tokens",
    "cached_input_tokens",
    "output_tokens",
    "reasoning_output_tokens",
    "rate_limit_event_count",
    "model_unavailable_event_count",
    "authentication_event_count",
    "output_schema_error_count",
    "host_policy_failure_count",
    "infrastructure_failure_class",
}
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,160}")
EFFORT_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,64}")


class AuthorizedDispatchError(RuntimeError):
    pass


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_utc(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise AuthorizedDispatchError(f"AUTHORIZATION_{field.upper()}_INVALID")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise AuthorizedDispatchError(f"AUTHORIZATION_{field.upper()}_INVALID") from exc
    if parsed.tzinfo is None:
        raise AuthorizedDispatchError(f"AUTHORIZATION_{field.upper()}_INVALID")
    return parsed.astimezone(timezone.utc)


def _string_list(value: Any, field: str, *, minimum: int = 1) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) < minimum
        or len(value) > 64
        or any(not isinstance(item, str) or not item for item in value)
        or len(set(value)) != len(value)
    ):
        raise AuthorizedDispatchError(f"AUTHORIZATION_{field.upper()}_INVALID")
    return list(value)


def validate_authorization(
    value: Any, *, now: datetime | None = None
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != AUTHORIZATION_FIELDS:
        raise AuthorizedDispatchError("AUTHORIZATION_SCHEMA_INVALID")
    if value.get("schema_version") != SCHEMA_VERSION:
        raise AuthorizedDispatchError("AUTHORIZATION_SCHEMA_VERSION_INVALID")
    if value.get("component_id") != COMPONENT_ID:
        raise AuthorizedDispatchError("AUTHORIZATION_COMPONENT_INVALID")
    for field in ("authorization_id", "experiment_id"):
        if not isinstance(value.get(field), str) or IDENTIFIER_PATTERN.fullmatch(
            value[field]
        ) is None:
            raise AuthorizedDispatchError(f"AUTHORIZATION_{field.upper()}_INVALID")
    if (
        not isinstance(value.get("authorized_by"), str)
        or not value["authorized_by"].strip()
        or len(value["authorized_by"]) > 200
    ):
        raise AuthorizedDispatchError("AUTHORIZATION_AUTHORIZED_BY_INVALID")
    issued = _parse_utc(value.get("issued_at_utc"), "issued_at_utc")
    expires = _parse_utc(value.get("expires_at_utc"), "expires_at_utc")
    current = (now or _utc_now()).astimezone(timezone.utc)
    if not issued <= current < expires:
        raise AuthorizedDispatchError("AUTHORIZATION_NOT_ACTIVE")
    repositories = _string_list(
        value.get("allowed_repository_roots"), "allowed_repository_roots"
    )
    normalized_repositories: list[str] = []
    for repository in repositories:
        candidate = Path(repository)
        if not candidate.is_absolute():
            raise AuthorizedDispatchError("AUTHORIZATION_REPOSITORY_NOT_ABSOLUTE")
        normalized_repositories.append(str(normalized_path(candidate)))
    if len({item.casefold() for item in normalized_repositories}) != len(
        normalized_repositories
    ):
        raise AuthorizedDispatchError("AUTHORIZATION_REPOSITORY_DUPLICATE")
    models = _string_list(value.get("allowed_models"), "allowed_models", minimum=2)
    control_model = value.get("control_model")
    if not isinstance(control_model, str) or control_model not in models:
        raise AuthorizedDispatchError("AUTHORIZATION_CONTROL_MODEL_INVALID")
    effort = value.get("control_reasoning_effort")
    if not isinstance(effort, str) or EFFORT_PATTERN.fullmatch(effort) is None:
        raise AuthorizedDispatchError("AUTHORIZATION_CONTROL_EFFORT_INVALID")
    share = value.get("router_share_basis_points")
    if type(share) is not int or not 1 <= share <= 9_999:
        raise AuthorizedDispatchError("AUTHORIZATION_ROUTER_SHARE_INVALID")
    maximum = value.get("maximum_model_starts")
    if type(maximum) is not int or not 1 <= maximum <= 10_000:
        raise AuthorizedDispatchError("AUTHORIZATION_MODEL_START_BUDGET_INVALID")
    if value.get("model_selection_authorized") is not True:
        raise AuthorizedDispatchError("MODEL_SELECTION_NOT_AUTHORIZED")
    if value.get("new_process_launch_authorized") is not True:
        raise AuthorizedDispatchError("NEW_PROCESS_LAUNCH_NOT_AUTHORIZED")
    if value.get("permission_expansion_authorized") is not False:
        raise AuthorizedDispatchError("PERMISSION_EXPANSION_MUST_REMAIN_FALSE")
    if value.get("authorized_write_scope") != []:
        raise AuthorizedDispatchError("WRITE_SCOPE_MUST_REMAIN_EMPTY")
    if value.get("network_access_authorized") is not False:
        raise AuthorizedDispatchError("NETWORK_ACCESS_MUST_REMAIN_FALSE")
    if value.get("model_service_data_export_authorized") is not True:
        raise AuthorizedDispatchError(
            "MODEL_SERVICE_DATA_EXPORT_NOT_AUTHORIZED"
        )
    normalized = copy.deepcopy(value)
    normalized["allowed_repository_roots"] = normalized_repositories
    normalized["authorization_sha256"] = json_digest(normalized)
    return normalized


def _assignment_bucket(experiment_id: str, assignment_unit: str) -> int:
    raw = f"{experiment_id}\0{assignment_unit}".encode("utf-8", errors="strict")
    return int.from_bytes(hashlib.sha256(raw).digest()[:8], "big") % 10_000


def _repository_allowed(repository: str | Path, allowed: list[str]) -> str:
    matches = [candidate for candidate in allowed if same_path(repository, candidate)]
    if len(matches) != 1:
        raise AuthorizedDispatchError("REPOSITORY_OUTSIDE_AUTHORIZED_ALLOWLIST")
    return str(normalized_path(matches[0]))


def plan_dispatch(
    authorization: dict[str, Any],
    router_decision: dict[str, Any],
    model_map: dict[str, Any],
    *,
    repository: str | Path,
    assignment_unit: str,
    model_start_ordinal: int,
    now: datetime | None = None,
) -> dict[str, Any]:
    current = (now or _utc_now()).astimezone(timezone.utc)
    authorized = validate_authorization(authorization, now=current)
    if not isinstance(assignment_unit, str) or not assignment_unit or len(
        assignment_unit
    ) > 512:
        raise AuthorizedDispatchError("ASSIGNMENT_UNIT_INVALID")
    if (
        type(model_start_ordinal) is not int
        or not 1 <= model_start_ordinal <= authorized["maximum_model_starts"]
    ):
        raise AuthorizedDispatchError("MODEL_START_ORDINAL_OUT_OF_BUDGET")
    profiles = model_map.get("logical_profiles") if isinstance(model_map, dict) else None
    if not isinstance(profiles, dict) or not profiles:
        raise AuthorizedDispatchError("MODEL_MAP_INVALID")
    mapping_version = model_map.get("mapping_version")
    if (
        not isinstance(mapping_version, str)
        or IDENTIFIER_PATTERN.fullmatch(mapping_version) is None
    ):
        raise AuthorizedDispatchError("MODEL_MAP_INVALID")
    model_map_sha256 = json_digest(model_map)
    try:
        advisory = validate_decision(router_decision, set(profiles))
    except RouterDecisionError as exc:
        raise AuthorizedDispatchError("ROUTER_ADVISORY_INVALID") from exc
    if advisory.get("status") != "recommended":
        raise AuthorizedDispatchError("ROUTER_DID_NOT_RECOMMEND")
    selected_profile = advisory["selected_profile"]
    bucket = _assignment_bucket(authorized["experiment_id"], assignment_unit)
    if bucket < authorized["router_share_basis_points"]:
        arm = "ROUTER_AUTO"
        selected_model, reasoning_effort = map_profile(model_map, selected_profile)
    else:
        arm = "FIXED_MODEL_CONTROL"
        selected_model = authorized["control_model"]
        reasoning_effort = authorized["control_reasoning_effort"]
    if selected_model not in authorized["allowed_models"]:
        raise AuthorizedDispatchError("SELECTED_MODEL_OUTSIDE_AUTHORIZATION")
    repository_root = _repository_allowed(
        repository, authorized["allowed_repository_roots"]
    )
    assignment_unit_sha256 = hashlib.sha256(
        assignment_unit.encode("utf-8", errors="strict")
    ).hexdigest()
    assignment_material = {
        "authorization_sha256": authorized["authorization_sha256"],
        "router_decision_sha256": advisory[DIGEST_FIELD],
        "model_map_sha256": model_map_sha256,
        "experiment_id": authorized["experiment_id"],
        "assignment_unit_sha256": assignment_unit_sha256,
        "model_start_ordinal": model_start_ordinal,
    }
    assignment_id = json_digest(assignment_material)[:32]
    plan: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "component_id": COMPONENT_ID,
        "status": "planned",
        "assignment_id": assignment_id,
        "created_at_utc": _utc_text(current),
        "authorization": {
            "authorization_id": authorized["authorization_id"],
            "authorization_sha256": authorized["authorization_sha256"],
            "expires_at_utc": authorized["expires_at_utc"],
        },
        "experiment": {
            "experiment_id": authorized["experiment_id"],
            "assignment_unit_sha256": assignment_unit_sha256,
            "router_share_basis_points": authorized["router_share_basis_points"],
            "assignment_bucket": bucket,
            "arm": arm,
        },
        "router_advisory": {
            "selected_profile": selected_profile,
            "decision_sha256": advisory[DIGEST_FIELD],
            "execution_authorized": False,
            "authorized_write_scope": [],
        },
        "model_mapping": {
            "mapping_version": mapping_version,
            "model_map_sha256": model_map_sha256,
        },
        "execution": {
            "repository": repository_root,
            "selected_model": selected_model,
            "reasoning_effort": reasoning_effort,
            "model_start_ordinal": model_start_ordinal,
            "maximum_model_starts": authorized["maximum_model_starts"],
        },
        "authority_boundary": {
            "model_selection_authorized": True,
            "new_process_launch_authorized": True,
            "permission_expansion_authorized": False,
            "authorized_write_scope": [],
            "network_access_authorized": False,
            "model_service_data_export_authorized": True,
        },
    }
    plan["plan_sha256"] = json_digest(plan)
    return plan


def verify_plan(
    plan: Any,
    authorization: dict[str, Any] | None = None,
    *,
    router_decision: dict[str, Any] | None = None,
    model_map: dict[str, Any] | None = None,
    assignment_unit: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    if not isinstance(plan, dict):
        raise AuthorizedDispatchError("DISPATCH_PLAN_INVALID")
    recorded = plan.get("plan_sha256")
    if not isinstance(recorded, str):
        raise AuthorizedDispatchError("DISPATCH_PLAN_DIGEST_MISSING")
    view = copy.deepcopy(plan)
    view.pop("plan_sha256", None)
    if recorded != json_digest(view):
        raise AuthorizedDispatchError("DISPATCH_PLAN_DIGEST_INVALID")
    if (
        plan.get("schema_version") != SCHEMA_VERSION
        or plan.get("component_id") != COMPONENT_ID
        or plan.get("status") != "planned"
    ):
        raise AuthorizedDispatchError("DISPATCH_PLAN_SCHEMA_INVALID")
    boundary = plan.get("authority_boundary")
    if not isinstance(boundary, dict) or boundary != {
        "model_selection_authorized": True,
        "new_process_launch_authorized": True,
        "permission_expansion_authorized": False,
        "authorized_write_scope": [],
        "network_access_authorized": False,
        "model_service_data_export_authorized": True,
    }:
        raise AuthorizedDispatchError("DISPATCH_PLAN_AUTHORITY_DRIFT")
    if authorization is not None:
        current = (now or _utc_now()).astimezone(timezone.utc)
        authorized = validate_authorization(authorization, now=current)
        plan_authorization = plan.get("authorization")
        experiment = plan.get("experiment")
        model_mapping = plan.get("model_mapping")
        execution = plan.get("execution")
        if not all(
            isinstance(item, dict)
            for item in (plan_authorization, experiment, model_mapping, execution)
        ):
            raise AuthorizedDispatchError("DISPATCH_PLAN_SCHEMA_INVALID")
        if (
            not isinstance(execution.get("repository"), str)
            or not isinstance(execution.get("selected_model"), str)
            or not isinstance(execution.get("reasoning_effort"), str)
        ):
            raise AuthorizedDispatchError("DISPATCH_PLAN_SCHEMA_INVALID")
        if plan_authorization != {
            "authorization_id": authorized["authorization_id"],
            "authorization_sha256": authorized["authorization_sha256"],
            "expires_at_utc": authorized["expires_at_utc"],
        }:
            raise AuthorizedDispatchError("DISPATCH_PLAN_AUTHORIZATION_DRIFT")
        if (
            experiment.get("experiment_id") != authorized["experiment_id"]
            or experiment.get("router_share_basis_points")
            != authorized["router_share_basis_points"]
        ):
            raise AuthorizedDispatchError("DISPATCH_PLAN_EXPERIMENT_DRIFT")
        if execution.get("selected_model") not in authorized["allowed_models"]:
            raise AuthorizedDispatchError("DISPATCH_PLAN_MODEL_NOT_AUTHORIZED")
        _repository_allowed(
            execution.get("repository"), authorized["allowed_repository_roots"]
        )
        if (
            execution.get("maximum_model_starts")
            != authorized["maximum_model_starts"]
            or type(execution.get("model_start_ordinal")) is not int
            or not 1 <= execution["model_start_ordinal"] <= authorized["maximum_model_starts"]
        ):
            raise AuthorizedDispatchError("DISPATCH_PLAN_BUDGET_DRIFT")
        if (
            router_decision is None
            or model_map is None
            or assignment_unit is None
        ):
            raise AuthorizedDispatchError(
                "DISPATCH_PLAN_SEMANTIC_CONTEXT_MISSING"
            )
        expected = plan_dispatch(
            authorization,
            router_decision,
            model_map,
            repository=execution["repository"],
            assignment_unit=assignment_unit,
            model_start_ordinal=execution["model_start_ordinal"],
            now=current,
        )
        for field in (
            "assignment_id",
            "authorization",
            "experiment",
            "router_advisory",
            "model_mapping",
            "execution",
            "authority_boundary",
        ):
            if plan.get(field) != expected[field]:
                raise AuthorizedDispatchError(
                    "DISPATCH_PLAN_ASSIGNMENT_DRIFT"
                )
    return copy.deepcopy(plan)


def build_dispatch_command(
    plan: dict[str, Any],
    *,
    authorization: dict[str, Any],
    router_decision: dict[str, Any],
    model_map: dict[str, Any],
    assignment_unit: str,
    worktree: str | Path,
    output_schema: str | Path,
    output_file: str | Path,
    now: datetime | None = None,
) -> list[str]:
    verified = verify_plan(
        plan,
        authorization,
        router_decision=router_decision,
        model_map=model_map,
        assignment_unit=assignment_unit,
        now=now,
    )
    execution = verified["execution"]
    if not same_path(worktree, execution["repository"]):
        raise AuthorizedDispatchError("DISPATCH_WORKTREE_DRIFT")
    for path in (output_schema, output_file):
        if not is_contained(worktree, path):
            raise AuthorizedDispatchError("DISPATCH_OUTPUT_PATH_OUTSIDE_WORKTREE")
    command = build_command(
        worktree,
        execution["selected_model"],
        execution["reasoning_effort"],
        output_schema,
        output_file,
    )
    if command.count("--model") != 1:
        raise AuthorizedDispatchError("DISPATCH_MODEL_ARGUMENT_INVALID")
    model_index = command.index("--model")
    if command[model_index + 1] != execution["selected_model"]:
        raise AuthorizedDispatchError("DISPATCH_MODEL_ARGUMENT_DRIFT")
    return command


def _write_exclusive(path: Path, value: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = canonical_json_bytes(value)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            path.unlink(missing_ok=True)
        finally:
            raise
    return path


def _authorization_state_root(
    data_root: str | Path, authorization_id: str
) -> Path:
    if IDENTIFIER_PATTERN.fullmatch(authorization_id) is None:
        raise AuthorizedDispatchError("AUTHORIZATION_ID_INVALID")
    root = Path(data_root)
    if not root.is_absolute():
        raise AuthorizedDispatchError("DISPATCH_DATA_ROOT_NOT_ABSOLUTE")
    return (
        normalized_path(root)
        / "authorized-dispatch-r2"
        / authorization_id
    )


def _kill_switch_path(data_root: str | Path, authorization_id: str) -> Path:
    return _authorization_state_root(data_root, authorization_id) / "STOP.json"


def activate_kill_switch(
    data_root: str | Path,
    authorization_id: str,
    *,
    reason: str = "operator-request",
    now: datetime | None = None,
) -> Path:
    if IDENTIFIER_PATTERN.fullmatch(reason) is None:
        raise AuthorizedDispatchError("KILL_SWITCH_REASON_INVALID")
    path = _kill_switch_path(data_root, authorization_id)
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "component_id": COMPONENT_ID,
        "status": "stopped",
        "authorization_id": authorization_id,
        "reason": reason,
        "stopped_at_utc": _utc_text(
            (now or _utc_now()).astimezone(timezone.utc)
        ),
    }
    try:
        return _write_exclusive(path, receipt)
    except FileExistsError:
        return path


def _assert_dispatch_enabled(
    data_root: str | Path,
    authorization: dict[str, Any],
    *,
    now: datetime | None = None,
) -> tuple[dict[str, Any], Path]:
    current = (now or _utc_now()).astimezone(timezone.utc)
    authorized = validate_authorization(authorization, now=current)
    path = _kill_switch_path(data_root, authorized["authorization_id"])
    if os.path.lexists(path):
        raise AuthorizedDispatchError("DISPATCH_KILL_SWITCH_ACTIVE")
    return authorized, path


def preflight_authorized_dispatch(
    authorization: dict[str, Any],
    router_decision: dict[str, Any],
    model_map: dict[str, Any],
    *,
    repository: str | Path,
    assignment_unit: str,
    data_root: str | Path,
    output_schema: str | Path,
    output_file: str | Path,
    model_start_ordinal: int,
    now: datetime | None = None,
) -> dict[str, Any]:
    current = (now or _utc_now()).astimezone(timezone.utc)
    _authorized, stop_path = _assert_dispatch_enabled(
        data_root, authorization, now=current
    )
    plan = plan_dispatch(
        authorization,
        router_decision,
        model_map,
        repository=repository,
        assignment_unit=assignment_unit,
        model_start_ordinal=model_start_ordinal,
        now=current,
    )
    command = build_dispatch_command(
        plan,
        authorization=authorization,
        router_decision=router_decision,
        model_map=model_map,
        assignment_unit=assignment_unit,
        worktree=repository,
        output_schema=output_schema,
        output_file=output_file,
        now=current,
    )
    schema_path = normalized_path(output_schema)
    if not schema_path.is_file():
        raise AuthorizedDispatchError("DISPATCH_OUTPUT_SCHEMA_MISSING")
    executable = normalized_path(command[0])
    if not executable.is_file():
        raise AuthorizedDispatchError("DISPATCH_CODEX_EXECUTABLE_MISSING")
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "component_id": COMPONENT_ID,
        "status": "ready",
        "checked_at_utc": _utc_text(current),
        "plan": plan,
        "checks": {
            "authorization_active": True,
            "kill_switch_active": False,
            "kill_switch_path_sha256": hashlib.sha256(
                str(stop_path).encode("utf-8", errors="strict")
            ).hexdigest(),
            "codex_executable_sha256": hashlib.sha256(
                executable.read_bytes()
            ).hexdigest(),
            "dispatcher_source_sha256": hashlib.sha256(
                Path(__file__).read_bytes()
            ).hexdigest(),
            "output_schema_sha256": hashlib.sha256(
                schema_path.read_bytes()
            ).hexdigest(),
            "command_sha256": json_digest(command),
            "model_process_started": False,
            "network_request_started": False,
        },
    }
    result["preflight_sha256"] = json_digest(result)
    return result


def reserve_model_start(
    data_root: str | Path, authorization: dict[str, Any], *, now: datetime | None = None
) -> int:
    current = (now or _utc_now()).astimezone(timezone.utc)
    authorized, _stop_path = _assert_dispatch_enabled(
        data_root, authorization, now=current
    )
    budget_root = _authorization_state_root(
        data_root, authorized["authorization_id"]
    ) / "budget"
    for ordinal in range(1, authorized["maximum_model_starts"] + 1):
        receipt = {
            "schema_version": SCHEMA_VERSION,
            "component_id": COMPONENT_ID,
            "authorization_id": authorized["authorization_id"],
            "authorization_sha256": authorized["authorization_sha256"],
            "model_start_ordinal": ordinal,
            "reserved_at_utc": _utc_text(current),
        }
        try:
            _write_exclusive(budget_root / f"slot-{ordinal:06d}.json", receipt)
            return ordinal
        except FileExistsError:
            continue
    raise AuthorizedDispatchError("MODEL_START_BUDGET_EXHAUSTED")


def _write_assignment_receipt(
    data_root: str | Path, plan: dict[str, Any], kind: str, value: dict[str, Any]
) -> Path:
    if kind not in {"planned", "started", "completed"}:
        raise AuthorizedDispatchError("DISPATCH_RECEIPT_KIND_INVALID")
    verified = verify_plan(plan)
    root = (
        normalized_path(data_root)
        / "authorized-dispatch-r2"
        / verified["authorization"]["authorization_id"]
        / "assignments"
        / verified["assignment_id"]
    )
    return _write_exclusive(root / f"{kind}.json", value)


def _safe_execution_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AuthorizedDispatchError("DISPATCH_EXECUTION_RESULT_INVALID")
    return {key: copy.deepcopy(value.get(key)) for key in sorted(SAFE_RESULT_FIELDS)}


def execute_authorized_dispatch(
    authorization: dict[str, Any],
    router_decision: dict[str, Any],
    model_map: dict[str, Any],
    *,
    repository: str | Path,
    assignment_unit: str,
    data_root: str | Path,
    raw_directory: str | Path,
    output_schema: str | Path,
    output_file: str | Path,
    prompt: str,
    timeout_seconds: int,
    now: datetime | None = None,
    run_codex_fn: Callable[..., dict[str, Any]] = run_codex,
) -> dict[str, Any]:
    if not isinstance(prompt, str) or not prompt:
        raise AuthorizedDispatchError("DISPATCH_PROMPT_MISSING")
    current = (now or _utc_now()).astimezone(timezone.utc)
    if not Path(raw_directory).is_absolute():
        raise AuthorizedDispatchError("DISPATCH_RAW_DIRECTORY_NOT_ABSOLUTE")
    _authorized, stop_path = _assert_dispatch_enabled(
        data_root, authorization, now=current
    )
    ordinal = reserve_model_start(data_root, authorization, now=current)
    plan = plan_dispatch(
        authorization,
        router_decision,
        model_map,
        repository=repository,
        assignment_unit=assignment_unit,
        model_start_ordinal=ordinal,
        now=current,
    )
    command = build_dispatch_command(
        plan,
        worktree=repository,
        authorization=authorization,
        router_decision=router_decision,
        model_map=model_map,
        assignment_unit=assignment_unit,
        output_schema=output_schema,
        output_file=output_file,
        now=current,
    )
    _assert_dispatch_enabled(data_root, authorization, now=current)
    planned_path = _write_assignment_receipt(data_root, plan, "planned", plan)
    started_path: Path | None = None

    def on_process_started() -> None:
        nonlocal started_path
        started_path = _write_assignment_receipt(
            data_root,
            plan,
            "started",
            {
                "schema_version": SCHEMA_VERSION,
                "component_id": COMPONENT_ID,
                "assignment_id": plan["assignment_id"],
                "plan_sha256": plan["plan_sha256"],
                "started_at_utc": _utc_text(_utc_now()),
                "selected_model": plan["execution"]["selected_model"],
                "model_start_ordinal": ordinal,
            },
        )

    try:
        execution = run_codex_fn(
            command,
            prompt,
            raw_directory,
            worktree=repository,
            timeout_seconds=timeout_seconds,
            on_process_started=on_process_started,
            should_cancel=lambda: os.path.lexists(stop_path),
        )
        safe_execution = _safe_execution_result(execution)
        terminal_status = (
            "completed"
            if safe_execution.get("model_execution_completed") is True
            else "failed"
        )
        completed = {
            "schema_version": SCHEMA_VERSION,
            "component_id": COMPONENT_ID,
            "assignment_id": plan["assignment_id"],
            "plan_sha256": plan["plan_sha256"],
            "completed_at_utc": _utc_text(_utc_now()),
            "status": terminal_status,
            "selected_model": plan["execution"]["selected_model"],
            "execution": safe_execution,
        }
    except Exception as exc:
        completed = {
            "schema_version": SCHEMA_VERSION,
            "component_id": COMPONENT_ID,
            "assignment_id": plan["assignment_id"],
            "plan_sha256": plan["plan_sha256"],
            "completed_at_utc": _utc_text(_utc_now()),
            "status": "failed",
            "selected_model": plan["execution"]["selected_model"],
            "execution": {"error_type": type(exc).__name__},
        }
        _write_assignment_receipt(data_root, plan, "completed", completed)
        raise
    completed_path = _write_assignment_receipt(
        data_root, plan, "completed", completed
    )
    return {
        "plan": plan,
        "execution": completed["execution"],
        "receipts": {
            "planned": str(planned_path),
            "started": str(started_path) if started_path is not None else None,
            "completed": str(completed_path),
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mtr-dogfood-authorized-dispatch")
    parser.add_argument("--authorization", required=True)
    parser.add_argument("--router-decision", required=True)
    parser.add_argument("--model-map", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--assignment-unit", required=True)
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan = subparsers.add_parser("plan")
    plan.add_argument("--model-start-ordinal", type=int, required=True)
    preflight = subparsers.add_parser("preflight")
    preflight.add_argument("--data-root", required=True)
    preflight.add_argument("--output-schema", required=True)
    preflight.add_argument("--output-file", required=True)
    preflight.add_argument("--model-start-ordinal", type=int, required=True)
    run = subparsers.add_parser("run")
    run.add_argument("--data-root", required=True)
    run.add_argument("--raw-directory", required=True)
    run.add_argument("--output-schema", required=True)
    run.add_argument("--output-file", required=True)
    run.add_argument("--timeout-seconds", type=int, default=1800)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        authorization = load_json(args.authorization)
        decision = load_json(args.router_decision)
        model_map = load_json(args.model_map)
        if args.command == "plan":
            result = plan_dispatch(
                authorization,
                decision,
                model_map,
                repository=args.repository,
                assignment_unit=args.assignment_unit,
                model_start_ordinal=args.model_start_ordinal,
            )
        elif args.command == "preflight":
            result = preflight_authorized_dispatch(
                authorization,
                decision,
                model_map,
                repository=args.repository,
                assignment_unit=args.assignment_unit,
                data_root=args.data_root,
                output_schema=args.output_schema,
                output_file=args.output_file,
                model_start_ordinal=args.model_start_ordinal,
            )
        else:
            prompt = sys.stdin.read()
            result = execute_authorized_dispatch(
                authorization,
                decision,
                model_map,
                repository=args.repository,
                assignment_unit=args.assignment_unit,
                data_root=args.data_root,
                raw_directory=args.raw_directory,
                output_schema=args.output_schema,
                output_file=args.output_file,
                prompt=prompt,
                timeout_seconds=args.timeout_seconds,
            )
        sys.stdout.buffer.write(canonical_json_bytes(result))
        return 0
    except Exception as exc:
        sys.stdout.buffer.write(
            canonical_json_bytes(
                {
                    "status": "error",
                    "error_type": type(exc).__name__,
                    "message": str(exc),
                }
            )
        )
        return 2



def build_stop_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mtr-dogfood-authorized-dispatch-stop"
    )
    parser.add_argument("--data-root", required=True)
    parser.add_argument("--authorization-id", required=True)
    parser.add_argument("--reason", default="operator-request")
    return parser


def stop_main(argv: list[str] | None = None) -> int:
    args = build_stop_parser().parse_args(argv)
    try:
        path = activate_kill_switch(
            args.data_root,
            args.authorization_id,
            reason=args.reason,
        )
        digest = (
            hashlib.sha256(path.read_bytes()).hexdigest()
            if path.is_file()
            else None
        )
        result = {
            "schema_version": SCHEMA_VERSION,
            "component_id": COMPONENT_ID,
            "status": "kill_switch_active",
            "authorization_id": args.authorization_id,
            "kill_switch_receipt_sha256": digest,
        }
        sys.stdout.buffer.write(canonical_json_bytes(result))
        return 0
    except Exception as exc:
        sys.stdout.buffer.write(
            canonical_json_bytes(
                {
                    "status": "error",
                    "error_type": type(exc).__name__,
                    "message": str(exc),
                }
            )
        )
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
