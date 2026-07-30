from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol

from .app_server_atomic_host_launch import (
    AtomicHostLaunchError,
    HostAtomicTurnLauncher,
    build_atomic_launch_intent,
    build_launch_outcome_join,
    launch_atomic_turn_start,
    validate_atomic_launch_intent,
    validate_atomic_launch_receipt,
    validate_launch_outcome_join,
)
from .config import json_digest


COMPONENT_ID = "MTR_CODEX_APP_SERVER_HOST_CONFORMANCE_R1"
SCHEMA_VERSION = "1.0.0"
CONFORMANCE_MODE = "synthetic_no_product_model"
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,160}")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
STABLE_ERROR_PATTERN = re.compile(r"[A-Z][A-Z0-9_]{2,127}")
MUTATED_CWD_MARKER = r"C:\private\r6-mutated-after-capability"

CASE_ASSERTIONS: dict[str, tuple[str, ...]] = {
    "post_capability_mutation_rejected": (
        "exact_request_binding_rechecked",
        "rejected_before_transport_send",
        "rejected_before_turn_start",
    ),
    "capability_replay_rejected": (
        "one_capability_one_start",
        "second_transport_send_absent",
        "second_turn_absent",
    ),
    "integer_start_budget_enforced": (
        "boolean_is_not_integer_budget",
        "invalid_host_result_has_no_receipt",
    ),
    "durable_failure_redaction_enforced": (
        "raw_failure_detail_absent",
        "raw_request_absent",
        "raw_capability_absent",
    ),
    "selection_only_mutation_preserved": (
        "model_bound_to_assignment",
        "effort_bound_to_assignment",
        "non_selection_params_preserved",
    ),
    "initial_response_identity_bound": (
        "request_identity_bound",
        "thread_identity_bound",
        "assignment_identity_bound",
        "turn_identity_bound",
    ),
    "terminal_outcome_identity_joined": (
        "launch_receipt_bound",
        "outcome_bound",
        "launched_turn_bound",
    ),
    "host_only_action_boundary_enforced": (
        "no_local_signer",
        "no_fallback_issuer",
        "no_local_transport",
        "no_implicit_network_path",
        "no_product_model_start",
    ),
}
CASE_IDS = tuple(CASE_ASSERTIONS)

SUBJECT_FIELDS = {
    "implementation_id",
    "implementation_version",
    "implementation_sha256",
    "client_info_name",
    "protocol_schema_sha256",
    "conformance_mode",
}
OBSERVATION_FIELDS = {
    "transport_send_count",
    "turn_start_count",
    "product_model_start_count",
}
CASE_RESULT_FIELDS = {
    "case_id",
    "status",
    "result_code",
    "assertions",
    "evidence_sha256",
}
SUMMARY_FIELDS = {"required", "passed", "failed"}
REPORT_FIELDS = {
    "schema_version",
    "component_id",
    "status",
    "generated_at_utc",
    "subject",
    "cases",
    "summary",
    "authority_boundary",
    "local_boundary",
    "privacy",
    "report_sha256",
}

AUTHORITY_BOUNDARY = {
    "execution_authorized_by_router": False,
    "execution_authorized_by_conformance_suite": False,
    "host_test_transport_required": True,
    "product_model_start_authorized": False,
    "permission_expansion_authorized": False,
    "approval_policy_override_authorized": False,
    "sandbox_override_authorized": False,
    "network_expansion_authorized": False,
    "authorized_write_scope": [],
}
LOCAL_BOUNDARY = {
    "local_signer_included": False,
    "fallback_capability_issuer_included": False,
    "app_server_transport_included": False,
    "implicit_network_path_included": False,
    "product_model_launcher_included": False,
}
PRIVACY_BOUNDARY = {
    "raw_capability_envelope_persisted": False,
    "raw_request_persisted": False,
    "raw_prompt_persisted": False,
    "raw_thread_id_persisted": False,
    "raw_turn_id_persisted": False,
    "raw_path_persisted": False,
    "raw_app_server_response_persisted": False,
    "raw_model_output_persisted": False,
    "raw_tool_output_persisted": False,
    "raw_error_text_persisted": False,
    "only_redacted_hash_evidence_persisted": True,
}


class HostConformanceError(RuntimeError):
    pass


@dataclass(frozen=True)
class HostConformanceCase:
    """Ephemeral, synthetic inputs supplied by a host-owned test driver."""

    case_id: str
    proposal: Mapping[str, Any]
    base_params: Mapping[str, Any]
    request: Mapping[str, Any]
    launch_intent: Mapping[str, Any]
    capability_envelope: bytes
    launcher: HostAtomicTurnLauncher
    private_markers: tuple[str | bytes, ...] = ()


class HostConformanceDriver(Protocol):
    """Host-owned fixture, observation, and terminal-outcome seam."""

    def prepare(self, case_id: str) -> HostConformanceCase:
        """Return a fresh one-use synthetic case for the requested case ID."""

    def snapshot(self, case_id: str) -> Mapping[str, Any]:
        """Return redaction-safe monotonic synthetic transport counters."""

    def build_terminal_outcome(
        self,
        case_id: str,
        *,
        proposal: Mapping[str, Any],
        response: Mapping[str, Any],
        launch_receipt: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Build the privacy-safe R3 terminal outcome for a launched turn."""


class _BooleanStartBudgetLauncher:
    """Test wrapper that proves a bool host-result budget is rejected."""

    def __init__(self, inner: HostAtomicTurnLauncher):
        self._inner = inner

    def launch(
        self,
        capability_envelope: bytes,
        request: Mapping[str, Any],
        launch_intent: Mapping[str, Any],
    ) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
        raw = self._inner.launch(
            capability_envelope,
            request,
            launch_intent,
        )
        if not isinstance(raw, tuple) or len(raw) != 2:
            return raw
        response, result = raw
        if not isinstance(result, Mapping):
            return raw
        invalid = copy.deepcopy(dict(result))
        invalid["starts_consumed"] = True
        return response, invalid


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_PATTERN.fullmatch(value):
        raise HostConformanceError(f"{field}_INVALID")
    return value


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or not SHA256_PATTERN.fullmatch(value):
        raise HostConformanceError(f"{field}_INVALID")
    return value


def _aware_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise HostConformanceError("CONFORMANCE_TIME_INVALID")
    return value.astimezone(timezone.utc)


def _utc_text(value: datetime) -> str:
    return _aware_utc(value).isoformat().replace("+00:00", "Z")


def _utc(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise HostConformanceError(f"{field}_INVALID")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise HostConformanceError(f"{field}_INVALID") from None
    return _aware_utc(parsed)


def _validated_subject(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise HostConformanceError("CONFORMANCE_SUBJECT_INVALID")
    subject = copy.deepcopy(dict(value))
    if set(subject) != SUBJECT_FIELDS:
        raise HostConformanceError("CONFORMANCE_SUBJECT_INVALID")
    _identifier(subject.get("implementation_id"), "IMPLEMENTATION_ID")
    _identifier(
        subject.get("implementation_version"),
        "IMPLEMENTATION_VERSION",
    )
    _sha256(subject.get("implementation_sha256"), "IMPLEMENTATION_SHA256")
    _identifier(subject.get("client_info_name"), "CLIENT_INFO_NAME")
    _sha256(
        subject.get("protocol_schema_sha256"),
        "PROTOCOL_SCHEMA_SHA256",
    )
    if subject.get("conformance_mode") != CONFORMANCE_MODE:
        raise HostConformanceError("CONFORMANCE_MODE_INVALID")
    return subject


def _validated_observation(value: Any) -> dict[str, int]:
    if not isinstance(value, Mapping):
        raise HostConformanceError("HOST_OBSERVATION_INVALID")
    observation = copy.deepcopy(dict(value))
    if set(observation) != OBSERVATION_FIELDS:
        raise HostConformanceError("HOST_OBSERVATION_INVALID")
    for field in OBSERVATION_FIELDS:
        count = observation.get(field)
        if type(count) is not int or count < 0:
            raise HostConformanceError("HOST_OBSERVATION_INVALID")
    return observation


def _driver_method(driver: Any, name: str):
    method = getattr(driver, name, None)
    if not callable(method):
        raise HostConformanceError("HOST_CONFORMANCE_DRIVER_INVALID")
    return method


def _snapshot(
    driver: HostConformanceDriver,
    case_id: str,
) -> dict[str, int]:
    return _validated_observation(_driver_method(driver, "snapshot")(case_id))


def _normalize_marker(value: str | bytes) -> str:
    if isinstance(value, bytes):
        marker = value.decode("utf-8", errors="replace")
    elif isinstance(value, str):
        marker = value
    else:
        raise HostConformanceError("PRIVATE_MARKER_INVALID")
    if not 8 <= len(marker) <= 4_096:
        raise HostConformanceError("PRIVATE_MARKER_INVALID")
    return marker


def _prepare_case(
    driver: HostConformanceDriver,
    subject: dict[str, Any],
    case_id: str,
) -> tuple[HostConformanceCase, list[str]]:
    raw_case = _driver_method(driver, "prepare")(case_id)
    if not isinstance(raw_case, HostConformanceCase):
        raise HostConformanceError("HOST_CONFORMANCE_CASE_INVALID")
    if raw_case.case_id != case_id:
        raise HostConformanceError("HOST_CONFORMANCE_CASE_ID_INVALID")
    if (
        not isinstance(raw_case.proposal, Mapping)
        or not isinstance(raw_case.base_params, Mapping)
        or not isinstance(raw_case.request, Mapping)
        or not isinstance(raw_case.launch_intent, Mapping)
        or not isinstance(raw_case.capability_envelope, bytes)
        or not 1 <= len(raw_case.capability_envelope) <= 65_536
        or not callable(getattr(raw_case.launcher, "launch", None))
    ):
        raise HostConformanceError("HOST_CONFORMANCE_CASE_INVALID")

    proposal = copy.deepcopy(dict(raw_case.proposal))
    base_params = copy.deepcopy(dict(raw_case.base_params))
    request = copy.deepcopy(dict(raw_case.request))
    intent = validate_atomic_launch_intent(
        copy.deepcopy(dict(raw_case.launch_intent)),
        proposal=proposal,
    )
    if (
        proposal["app_server_binding"]["client_info_name"]
        != subject["client_info_name"]
        or proposal["app_server_binding"]["protocol_schema_sha256"]
        != subject["protocol_schema_sha256"]
    ):
        raise HostConformanceError("HOST_CONFORMANCE_SUBJECT_BINDING_INVALID")
    if not isinstance(request.get("id"), int) or isinstance(
        request.get("id"), bool
    ):
        raise HostConformanceError("HOST_CONFORMANCE_CASE_INVALID")
    expected_request, expected_intent = build_atomic_launch_intent(
        proposal,
        base_params,
        intent["host_bindings"],
        request_id=request["id"],
    )
    if request != expected_request or intent != expected_intent:
        raise HostConformanceError("HOST_CONFORMANCE_CASE_BINDING_INVALID")

    markers = [_normalize_marker(value) for value in raw_case.private_markers]
    case = HostConformanceCase(
        case_id=case_id,
        proposal=proposal,
        base_params=base_params,
        request=request,
        launch_intent=intent,
        capability_envelope=bytes(raw_case.capability_envelope),
        launcher=raw_case.launcher,
        private_markers=tuple(markers),
    )
    return case, markers


def _stable_error(exc: BaseException) -> str:
    text = str(exc)
    if isinstance(exc, (AtomicHostLaunchError, HostConformanceError)) and (
        STABLE_ERROR_PATTERN.fullmatch(text)
    ):
        return text
    return "FAIL_CLOSED"


def _increments(
    before: dict[str, int],
    after: dict[str, int],
    *,
    sends: int,
    turns: int,
) -> bool:
    return (
        after["transport_send_count"]
        == before["transport_send_count"] + sends
        and after["turn_start_count"] == before["turn_start_count"] + turns
        and before["product_model_start_count"] == 0
        and after["product_model_start_count"] == 0
    )


def _selection_only_preserved(case: HostConformanceCase) -> bool:
    base = copy.deepcopy(dict(case.base_params))
    request = copy.deepcopy(dict(case.request))
    params = request.get("params")
    if not isinstance(params, dict):
        return False
    base_non_selection = copy.deepcopy(base)
    request_non_selection = copy.deepcopy(params)
    base_non_selection.pop("model", None)
    base_non_selection.pop("effort", None)
    request_non_selection.pop("model", None)
    request_non_selection.pop("effort", None)
    proposal = dict(case.proposal)
    selection = proposal.get("selection")
    return (
        base_non_selection == request_non_selection
        and isinstance(selection, dict)
        and params.get("model") == selection.get("requested_model")
        and params.get("effort") == selection.get("requested_effort")
    )


def _mutated_request(case: HostConformanceCase) -> dict[str, Any]:
    request = copy.deepcopy(dict(case.request))
    params = request.get("params")
    if not isinstance(params, dict):
        raise HostConformanceError("HOST_CONFORMANCE_CASE_INVALID")
    params["cwd"] = MUTATED_CWD_MARKER
    return request


def _case_record(
    case_id: str,
    passed: bool,
    evidence: Mapping[str, Any],
) -> dict[str, Any]:
    if case_id not in CASE_ASSERTIONS:
        raise HostConformanceError("CONFORMANCE_CASE_ID_INVALID")
    safe_evidence = copy.deepcopy(dict(evidence))
    try:
        evidence_sha256 = json_digest(safe_evidence)
    except Exception:
        evidence_sha256 = json_digest(
            {"case_id": case_id, "result": "FAIL_CLOSED"}
        )
        passed = False
    return {
        "case_id": case_id,
        "status": "passed" if passed else "failed",
        "result_code": "PASS" if passed else "FAIL_CLOSED",
        "assertions": list(CASE_ASSERTIONS[case_id]),
        "evidence_sha256": evidence_sha256,
    }


def _serialized_contains_marker(value: Any, markers: list[str]) -> bool:
    serialized = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return any(marker in serialized for marker in markers)


def _build_report(
    subject: dict[str, Any],
    records: dict[str, dict[str, Any]],
    *,
    generated_at: datetime,
) -> dict[str, Any]:
    ordered = [copy.deepcopy(records[case_id]) for case_id in CASE_IDS]
    passed = sum(record["status"] == "passed" for record in ordered)
    failed = len(ordered) - passed
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "component_id": COMPONENT_ID,
        "status": "conformant" if failed == 0 else "non_conformant",
        "generated_at_utc": _utc_text(generated_at),
        "subject": copy.deepcopy(subject),
        "cases": ordered,
        "summary": {
            "required": len(CASE_IDS),
            "passed": passed,
            "failed": failed,
        },
        "authority_boundary": copy.deepcopy(AUTHORITY_BOUNDARY),
        "local_boundary": copy.deepcopy(LOCAL_BOUNDARY),
        "privacy": copy.deepcopy(PRIVACY_BOUNDARY),
    }
    report["report_sha256"] = json_digest(report)
    return report


def run_host_conformance_suite(
    subject: Mapping[str, Any],
    driver: HostConformanceDriver,
    *,
    now: datetime,
) -> dict[str, Any]:
    """Exercise an injected synthetic host and return a redacted report."""

    verified_subject = _validated_subject(subject)
    current = _aware_utc(now)
    for method in ("prepare", "snapshot", "build_terminal_outcome"):
        _driver_method(driver, method)

    records: dict[str, dict[str, Any]] = {}
    markers = [MUTATED_CWD_MARKER]
    durable_values: list[Any] = []
    observations: list[dict[str, int]] = []

    baseline_case: HostConformanceCase | None = None
    baseline_response: dict[str, Any] | None = None
    baseline_receipt: dict[str, Any] | None = None
    try:
        baseline_case, case_markers = _prepare_case(
            driver,
            verified_subject,
            "initial_response_identity_bound",
        )
        markers.extend(case_markers)
        selection_passed = _selection_only_preserved(baseline_case)
        records["selection_only_mutation_preserved"] = _case_record(
            "selection_only_mutation_preserved",
            selection_passed,
            {
                "proposal_sha256": baseline_case.proposal["proposal_sha256"],
                "launch_intent_sha256": baseline_case.launch_intent[
                    "intent_sha256"
                ],
                "selection_only": selection_passed,
            },
        )

        before = _snapshot(driver, baseline_case.case_id)
        observations.append(before)
        response, receipt = launch_atomic_turn_start(
            dict(baseline_case.proposal),
            dict(baseline_case.launch_intent),
            dict(baseline_case.request),
            baseline_case.capability_envelope,
            baseline_case.launcher,
            now=current,
        )
        after = _snapshot(driver, baseline_case.case_id)
        observations.append(after)
        baseline_response = response
        baseline_receipt = validate_atomic_launch_receipt(
            receipt,
            proposal=dict(baseline_case.proposal),
        )
        identity_passed = (
            _increments(before, after, sends=1, turns=1)
            and baseline_receipt["request"]["request_id"]
            == baseline_case.request["id"]
            and baseline_receipt["request"]["thread_id_sha256"]
            == baseline_case.launch_intent["request"]["thread_id_sha256"]
            and baseline_receipt["assignment_id"]
            == baseline_case.proposal["assignment_id"]
        )
        durable_values.append(baseline_receipt)
        records["initial_response_identity_bound"] = _case_record(
            "initial_response_identity_bound",
            identity_passed,
            {
                "receipt_sha256": baseline_receipt["receipt_sha256"],
                "turn_id_sha256": baseline_receipt["response"][
                    "turn_id_sha256"
                ],
                "before": before,
                "after": after,
            },
        )
    except Exception as exc:
        code = _stable_error(exc)
        records.setdefault(
            "selection_only_mutation_preserved",
            _case_record(
                "selection_only_mutation_preserved",
                False,
                {"result_code": code},
            ),
        )
        records["initial_response_identity_bound"] = _case_record(
            "initial_response_identity_bound",
            False,
            {"result_code": code},
        )

    if (
        baseline_case is not None
        and baseline_response is not None
        and baseline_receipt is not None
    ):
        try:
            raw_outcome = _driver_method(
                driver, "build_terminal_outcome"
            )(
                baseline_case.case_id,
                proposal=copy.deepcopy(dict(baseline_case.proposal)),
                response=copy.deepcopy(baseline_response),
                launch_receipt=copy.deepcopy(baseline_receipt),
            )
            if not isinstance(raw_outcome, Mapping):
                raise HostConformanceError("TERMINAL_OUTCOME_INVALID")
            outcome = copy.deepcopy(dict(raw_outcome))
            joined = build_launch_outcome_join(
                baseline_receipt,
                outcome,
                proposal=dict(baseline_case.proposal),
            )
            validate_launch_outcome_join(
                joined,
                launch_receipt=baseline_receipt,
                outcome=outcome,
            )
            joined_passed = (
                joined["turn_id_sha256"]
                == baseline_receipt["response"]["turn_id_sha256"]
            )
            durable_values.extend((outcome, joined))
            records["terminal_outcome_identity_joined"] = _case_record(
                "terminal_outcome_identity_joined",
                joined_passed,
                {
                    "launch_receipt_sha256": joined[
                        "launch_receipt_sha256"
                    ],
                    "outcome_sha256": joined["outcome_sha256"],
                    "join_sha256": joined["join_sha256"],
                },
            )
        except Exception as exc:
            records["terminal_outcome_identity_joined"] = _case_record(
                "terminal_outcome_identity_joined",
                False,
                {"result_code": _stable_error(exc)},
            )
    else:
        records["terminal_outcome_identity_joined"] = _case_record(
            "terminal_outcome_identity_joined",
            False,
            {"result_code": "DEPENDENCY_FAILED"},
        )

    try:
        mutation_case, case_markers = _prepare_case(
            driver,
            verified_subject,
            "post_capability_mutation_rejected",
        )
        markers.extend(case_markers)
        before = _snapshot(driver, mutation_case.case_id)
        observations.append(before)
        rejection_code = "NO_REJECTION"
        try:
            _, unexpected_receipt = launch_atomic_turn_start(
                dict(mutation_case.proposal),
                dict(mutation_case.launch_intent),
                _mutated_request(mutation_case),
                mutation_case.capability_envelope,
                mutation_case.launcher,
                now=current,
            )
            durable_values.append(unexpected_receipt)
        except Exception as exc:
            rejection_code = _stable_error(exc)
        after = _snapshot(driver, mutation_case.case_id)
        observations.append(after)
        mutation_passed = (
            rejection_code == "HOST_ATOMIC_LAUNCH_FAILED"
            and _increments(before, after, sends=0, turns=0)
        )
        records["post_capability_mutation_rejected"] = _case_record(
            "post_capability_mutation_rejected",
            mutation_passed,
            {
                "rejection_code": rejection_code,
                "before": before,
                "after": after,
            },
        )
    except Exception as exc:
        records["post_capability_mutation_rejected"] = _case_record(
            "post_capability_mutation_rejected",
            False,
            {"result_code": _stable_error(exc)},
        )

    try:
        replay_case, case_markers = _prepare_case(
            driver,
            verified_subject,
            "capability_replay_rejected",
        )
        markers.extend(case_markers)
        before = _snapshot(driver, replay_case.case_id)
        observations.append(before)
        _, first_receipt = launch_atomic_turn_start(
            dict(replay_case.proposal),
            dict(replay_case.launch_intent),
            dict(replay_case.request),
            replay_case.capability_envelope,
            replay_case.launcher,
            now=current,
        )
        durable_values.append(first_receipt)
        middle = _snapshot(driver, replay_case.case_id)
        observations.append(middle)
        replay_code = "NO_REJECTION"
        try:
            _, second_receipt = launch_atomic_turn_start(
                dict(replay_case.proposal),
                dict(replay_case.launch_intent),
                dict(replay_case.request),
                replay_case.capability_envelope,
                replay_case.launcher,
                now=current,
            )
            durable_values.append(second_receipt)
        except Exception as exc:
            replay_code = _stable_error(exc)
        after = _snapshot(driver, replay_case.case_id)
        observations.append(after)
        replay_passed = (
            replay_code == "HOST_ATOMIC_LAUNCH_FAILED"
            and _increments(before, middle, sends=1, turns=1)
            and _increments(middle, after, sends=0, turns=0)
        )
        records["capability_replay_rejected"] = _case_record(
            "capability_replay_rejected",
            replay_passed,
            {
                "rejection_code": replay_code,
                "before": before,
                "middle": middle,
                "after": after,
            },
        )
    except Exception as exc:
        records["capability_replay_rejected"] = _case_record(
            "capability_replay_rejected",
            False,
            {"result_code": _stable_error(exc)},
        )

    try:
        budget_case, case_markers = _prepare_case(
            driver,
            verified_subject,
            "integer_start_budget_enforced",
        )
        markers.extend(case_markers)
        before = _snapshot(driver, budget_case.case_id)
        observations.append(before)
        budget_code = "NO_REJECTION"
        try:
            _, invalid_receipt = launch_atomic_turn_start(
                dict(budget_case.proposal),
                dict(budget_case.launch_intent),
                dict(budget_case.request),
                budget_case.capability_envelope,
                _BooleanStartBudgetLauncher(budget_case.launcher),
                now=current,
            )
            durable_values.append(invalid_receipt)
        except Exception as exc:
            budget_code = _stable_error(exc)
        after = _snapshot(driver, budget_case.case_id)
        observations.append(after)
        budget_passed = (
            budget_code == "HOST_LAUNCH_START_BUDGET_INVALID"
            and _increments(before, after, sends=1, turns=1)
        )
        records["integer_start_budget_enforced"] = _case_record(
            "integer_start_budget_enforced",
            budget_passed,
            {
                "rejection_code": budget_code,
                "before": before,
                "after": after,
            },
        )
    except Exception as exc:
        records["integer_start_budget_enforced"] = _case_record(
            "integer_start_budget_enforced",
            False,
            {"result_code": _stable_error(exc)},
        )

    boundary_passed = (
        verified_subject["conformance_mode"] == CONFORMANCE_MODE
        and all(value is False for value in LOCAL_BOUNDARY.values())
        and bool(observations)
        and all(
            observation["product_model_start_count"] == 0
            for observation in observations
        )
    )
    records["host_only_action_boundary_enforced"] = _case_record(
        "host_only_action_boundary_enforced",
        boundary_passed,
        {
            "implementation_sha256": verified_subject[
                "implementation_sha256"
            ],
            "observation_count": len(observations),
            "local_boundary": LOCAL_BOUNDARY,
        },
    )

    records["durable_failure_redaction_enforced"] = _case_record(
        "durable_failure_redaction_enforced",
        not _serialized_contains_marker(durable_values, markers),
        {
            "durable_value_count": len(durable_values),
            "private_marker_count": len(markers),
            "privacy_boundary": PRIVACY_BOUNDARY,
        },
    )
    report = _build_report(
        verified_subject,
        records,
        generated_at=current,
    )
    if _serialized_contains_marker(report, markers):
        records["durable_failure_redaction_enforced"] = _case_record(
            "durable_failure_redaction_enforced",
            False,
            {
                "durable_value_count": len(durable_values),
                "private_marker_count": len(markers),
                "result": "FAIL_CLOSED",
            },
        )
        report = _build_report(
            verified_subject,
            records,
            generated_at=current,
        )
    return validate_host_conformance_report(
        report,
        expected_subject=verified_subject,
    )


def validate_host_conformance_report(
    value: Any,
    *,
    expected_subject: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate one report against a caller-owned exact subject binding."""

    verified_expected_subject = _validated_subject(expected_subject)
    if not isinstance(value, dict) or set(value) != REPORT_FIELDS:
        raise HostConformanceError("CONFORMANCE_REPORT_SCHEMA_INVALID")
    report = copy.deepcopy(value)
    digest = _sha256(
        report.get("report_sha256"),
        "CONFORMANCE_REPORT_SHA256",
    )
    digest_view = copy.deepcopy(report)
    digest_view.pop("report_sha256", None)
    if json_digest(digest_view) != digest:
        raise HostConformanceError("CONFORMANCE_REPORT_DIGEST_INVALID")
    if (
        report.get("schema_version") != SCHEMA_VERSION
        or report.get("component_id") != COMPONENT_ID
        or report.get("status") not in {"conformant", "non_conformant"}
    ):
        raise HostConformanceError("CONFORMANCE_REPORT_SCHEMA_INVALID")
    _utc(report.get("generated_at_utc"), "CONFORMANCE_GENERATED_AT")
    report_subject = _validated_subject(report.get("subject"))
    if report_subject != verified_expected_subject:
        raise HostConformanceError(
            "CONFORMANCE_REPORT_SUBJECT_BINDING_INVALID"
        )

    cases = report.get("cases")
    if not isinstance(cases, list) or len(cases) != len(CASE_IDS):
        raise HostConformanceError("CONFORMANCE_REPORT_CASES_INVALID")
    passed = 0
    for expected_id, case in zip(CASE_IDS, cases, strict=True):
        if not isinstance(case, dict) or set(case) != CASE_RESULT_FIELDS:
            raise HostConformanceError("CONFORMANCE_REPORT_CASES_INVALID")
        if (
            case.get("case_id") != expected_id
            or case.get("status") not in {"passed", "failed"}
            or case.get("assertions") != list(CASE_ASSERTIONS[expected_id])
        ):
            raise HostConformanceError("CONFORMANCE_REPORT_CASES_INVALID")
        if case["status"] == "passed":
            passed += 1
            if case.get("result_code") != "PASS":
                raise HostConformanceError(
                    "CONFORMANCE_REPORT_CASES_INVALID"
                )
        elif case.get("result_code") != "FAIL_CLOSED":
            raise HostConformanceError("CONFORMANCE_REPORT_CASES_INVALID")
        _sha256(case.get("evidence_sha256"), "CASE_EVIDENCE_SHA256")

    summary = report.get("summary")
    failed = len(CASE_IDS) - passed
    if (
        not isinstance(summary, dict)
        or set(summary) != SUMMARY_FIELDS
        or any(type(summary.get(field)) is not int for field in SUMMARY_FIELDS)
        or summary
        != {"required": len(CASE_IDS), "passed": passed, "failed": failed}
        or (report["status"] == "conformant") != (failed == 0)
    ):
        raise HostConformanceError("CONFORMANCE_REPORT_SUMMARY_INVALID")
    if report.get("authority_boundary") != AUTHORITY_BOUNDARY:
        raise HostConformanceError("CONFORMANCE_REPORT_AUTHORITY_DRIFT")
    if report.get("local_boundary") != LOCAL_BOUNDARY:
        raise HostConformanceError("CONFORMANCE_REPORT_LOCAL_BOUNDARY_DRIFT")
    if report.get("privacy") != PRIVACY_BOUNDARY:
        raise HostConformanceError("CONFORMANCE_REPORT_PRIVACY_DRIFT")
    return report
