from __future__ import annotations

import copy
import hashlib
import hmac
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from mtr_dogfood.app_server_atomic_host_launch import (
    HOST_BINDING_FIELDS,
    HOST_RESULT_FIELDS,
    INTENT_FIELDS,
    JOIN_FIELDS,
    RECEIPT_FIELDS,
    AtomicHostLaunchError,
    build_atomic_launch_intent,
    build_launch_outcome_join,
    launch_atomic_turn_start,
    validate_atomic_launch_intent,
    validate_atomic_launch_receipt,
    validate_launch_outcome_join,
)
from mtr_dogfood.app_server_experiment import (
    AUTHORITY_BOUNDARY as PROPOSAL_AUTHORITY_BOUNDARY,
    COMPONENT_ID as PROPOSAL_COMPONENT_ID,
    PRIVACY_BOUNDARY as EXPERIMENT_PRIVACY_BOUNDARY,
    PRIVACY_BOUNDARY as PROPOSAL_PRIVACY_BOUNDARY,
    validate_outcome,
    validate_proposal,
)
from mtr_dogfood.config import canonical_json_bytes, json_digest


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 7, 28, 2, 0, tzinfo=timezone.utc)
HOST_TEST_KEY = b"synthetic-host-conformance-key-not-for-production"


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _proposal() -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "1.0.0",
        "component_id": PROPOSAL_COMPONENT_ID,
        "status": "host_review_required",
        "assignment_id": "assignment-r5",
        "plan_sha256": "1" * 64,
        "experiment": {
            "experiment_id": "atomic-host-launch-r1",
            "assignment_unit_sha256": "2" * 64,
            "assignment_bucket": 4321,
            "arm": "ROUTER_AUTO",
        },
        "selection": {
            "router_profile": "balanced",
            "requested_model": "gpt-5.6-terra",
            "requested_effort": "medium",
        },
        "app_server_binding": {
            "protocol_version": "v2",
            "codex_cli_version": "0.144.5",
            "protocol_schema_sha256": "3" * 64,
            "model_list_response_sha256": "4" * 64,
            "model_catalog_sha256": "5" * 64,
            "selected_model_entry_sha256": "6" * 64,
            "client_info_name": "mtr_dogfood",
            "catalog_complete": True,
        },
        "origin": {
            "kind": "integration_test",
            "issuer": "codex-desktop-host-test",
            "attestation_requested": True,
            "attestation_evidence_sha256": "7" * 64,
            "opaque_token_persisted": False,
        },
        "thread_start_override": {"model": "gpt-5.6-terra"},
        "turn_start_override": {
            "model": "gpt-5.6-terra",
            "effort": "medium",
        },
        "authority_boundary": copy.deepcopy(PROPOSAL_AUTHORITY_BOUNDARY),
        "privacy": copy.deepcopy(PROPOSAL_PRIVACY_BOUNDARY),
    }
    value["proposal_sha256"] = json_digest(value)
    return validate_proposal(value)


def _base_params() -> dict[str, object]:
    return {
        "threadId": "thread-private-r5",
        "input": [
            {
                "type": "text",
                "text": "private prompt excluded from every durable receipt",
            }
        ],
        "cwd": "C:\\private\\r5-workspace",
        "approvalPolicy": "unlessTrusted",
        "sandboxPolicy": {
            "type": "workspaceWrite",
            "writableRoots": ["C:\\private\\r5-workspace"],
            "networkAccess": False,
        },
        "model": "gpt-5.6-sol",
        "effort": "high",
    }


def _expected_request(
    proposal: dict[str, object],
    base_params: dict[str, object],
    request_id: int,
) -> dict[str, object]:
    params = copy.deepcopy(base_params)
    params["model"] = proposal["selection"]["requested_model"]
    params["effort"] = proposal["selection"]["requested_effort"]
    return {"method": "turn/start", "id": request_id, "params": params}


def _request_binding(request: dict[str, object]) -> str:
    return hmac.new(
        HOST_TEST_KEY,
        canonical_json_bytes(request),
        hashlib.sha256,
    ).hexdigest()


def _bindings(
    proposal: dict[str, object],
    base_params: dict[str, object],
    request_id: int,
) -> dict[str, str]:
    request = _expected_request(proposal, base_params, request_id)
    return {
        "host_request_binding_sha256": _request_binding(request),
        "host_context_binding_sha256": _sha256_text("context-r5"),
        "host_instance_sha256": _sha256_text("host-instance-r5"),
        "connection_sha256": _sha256_text("connection-r5"),
        "consent_grant_sha256": _sha256_text("consent-r5"),
        "budget_lease_sha256": _sha256_text("budget-r5"),
    }


def _outcome(
    proposal: dict[str, object],
    *,
    turn_id: str = "turn-private-r5",
) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "1.0.0",
        "component_id": PROPOSAL_COMPONENT_ID,
        "status": "observed",
        "proposal_sha256": proposal["proposal_sha256"],
        "assignment_id": proposal["assignment_id"],
        "experiment": {
            "experiment_id": proposal["experiment"]["experiment_id"],
            "arm": proposal["experiment"]["arm"],
        },
        "origin": copy.deepcopy(proposal["origin"]),
        "identity": {
            "thread_id_sha256": _sha256_text("thread-private-r5"),
            "turn_id_sha256": _sha256_text(turn_id),
        },
        "model": {
            "requested_model": proposal["selection"]["requested_model"],
            "requested_effort": proposal["selection"]["requested_effort"],
            "resolved_model": proposal["selection"]["requested_model"],
            "reroute_count": 0,
            "reroutes": [],
        },
        "terminal": {
            "turn_status": "completed",
            "outcome_class": "success",
            "started_at_unix": 100,
            "completed_at_unix": 101,
            "duration_ms": 1000,
            "error_present": False,
        },
        "usage": {
            "observed": False,
            "notification_count": 0,
            "input_tokens": None,
            "cached_input_tokens": None,
            "output_tokens": None,
            "reasoning_output_tokens": None,
            "total_tokens": None,
            "model_context_window": None,
        },
        "items": {
            "count": 0,
            "type_counts": {},
            "status_counts": {},
        },
        "privacy": copy.deepcopy(EXPERIMENT_PRIVACY_BOUNDARY),
    }
    value["outcome_sha256"] = json_digest(value)
    return validate_outcome(value, proposal=proposal)


class RecordingAtomicLauncher:
    def __init__(
        self,
        *,
        result_overrides: dict[str, object] | None = None,
        response_overrides: dict[str, object] | None = None,
        failure: Exception | None = None,
    ):
        self.result_overrides = result_overrides or {}
        self.response_overrides = response_overrides or {}
        self.failure = failure
        self.calls: list[tuple[bytes, dict, dict]] = []
        self.seen_envelopes: set[str] = set()

    def launch(
        self,
        capability_envelope: bytes,
        request: dict[str, object],
        launch_intent: dict[str, object],
    ) -> tuple[dict[str, object], dict[str, object]]:
        self.calls.append(
            (
                capability_envelope,
                copy.deepcopy(request),
                copy.deepcopy(launch_intent),
            )
        )
        if self.failure is not None:
            raise self.failure
        envelope_sha256 = hashlib.sha256(capability_envelope).hexdigest()
        if envelope_sha256 in self.seen_envelopes:
            raise RuntimeError("synthetic replay detail must be redacted")
        if (
            _request_binding(request)
            != launch_intent["host_bindings"][
                "host_request_binding_sha256"
            ]
        ):
            raise RuntimeError("synthetic request binding mismatch")
        self.seen_envelopes.add(envelope_sha256)
        turn_id = "turn-private-r5"
        response: dict[str, object] = {
            "turn": {
                "id": turn_id,
                "items": [],
                "status": "inProgress",
                "startedAt": 100,
            }
        }
        response.update(copy.deepcopy(self.response_overrides))
        result: dict[str, object] = {
            "capability_version": "2.0.0",
            "status": "turn_started",
            "issuer": "openai-codex-host-test",
            "audience": launch_intent["client_info_name"],
            "issued_at_utc": "2026-07-28T01:59:00Z",
            "expires_at_utc": "2026-07-28T02:05:00Z",
            "launched_at_utc": "2026-07-28T01:59:59Z",
            "capability_id_sha256": _sha256_text("capability-private-r5"),
            "capability_envelope_sha256": envelope_sha256,
            "nonce_sha256": _sha256_text("nonce-private-r5"),
            "launch_intent_sha256": launch_intent["intent_sha256"],
            "proposal_sha256": launch_intent["proposal_sha256"],
            "plan_sha256": launch_intent["plan_sha256"],
            "assignment_id": launch_intent["assignment_id"],
            **copy.deepcopy(launch_intent["host_bindings"]),
            "method": "turn/start",
            "request_id": launch_intent["request"]["request_id"],
            "thread_id_sha256": launch_intent["request"][
                "thread_id_sha256"
            ],
            "turn_id_sha256": _sha256_text(turn_id),
            "selected_model": launch_intent["selection"]["model"],
            "selected_effort": launch_intent["selection"]["effort"],
            "capability_verified": True,
            "nonce_consumed": True,
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
            "starts_consumed": 1,
            "request_sent": True,
            "turn_started": True,
        }
        result.update(copy.deepcopy(self.result_overrides))
        return response, result


class AtomicHostLaunchTests(unittest.TestCase):
    def _prepared(self):
        proposal = _proposal()
        base = _base_params()
        request, intent = build_atomic_launch_intent(
            proposal,
            base,
            _bindings(proposal, base, 50),
            request_id=50,
        )
        return proposal, base, request, intent

    def test_intent_is_non_authorizing_and_changes_only_selection(self):
        proposal, base, request, intent = self._prepared()
        self.assertEqual(
            validate_atomic_launch_intent(intent, proposal=proposal),
            intent,
        )
        self.assertEqual(set(intent), INTENT_FIELDS)
        self.assertEqual(set(intent["host_bindings"]), HOST_BINDING_FIELDS)
        self.assertFalse(
            intent["authority_boundary"]["execution_authorized_by_intent"]
        )
        self.assertTrue(
            intent["authority_boundary"]["host_atomic_launch_required"]
        )
        for field, original_value in base.items():
            if field not in {"model", "effort"}:
                self.assertEqual(request["params"][field], original_value)
        self.assertEqual(request["params"]["model"], "gpt-5.6-terra")
        self.assertEqual(request["params"]["effort"], "medium")

    def test_host_atomic_launch_returns_response_and_redacted_receipt(self):
        proposal, _, request, intent = self._prepared()
        launcher = RecordingAtomicLauncher()
        envelope = b"opaque-host-capability-r5"
        response, receipt = launch_atomic_turn_start(
            proposal,
            intent,
            request,
            envelope,
            launcher,
            now=NOW,
        )
        self.assertEqual(response["turn"]["id"], "turn-private-r5")
        self.assertEqual(len(launcher.calls), 1)
        self.assertEqual(set(launcher.calls[0][2]), INTENT_FIELDS)
        self.assertEqual(
            validate_atomic_launch_receipt(receipt, proposal=proposal),
            receipt,
        )
        self.assertEqual(set(receipt), RECEIPT_FIELDS)
        self.assertTrue(receipt["request"]["exact_request_sent"])
        self.assertEqual(receipt["response"]["starts_consumed"], 1)

        serialized = json.dumps(receipt, ensure_ascii=False)
        for private_value in (
            "private prompt excluded from every durable receipt",
            "thread-private-r5",
            "turn-private-r5",
            "C:\\private\\r5-workspace",
            envelope.decode("ascii"),
            "capability-private-r5",
        ):
            self.assertNotIn(private_value, serialized)

    def test_missing_or_failing_host_never_creates_false_receipt(self):
        proposal, _, request, intent = self._prepared()
        with self.assertRaisesRegex(
            AtomicHostLaunchError,
            "HOST_ATOMIC_LAUNCHER_REQUIRED",
        ):
            launch_atomic_turn_start(
                proposal,
                intent,
                request,
                b"opaque",
                object(),
                now=NOW,
            )
        launcher = RecordingAtomicLauncher(
            failure=RuntimeError("private host transport failure")
        )
        with self.assertRaisesRegex(
            AtomicHostLaunchError,
            "HOST_ATOMIC_LAUNCH_FAILED",
        ) as raised:
            launch_atomic_turn_start(
                proposal,
                intent,
                request,
                b"opaque",
                launcher,
                now=NOW,
            )
        self.assertNotIn("private host transport failure", str(raised.exception))

    def test_host_request_binding_closes_mutation_window(self):
        proposal, _, request, intent = self._prepared()
        request["params"]["input"][0]["text"] = "mutated after capability"
        launcher = RecordingAtomicLauncher()
        with self.assertRaisesRegex(
            AtomicHostLaunchError,
            "HOST_ATOMIC_LAUNCH_FAILED",
        ):
            launch_atomic_turn_start(
                proposal,
                intent,
                request,
                b"opaque",
                launcher,
                now=NOW,
            )
        self.assertEqual(len(launcher.calls), 1)

        proposal, _, request, intent = self._prepared()
        request["params"]["threadId"] = "other-thread"
        launcher = RecordingAtomicLauncher()
        with self.assertRaisesRegex(
            AtomicHostLaunchError,
            "TURN_START_REQUEST_BINDING_INVALID",
        ):
            launch_atomic_turn_start(
                proposal,
                intent,
                request,
                b"opaque",
                launcher,
                now=NOW,
            )
        self.assertEqual(launcher.calls, [])

    def test_replay_and_host_attestation_drift_fail_closed(self):
        proposal, _, request, intent = self._prepared()
        launcher = RecordingAtomicLauncher()
        envelope = b"same-one-use-capability"
        launch_atomic_turn_start(
            proposal,
            intent,
            request,
            envelope,
            launcher,
            now=NOW,
        )
        with self.assertRaisesRegex(
            AtomicHostLaunchError,
            "HOST_ATOMIC_LAUNCH_FAILED",
        ):
            launch_atomic_turn_start(
                proposal,
                intent,
                request,
                envelope,
                launcher,
                now=NOW,
            )
        self.assertEqual(len(launcher.calls), 2)

        cases = [
            ({"capability_verified": False}, "CAPABILITY_VERIFIED_REQUIRED"),
            ({"nonce_consumed": False}, "NONCE_CONSUMED_REQUIRED"),
            (
                {"request_binding_verified": False},
                "REQUEST_BINDING_VERIFIED_REQUIRED",
            ),
            (
                {"attestation_validated": False},
                "ATTESTATION_VALIDATED_REQUIRED",
            ),
            (
                {"permission_boundary_validated": False},
                "PERMISSION_BOUNDARY_VALIDATED_REQUIRED",
            ),
            ({"consent_validated": False}, "CONSENT_VALIDATED_REQUIRED"),
            ({"budget_consumed": False}, "BUDGET_CONSUMED_REQUIRED"),
            ({"request_sent": False}, "REQUEST_SENT_REQUIRED"),
            ({"turn_started": False}, "TURN_STARTED_REQUIRED"),
            ({"starts_consumed": True}, "START_BUDGET_INVALID"),
            ({"audience": "other_client"}, "AUDIENCE_MISMATCH"),
            ({"turn_id_sha256": "9" * 64}, "TURN_ID_SHA256_MISMATCH"),
        ]
        for overrides, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(AtomicHostLaunchError, message):
                    launch_atomic_turn_start(
                        proposal,
                        intent,
                        request,
                        b"unique-" + message.encode("ascii"),
                        RecordingAtomicLauncher(
                            result_overrides=overrides
                        ),
                        now=NOW,
                    )

    def test_response_and_capability_lifetime_fail_closed(self):
        proposal, _, request, intent = self._prepared()
        response_cases = [
            {"turn": {"id": "turn-private-r5", "items": [], "status": "failed"}},
            {
                "turn": {
                    "id": "turn-private-r5",
                    "items": [{"type": "agentMessage"}],
                    "status": "inProgress",
                }
            },
        ]
        for response in response_cases:
            with self.subTest(response=response):
                with self.assertRaisesRegex(
                    AtomicHostLaunchError,
                    "TURN_START_RESPONSE_INVALID",
                ):
                    launch_atomic_turn_start(
                        proposal,
                        intent,
                        request,
                        b"response-case-" + str(response).encode("utf-8"),
                        RecordingAtomicLauncher(
                            response_overrides=response
                        ),
                        now=NOW,
                    )
        with self.assertRaisesRegex(
            AtomicHostLaunchError,
            "HOST_CAPABILITY_EXPIRED_OR_INVALID",
        ):
            launch_atomic_turn_start(
                proposal,
                intent,
                request,
                b"expired",
                RecordingAtomicLauncher(
                    result_overrides={
                        "expires_at_utc": "2026-07-28T01:59:30Z"
                    }
                ),
                now=NOW,
            )
        _, receipt = launch_atomic_turn_start(
            proposal,
            intent,
            request,
            b"receipt-time-binding",
            RecordingAtomicLauncher(),
            now=NOW,
        )
        tampered = copy.deepcopy(receipt)
        tampered["capability"]["expires_at_utc"] = (
            "2026-07-28T01:58:00Z"
        )
        tampered["receipt_sha256"] = json_digest(
            {
                key: value
                for key, value in tampered.items()
                if key != "receipt_sha256"
            }
        )
        with self.assertRaisesRegex(
            AtomicHostLaunchError,
            "ATOMIC_LAUNCH_RECEIPT_STATE_INVALID",
        ):
            validate_atomic_launch_receipt(tampered, proposal=proposal)

    def test_launch_outcome_join_proves_causal_identity(self):
        proposal, _, request, intent = self._prepared()
        _, receipt = launch_atomic_turn_start(
            proposal,
            intent,
            request,
            b"join-capability",
            RecordingAtomicLauncher(),
            now=NOW,
        )
        outcome = _outcome(proposal)
        join = build_launch_outcome_join(
            receipt,
            outcome,
            proposal=proposal,
        )
        self.assertEqual(set(join), JOIN_FIELDS)
        self.assertEqual(
            validate_launch_outcome_join(
                join,
                launch_receipt=receipt,
                outcome=outcome,
            ),
            join,
        )
        invalid_join = copy.deepcopy(join)
        invalid_join["arm"] = "INVALID_ARM"
        invalid_join["join_sha256"] = json_digest(
            {
                key: value
                for key, value in invalid_join.items()
                if key != "join_sha256"
            }
        )
        with self.assertRaisesRegex(
            AtomicHostLaunchError,
            "LAUNCH_OUTCOME_JOIN_STATE_INVALID",
        ):
            validate_launch_outcome_join(invalid_join)
        wrong_outcome = _outcome(proposal, turn_id="different-turn")
        with self.assertRaisesRegex(
            AtomicHostLaunchError,
            "LAUNCH_OUTCOME_BINDING_INVALID",
        ):
            build_launch_outcome_join(
                receipt,
                wrong_outcome,
                proposal=proposal,
            )

    def test_schemas_are_strict_and_match_runtime_contract(self):
        schema_names = {
            "codex-app-server-atomic-host-launch-r1-intent.schema.json": (
                INTENT_FIELDS
            ),
            "codex-app-server-atomic-host-launch-r1-receipt.schema.json": (
                RECEIPT_FIELDS
            ),
            "codex-app-server-atomic-host-launch-r1-join.schema.json": (
                JOIN_FIELDS
            ),
        }
        for name, expected_fields in schema_names.items():
            with self.subTest(schema=name):
                schema = json.loads(
                    (ROOT / "schemas" / name).read_text(encoding="utf-8")
                )
                self.assertFalse(schema["additionalProperties"])
                self.assertEqual(set(schema["required"]), expected_fields)
                self.assertEqual(set(schema["properties"]), expected_fields)
        claims = json.loads(
            (
                ROOT
                / "schemas"
                / "codex-app-server-host-capability-r2-atomic-claims.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertFalse(claims["additionalProperties"])
        self.assertEqual(
            set(claims["required"]),
            set(claims["properties"]),
        )
        self.assertEqual(
            claims["properties"]["maximum_model_starts"]["const"],
            1,
        )
        self.assertEqual(set(HOST_RESULT_FIELDS) - {"launched_at_utc"}, {
            "capability_version",
            "status",
            "issuer",
            "audience",
            "issued_at_utc",
            "expires_at_utc",
            "capability_id_sha256",
            "capability_envelope_sha256",
            "nonce_sha256",
            "launch_intent_sha256",
            "proposal_sha256",
            "plan_sha256",
            "assignment_id",
            *HOST_BINDING_FIELDS,
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
        })


if __name__ == "__main__":
    unittest.main()
