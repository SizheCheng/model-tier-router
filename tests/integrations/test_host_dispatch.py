from __future__ import annotations

import copy
import hashlib
import unittest
from datetime import datetime, timezone

from model_tier_router import assess
from model_tier_router.host_dispatch import (
    CAPABILITY_VERSION,
    HostDispatchError,
    MODEL_MAP_SCHEMA_VERSION,
    build_atomic_launch_intent,
    build_dispatch_proposal,
    launch_atomic_turn_start,
    validate_atomic_launch_intent,
    validate_atomic_launch_receipt,
    validate_dispatch_proposal,
)
from model_tier_router.schema_validation import (
    SchemaValidationError,
    validate_host_dispatch_intent,
    validate_host_dispatch_proposal,
    validate_host_dispatch_receipt,
)
from model_tier_router.strict_json import canonical_json_bytes


NOW = datetime(2026, 7, 30, 3, 40, 0, tzinfo=timezone.utc)
CAPABILITY = b"synthetic-host-capability-envelope"
PROMPT_MARKER = "SYNTHETIC_PRIVATE_PROMPT_MARKER"


def _request() -> dict[str, object]:
    return {
        "schema_version": "model_tier_router_advisory_request_v1alpha1",
        "request_id": "host-dispatch-test",
        "requirements": {
            "modalities": ["text"],
            "tool_support": True,
        },
        "preferences": ["higher_reasoning"],
        "evidence": {
            "modalities": True,
            "tool_support": True,
        },
    }


def _model_map() -> dict[str, object]:
    return {
        "schema_version": MODEL_MAP_SCHEMA_VERSION,
        "mapping_id": "synthetic-codex-map-r1",
        "profiles": {
            "economy": {"model": "model-economy", "effort": "low"},
            "balanced": {"model": "model-balanced", "effort": "medium"},
            "premium": {"model": "model-premium", "effort": "high"},
        },
    }


def _catalog() -> dict[str, object]:
    return {
        "data": [
            {
                "id": "model-economy",
                "model": "model-economy",
                "supportedReasoningEfforts": [
                    {"reasoningEffort": "low", "description": "low"}
                ],
            },
            {
                "id": "model-balanced",
                "model": "model-balanced",
                "supportedReasoningEfforts": [
                    {"reasoningEffort": "medium", "description": "medium"}
                ],
            },
            {
                "id": "model-premium",
                "model": "model-premium",
                "supportedReasoningEfforts": [
                    {"reasoningEffort": "high", "description": "high"}
                ],
            },
        ],
        "nextCursor": None,
    }


def _proposal() -> dict[str, object]:
    return build_dispatch_proposal(
        assess(_request()),
        _model_map(),
        _catalog(),
        origin_sha256="a" * 64,
        protocol_schema_sha256="b" * 64,
    )


def _bindings() -> dict[str, str]:
    return {
        "host_request_binding_sha256": "1" * 64,
        "host_context_binding_sha256": "2" * 64,
        "host_instance_sha256": "3" * 64,
        "connection_sha256": "4" * 64,
        "consent_grant_sha256": "5" * 64,
        "budget_lease_sha256": "6" * 64,
    }


def _params() -> dict[str, object]:
    return {
        "threadId": "thread_fixture_123",
        "input": [{"type": "text", "text": PROMPT_MARKER}],
        "cwd": "/synthetic/project",
        "approvalPolicy": "never",
        "sandboxPolicy": {
            "type": "workspaceWrite",
            "writableRoots": ["/synthetic/project"],
            "networkAccess": False,
        },
        "model": "caller-model-that-must-be-replaced",
        "effort": "low",
        "summary": "concise",
    }


def _host_result(
    proposal: dict[str, object],
    intent: dict[str, object],
    *,
    turn_id: str,
) -> dict[str, object]:
    request = intent["request"]
    selection = intent["selection"]
    assert isinstance(request, dict)
    assert isinstance(selection, dict)
    return {
        "capability_version": CAPABILITY_VERSION,
        "capability_id_sha256": "7" * 64,
        "capability_envelope_sha256": hashlib.sha256(CAPABILITY).hexdigest(),
        "issuer": "synthetic-codex-host",
        "audience": "model-tier-router",
        "issued_at_utc": "2026-07-30T03:39:30Z",
        "expires_at_utc": "2026-07-30T03:44:30Z",
        "nonce_sha256": "8" * 64,
        "proposal_sha256": proposal["proposal_sha256"],
        "intent_sha256": intent["intent_sha256"],
        "exact_request_sha256": request["exact_request_sha256"],
        "authorized_model": selection["model"],
        "authorized_effort": selection["effort"],
        "maximum_model_starts": 1,
        "starts_consumed": 1,
        "capability_authenticated": True,
        "nonce_consumed": True,
        "catalog_validated": True,
        "entitlement_validated": True,
        "consent_validated": True,
        "budget_consumed": True,
        "request_binding_verified": True,
        "context_binding_verified": True,
        "permission_boundary_validated": True,
        "transport_identity_validated": True,
        "attestation_validated": True,
        "turn_id_sha256": hashlib.sha256(turn_id.encode()).hexdigest(),
        "launched_at_utc": "2026-07-30T03:40:00Z",
    }


class _Host:
    def __init__(self) -> None:
        self.calls = 0
        self.request: dict[str, object] | None = None

    def launch(
        self,
        capability_envelope: bytes,
        request: dict[str, object],
        intent: dict[str, object],
    ) -> tuple[dict[str, object], dict[str, object]]:
        self.calls += 1
        if self.calls > 1:
            raise RuntimeError("synthetic replay rejection")
        if capability_envelope != CAPABILITY:
            raise AssertionError("capability drift")
        self.request = copy.deepcopy(request)
        turn_id = "turn_fixture_456"
        response = {
            "turn": {
                "id": turn_id,
                "status": "inProgress",
                "items": [],
                "itemsView": "full",
                "startedAt": None,
                "error": None,
            }
        }
        return response, _host_result(_proposal(), intent, turn_id=turn_id)


class HostDispatchTests(unittest.TestCase):
    def test_proposal_binds_advisory_mapping_and_catalog_without_authorizing(self):
        proposal = _proposal()
        self.assertEqual(validate_dispatch_proposal(proposal), proposal)
        self.assertEqual(proposal["advisory"]["selected_profile"], "premium")
        self.assertEqual(proposal["selection"], {
            "model": "model-premium",
            "effort": "high",
        })
        self.assertIs(proposal["advisory"]["execution_authorized"], False)
        self.assertEqual(proposal["advisory"]["authorized_write_scope"], [])
        self.assertIs(
            proposal["authority_boundary"]["router_output_authorizes_launch"],
            False,
        )
        self.assertIs(
            proposal["authority_boundary"]["host_capability_required"],
            True,
        )

    def test_public_schemas_accept_outputs_and_reject_unknown_fields(self):
        proposal = _proposal()
        request, intent = build_atomic_launch_intent(
            proposal,
            _params(),
            _bindings(),
            request_id=41,
        )
        _, receipt = launch_atomic_turn_start(
            proposal,
            intent,
            request,
            CAPABILITY,
            _Host(),
            now=NOW,
        )
        cases = (
            (validate_host_dispatch_proposal, proposal),
            (validate_host_dispatch_intent, intent),
            (validate_host_dispatch_receipt, receipt),
        )
        for validator, value in cases:
            with self.subTest(validator=validator.__name__):
                validator(value)
                tampered = copy.deepcopy(value)
                tampered["unexpected"] = True
                with self.assertRaises(SchemaValidationError):
                    validator(tampered)

    def test_proposal_rejects_tampering_and_catalog_or_effort_drift(self):
        forged_decision = assess(_request())
        forged_decision["selected_profile"] = "balanced"
        with self.assertRaisesRegex(
            HostDispatchError,
            "ADVISORY_DECISION_DIGEST_INVALID",
        ):
            build_dispatch_proposal(
                forged_decision,
                _model_map(),
                _catalog(),
                origin_sha256="a" * 64,
                protocol_schema_sha256="b" * 64,
            )

        tampered = _proposal()
        tampered["selection"]["model"] = "other-model"
        with self.assertRaisesRegex(
            HostDispatchError,
            "DISPATCH_PROPOSAL_DIGEST_INVALID",
        ):
            validate_dispatch_proposal(tampered)

        catalog = _catalog()
        del catalog["data"][-1]["supportedReasoningEfforts"]
        with self.assertRaisesRegex(
            HostDispatchError,
            "MODEL_CATALOG_EFFORTS_INVALID",
        ):
            build_dispatch_proposal(
                assess(_request()),
                _model_map(),
                catalog,
                origin_sha256="a" * 64,
                protocol_schema_sha256="b" * 64,
            )

        catalog = _catalog()
        catalog["data"][-1]["supportedReasoningEfforts"][0][
            "reasoningEffort"
        ] = "medium"
        with self.assertRaisesRegex(
            HostDispatchError,
            "MODEL_CATALOG_EFFORT_UNSUPPORTED",
        ):
            build_dispatch_proposal(
                assess(_request()),
                _model_map(),
                catalog,
                origin_sha256="a" * 64,
                protocol_schema_sha256="b" * 64,
            )

    def test_intent_changes_only_model_and_effort_and_redacts_prompt(self):
        proposal = _proposal()
        original = _params()
        request, intent = build_atomic_launch_intent(
            proposal,
            original,
            _bindings(),
            request_id=42,
        )
        self.assertEqual(
            validate_atomic_launch_intent(intent, proposal=proposal),
            intent,
        )
        expected = copy.deepcopy(original)
        expected["model"] = "model-premium"
        expected["effort"] = "high"
        self.assertEqual(request, {
            "method": "turn/start",
            "id": 42,
            "params": expected,
        })
        redacted = canonical_json_bytes(intent).decode()
        self.assertNotIn(PROMPT_MARKER, redacted)
        self.assertNotIn("thread_fixture_123", redacted)
        self.assertNotIn("/synthetic/project", redacted)

    def test_naive_clock_is_rejected_before_host_call(self):
        proposal = _proposal()
        request, intent = build_atomic_launch_intent(
            proposal,
            _params(),
            _bindings(),
            request_id=42,
        )
        host = _Host()
        with self.assertRaisesRegex(
            HostDispatchError,
            "HOST_LAUNCH_TIME_INVALID",
        ):
            launch_atomic_turn_start(
                proposal,
                intent,
                request,
                CAPABILITY,
                host,
                now=datetime(2026, 7, 30, 3, 40, 0),
            )
        self.assertEqual(host.calls, 0)

    def test_host_launch_delay_is_bounded(self):
        proposal = _proposal()
        request, intent = build_atomic_launch_intent(
            proposal,
            _params(),
            _bindings(),
            request_id=43,
        )

        class DelayedHost(_Host):
            def launch(self, capability_envelope, request, received_intent):
                response, result = super().launch(
                    capability_envelope,
                    request,
                    received_intent,
                )
                result["launched_at_utc"] = "2026-07-30T03:41:01Z"
                return response, result

        with self.assertRaisesRegex(
            HostDispatchError,
            "HOST_CAPABILITY_LIFETIME_INVALID",
        ):
            launch_atomic_turn_start(
                proposal,
                intent,
                request,
                CAPABILITY,
                DelayedHost(),
                now=NOW,
            )

    def test_post_intent_request_mutation_is_rejected_before_host(self):
        proposal = _proposal()
        request, intent = build_atomic_launch_intent(
            proposal,
            _params(),
            _bindings(),
            request_id=43,
        )
        request["params"]["cwd"] = "/synthetic/mutated"
        host = _Host()
        with self.assertRaisesRegex(
            HostDispatchError,
            "TURN_START_REQUEST_BINDING_INVALID",
        ):
            launch_atomic_turn_start(
                proposal,
                intent,
                request,
                CAPABILITY,
                host,
                now=NOW,
            )
        self.assertEqual(host.calls, 0)

    def test_atomic_host_launch_returns_redacted_bound_receipt(self):
        proposal = _proposal()
        request, intent = build_atomic_launch_intent(
            proposal,
            _params(),
            _bindings(),
            request_id=44,
        )
        host = _Host()
        response, receipt = launch_atomic_turn_start(
            proposal,
            intent,
            request,
            CAPABILITY,
            host,
            now=NOW,
        )
        self.assertEqual(host.calls, 1)
        self.assertEqual(response["turn"]["status"], "inProgress")
        self.assertEqual(
            validate_atomic_launch_receipt(
                receipt,
                proposal=proposal,
                intent=intent,
            ),
            receipt,
        )
        serialized = canonical_json_bytes(receipt).decode()
        self.assertNotIn(PROMPT_MARKER, serialized)
        self.assertNotIn(CAPABILITY.decode(), serialized)
        self.assertNotIn("turn_fixture_456", serialized)
        self.assertEqual(receipt["response"]["starts_consumed"], 1)
        self.assertIs(receipt["capability"]["nonce_consumed"], True)
        self.assertIs(receipt["host"]["entitlement_validated"], True)

    def test_current_app_server_turn_metadata_is_accepted(self):
        proposal = _proposal()
        request, intent = build_atomic_launch_intent(
            proposal,
            _params(),
            _bindings(),
            request_id=48,
        )

        for items_view in ("notLoaded", "summary", "full"):
            class CurrentSchemaHost(_Host):
                def launch(
                    self,
                    capability_envelope,
                    received_request,
                    received_intent,
                ):
                    response, result = super().launch(
                        capability_envelope,
                        received_request,
                        received_intent,
                    )
                    response["turn"]["itemsView"] = items_view
                    response["turn"]["startedAt"] = None
                    return response, result

            response, receipt = launch_atomic_turn_start(
                proposal,
                intent,
                request,
                CAPABILITY,
                CurrentSchemaHost(),
                now=NOW,
            )
            self.assertEqual(response["turn"]["itemsView"], items_view)
            self.assertIsNone(response["turn"]["startedAt"])
            self.assertEqual(receipt["status"], "host_started")

    def test_invalid_turn_metadata_fails_closed(self):
        proposal = _proposal()
        request, intent = build_atomic_launch_intent(
            proposal,
            _params(),
            _bindings(),
            request_id=49,
        )

        for field, value in (
            ("itemsView", []),
            ("itemsView", "complete"),
            ("startedAt", -1),
            ("startedAt", True),
        ):
            class InvalidSchemaHost(_Host):
                def launch(
                    self,
                    capability_envelope,
                    received_request,
                    received_intent,
                ):
                    response, result = super().launch(
                        capability_envelope,
                        received_request,
                        received_intent,
                    )
                    response["turn"][field] = value
                    return response, result

            with self.subTest(field=field, value=value):
                with self.assertRaisesRegex(
                    HostDispatchError,
                    "TURN_START_RESPONSE_INVALID",
                ):
                    launch_atomic_turn_start(
                        proposal,
                        intent,
                        request,
                        CAPABILITY,
                        InvalidSchemaHost(),
                        now=NOW,
                    )

    def test_boolean_budget_and_false_attestation_fail_closed(self):
        proposal = _proposal()
        request, intent = build_atomic_launch_intent(
            proposal,
            _params(),
            _bindings(),
            request_id=45,
        )

        class BadHost(_Host):
            def launch(self, capability_envelope, request, received_intent):
                response, result = super().launch(
                    capability_envelope,
                    request,
                    received_intent,
                )
                result["starts_consumed"] = True
                return response, result

        with self.assertRaisesRegex(
            HostDispatchError,
            "HOST_START_BUDGET_INVALID",
        ):
            launch_atomic_turn_start(
                proposal,
                intent,
                request,
                CAPABILITY,
                BadHost(),
                now=NOW,
            )

        class UnverifiedHost(_Host):
            def launch(self, capability_envelope, request, received_intent):
                response, result = super().launch(
                    capability_envelope,
                    request,
                    received_intent,
                )
                result["entitlement_validated"] = False
                return response, result

        with self.assertRaisesRegex(
            HostDispatchError,
            "HOST_ATOMIC_LAUNCH_ATTESTATION_INVALID",
        ):
            launch_atomic_turn_start(
                proposal,
                intent,
                request,
                CAPABILITY,
                UnverifiedHost(),
                now=NOW,
            )

    def test_capability_replay_and_launcher_failure_have_no_false_receipt(self):
        proposal = _proposal()
        request, intent = build_atomic_launch_intent(
            proposal,
            _params(),
            _bindings(),
            request_id=46,
        )
        host = _Host()
        launch_atomic_turn_start(
            proposal,
            intent,
            request,
            CAPABILITY,
            host,
            now=NOW,
        )
        with self.assertRaisesRegex(
            HostDispatchError,
            "HOST_ATOMIC_LAUNCH_FAILED",
        ):
            launch_atomic_turn_start(
                proposal,
                intent,
                request,
                CAPABILITY,
                host,
                now=NOW,
            )
        self.assertEqual(host.calls, 2)

    def test_invalid_capability_and_receipt_tampering_fail_closed(self):
        proposal = _proposal()
        request, intent = build_atomic_launch_intent(
            proposal,
            _params(),
            _bindings(),
            request_id=47,
        )
        with self.assertRaisesRegex(
            HostDispatchError,
            "HOST_CAPABILITY_ENVELOPE_INVALID",
        ):
            launch_atomic_turn_start(
                proposal,
                intent,
                request,
                b"",
                _Host(),
                now=NOW,
            )
        _, receipt = launch_atomic_turn_start(
            proposal,
            intent,
            request,
            CAPABILITY,
            _Host(),
            now=NOW,
        )
        receipt["response"]["starts_consumed"] = 2
        with self.assertRaisesRegex(
            HostDispatchError,
            "HOST_LAUNCH_RECEIPT_DIGEST_INVALID",
        ):
            validate_atomic_launch_receipt(receipt)


if __name__ == "__main__":
    unittest.main()
