from __future__ import annotations

import copy
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from mtr_dogfood.app_server_experiment import (
    AUTHORITY_BOUNDARY as PROPOSAL_AUTHORITY_BOUNDARY,
    COMPONENT_ID as PROPOSAL_COMPONENT_ID,
    PRIVACY_BOUNDARY as PROPOSAL_PRIVACY_BOUNDARY,
    validate_proposal,
)
from mtr_dogfood.app_server_host_adapter import (
    AUTHORITY_BOUNDARY,
    CAPABILITY_CLAIM_FIELDS,
    COMPONENT_ID,
    PRIVACY_BOUNDARY,
    RECEIPT_FIELDS,
    AppServerHostAdapterError,
    build_initialize_request,
    build_initialized_notification,
    build_model_list_request,
    compile_turn_start_request,
    merge_model_list_pages,
    validate_launch_receipt,
)
from mtr_dogfood.config import json_digest


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 7, 27, 12, 0, tzinfo=timezone.utc)


def _proposal() -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "1.0.0",
        "component_id": PROPOSAL_COMPONENT_ID,
        "status": "host_review_required",
        "assignment_id": "assignment-1",
        "plan_sha256": "1" * 64,
        "experiment": {
            "experiment_id": "host-adapter-r1",
            "assignment_unit_sha256": "2" * 64,
            "assignment_bucket": 123,
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
            "kind": "product",
            "issuer": "codex-desktop-host",
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


def _claims(
    proposal: dict[str, object],
    **overrides: object,
) -> dict[str, object]:
    binding = proposal["app_server_binding"]
    selection = proposal["selection"]
    value: dict[str, object] = {
        "capability_version": "1.0.0",
        "capability_id": "capability-private-1",
        "issuer": "openai-codex-host-test",
        "audience": binding["client_info_name"],
        "issued_at_utc": "2026-07-27T11:59:00Z",
        "expires_at_utc": "2026-07-27T12:05:00Z",
        "nonce_sha256": "8" * 64,
        "proposal_sha256": proposal["proposal_sha256"],
        "plan_sha256": proposal["plan_sha256"],
        "assignment_id": proposal["assignment_id"],
        "protocol_schema_sha256": binding["protocol_schema_sha256"],
        "model_list_response_sha256": binding[
            "model_list_response_sha256"
        ],
        "selected_model_entry_sha256": binding[
            "selected_model_entry_sha256"
        ],
        "authorized_method": "turn/start",
        "authorized_model": selection["requested_model"],
        "authorized_effort": selection["requested_effort"],
        "maximum_model_starts": 1,
        "host_catalog_validated": True,
        "host_entitlement_validated": True,
        "host_assignment_validated": True,
        "host_attestation_validated": True,
        "permission_expansion_authorized": False,
        "approval_policy_override_authorized": False,
        "sandbox_override_authorized": False,
        "network_expansion_authorized": False,
        "authorized_write_scope": [],
    }
    value.update(overrides)
    return value


def _base_params() -> dict[str, object]:
    return {
        "threadId": "thread-private-1",
        "input": [
            {
                "type": "text",
                "text": "private prompt that must not enter the receipt",
            }
        ],
        "cwd": "C:\\private\\workspace",
        "approvalPolicy": "unlessTrusted",
        "sandboxPolicy": {
            "type": "workspaceWrite",
            "writableRoots": ["C:\\private\\workspace"],
            "networkAccess": True,
        },
        "personality": "friendly",
        "model": "gpt-5.6-sol",
        "effort": "high",
    }


class RecordingVerifier:
    def __init__(
        self,
        claims: dict[str, object],
        *,
        failure: Exception | None = None,
    ):
        self.claims = copy.deepcopy(claims)
        self.failure = failure
        self.calls: list[bytes] = []

    def verify(self, envelope: bytes) -> dict[str, object]:
        self.calls.append(envelope)
        if self.failure is not None:
            raise self.failure
        return copy.deepcopy(self.claims)


class RecordingNonceConsumer:
    def __init__(self, *, accepted: bool = True):
        self.accepted = accepted
        self.calls: list[tuple[str, str]] = []

    def consume(self, nonce_sha256: str, expires_at_utc: str) -> bool:
        self.calls.append((nonce_sha256, expires_at_utc))
        return self.accepted


class AppServerHostAdapterTests(unittest.TestCase):
    def test_stable_preflight_messages_and_catalog_pagination(self):
        initialize = build_initialize_request(
            client_info_name="mtr_dogfood",
            client_title="MTR Dogfood",
            client_version="1.0.0",
        )
        self.assertEqual(initialize["method"], "initialize")
        self.assertEqual(
            initialize["params"]["capabilities"],
            {"experimentalApi": False, "requestAttestation": True},
        )
        self.assertEqual(
            build_initialized_notification(),
            {"method": "initialized", "params": {}},
        )
        first_request = build_model_list_request(request_id=1)
        second_request = build_model_list_request(
            request_id=2,
            cursor="page-2",
        )
        self.assertFalse(first_request["params"]["includeHidden"])
        self.assertIsNone(first_request["params"]["cursor"])
        self.assertEqual(second_request["params"]["cursor"], "page-2")

        merged = merge_model_list_pages(
            [
                {
                    "data": [{"id": "terra", "model": "gpt-5.6-terra"}],
                    "nextCursor": "page-2",
                },
                {
                    "data": [{"id": "sol", "model": "gpt-5.6-sol"}],
                    "nextCursor": None,
                },
            ]
        )
        self.assertEqual(len(merged["data"]), 2)
        self.assertIsNone(merged["nextCursor"])
        with self.assertRaisesRegex(
            AppServerHostAdapterError, "MODEL_CATALOG_INCOMPLETE"
        ):
            merge_model_list_pages(
                [{"data": [], "nextCursor": "still-more"}]
            )
        with self.assertRaisesRegex(
            AppServerHostAdapterError, "MODEL_CATALOG_DUPLICATE"
        ):
            merge_model_list_pages(
                [
                    {
                        "data": [
                            {"id": "one", "model": "gpt-5.6-terra"},
                            {"id": "two", "model": "gpt-5.6-terra"},
                        ],
                        "nextCursor": None,
                    }
                ]
            )

    def test_verified_capability_compiles_only_model_fields(self):
        proposal = _proposal()
        claims = _claims(proposal)
        verifier = RecordingVerifier(claims)
        nonce = RecordingNonceConsumer()
        original = _base_params()
        snapshot = copy.deepcopy(original)
        envelope = b"opaque-signed-host-capability"

        request, receipt = compile_turn_start_request(
            proposal,
            envelope,
            verifier,
            nonce,
            original,
            request_id=30,
            now=NOW,
        )

        self.assertEqual(original, snapshot)
        self.assertEqual(request["method"], "turn/start")
        self.assertEqual(request["id"], 30)
        self.assertEqual(request["params"]["model"], "gpt-5.6-terra")
        self.assertEqual(request["params"]["effort"], "medium")
        for field, value in snapshot.items():
            if field not in {"model", "effort"}:
                self.assertEqual(request["params"][field], value)
        self.assertEqual(verifier.calls, [envelope])
        self.assertEqual(
            nonce.calls,
            [("8" * 64, "2026-07-27T12:05:00Z")],
        )
        self.assertEqual(
            validate_launch_receipt(receipt, proposal=proposal),
            receipt,
        )
        self.assertEqual(set(receipt), RECEIPT_FIELDS)
        self.assertEqual(receipt["authority_boundary"], AUTHORITY_BOUNDARY)
        self.assertEqual(receipt["privacy"], PRIVACY_BOUNDARY)
        serialized = json.dumps(receipt, ensure_ascii=False)
        for private_value in (
            "private prompt that must not enter the receipt",
            "thread-private-1",
            "C:\\private\\workspace",
            "capability-private-1",
            envelope.decode("ascii"),
        ):
            self.assertNotIn(private_value, serialized)

    def test_local_json_or_verifier_error_never_becomes_authority(self):
        proposal = _proposal()
        base = _base_params()
        nonce = RecordingNonceConsumer()
        with self.assertRaisesRegex(
            AppServerHostAdapterError,
            "HOST_CAPABILITY_VERIFIER_REQUIRED",
        ):
            compile_turn_start_request(
                proposal,
                b"local-json-is-not-authority",
                object(),
                nonce,
                base,
                request_id=1,
                now=NOW,
            )
        verifier = RecordingVerifier(
            _claims(proposal),
            failure=RuntimeError("private verifier detail"),
        )
        with self.assertRaisesRegex(
            AppServerHostAdapterError,
            "HOST_CAPABILITY_VERIFICATION_FAILED",
        ) as raised:
            compile_turn_start_request(
                proposal,
                b"opaque",
                verifier,
                nonce,
                base,
                request_id=1,
                now=NOW,
            )
        self.assertNotIn("private verifier detail", str(raised.exception))
        self.assertEqual(nonce.calls, [])

    def test_capability_binding_scope_and_authority_fail_closed(self):
        proposal = _proposal()
        cases = [
            (
                {"proposal_sha256": "9" * 64},
                "HOST_CAPABILITY_PROPOSAL_SHA256_MISMATCH",
            ),
            (
                {"authorized_model": "gpt-5.6-sol"},
                "HOST_CAPABILITY_AUTHORIZED_MODEL_MISMATCH",
            ),
            (
                {"audience": "other_client"},
                "HOST_CAPABILITY_AUDIENCE_MISMATCH",
            ),
            (
                {"maximum_model_starts": 2},
                "HOST_CAPABILITY_SCOPE_INVALID",
            ),
            (
                {"maximum_model_starts": True},
                "HOST_CAPABILITY_SCOPE_INVALID",
            ),
            (
                {"host_entitlement_validated": False},
                "HOST_CAPABILITY_HOST_ENTITLEMENT_VALIDATED_REQUIRED",
            ),
            (
                {"network_expansion_authorized": True},
                "HOST_CAPABILITY_NETWORK_EXPANSION_AUTHORIZED_FORBIDDEN",
            ),
            (
                {"authorized_write_scope": ["C:\\"]},
                "HOST_CAPABILITY_WRITE_SCOPE_FORBIDDEN",
            ),
            (
                {"expires_at_utc": "2026-07-27T11:59:30Z"},
                "HOST_CAPABILITY_EXPIRED_OR_INVALID",
            ),
            (
                {
                    "issued_at_utc": "2026-07-27T11:00:00Z",
                    "expires_at_utc": "2026-07-27T12:01:00Z",
                },
                "HOST_CAPABILITY_EXPIRED_OR_INVALID",
            ),
        ]
        for overrides, message in cases:
            with self.subTest(message=message):
                nonce = RecordingNonceConsumer()
                with self.assertRaisesRegex(
                    AppServerHostAdapterError, message
                ):
                    compile_turn_start_request(
                        proposal,
                        b"opaque",
                        RecordingVerifier(
                            _claims(proposal, **overrides)
                        ),
                        nonce,
                        _base_params(),
                        request_id=1,
                        now=NOW,
                    )
                self.assertEqual(nonce.calls, [])

    def test_replay_and_invalid_request_fail_without_false_receipt(self):
        proposal = _proposal()
        claims = _claims(proposal)
        replay = RecordingNonceConsumer(accepted=False)
        with self.assertRaisesRegex(
            AppServerHostAdapterError, "HOST_CAPABILITY_REPLAYED"
        ):
            compile_turn_start_request(
                proposal,
                b"opaque",
                RecordingVerifier(claims),
                replay,
                _base_params(),
                request_id=1,
                now=NOW,
            )
        self.assertEqual(len(replay.calls), 1)

        nonce = RecordingNonceConsumer()
        with self.assertRaisesRegex(
            AppServerHostAdapterError, "REQUEST_ID_INVALID"
        ):
            compile_turn_start_request(
                proposal,
                b"opaque",
                RecordingVerifier(claims),
                nonce,
                _base_params(),
                request_id=True,
                now=NOW,
            )
        self.assertEqual(nonce.calls, [])

    def test_receipt_digest_and_semantics_fail_closed(self):
        proposal = _proposal()
        _, receipt = compile_turn_start_request(
            proposal,
            b"opaque",
            RecordingVerifier(_claims(proposal)),
            RecordingNonceConsumer(),
            _base_params(),
            request_id=1,
            now=NOW,
        )
        tampered = copy.deepcopy(receipt)
        tampered["request"]["model_started"] = True
        tampered["receipt_sha256"] = json_digest(
            {
                key: value
                for key, value in tampered.items()
                if key != "receipt_sha256"
            }
        )
        with self.assertRaisesRegex(
            AppServerHostAdapterError, "LAUNCH_RECEIPT_STATE_INVALID"
        ):
            validate_launch_receipt(tampered, proposal=proposal)

    def test_claim_and_receipt_schemas_match_runtime_contract(self):
        claims_schema = json.loads(
            (
                ROOT
                / "schemas"
                / "codex-app-server-host-capability-r1-claims.schema.json"
            ).read_text(encoding="utf-8")
        )
        receipt_schema = json.loads(
            (
                ROOT
                / "schemas"
                / "codex-app-server-host-launch-r1-receipt.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertFalse(claims_schema["additionalProperties"])
        self.assertFalse(receipt_schema["additionalProperties"])
        self.assertEqual(
            set(claims_schema["required"]),
            CAPABILITY_CLAIM_FIELDS,
        )
        self.assertEqual(
            set(claims_schema["properties"]),
            CAPABILITY_CLAIM_FIELDS,
        )
        self.assertEqual(set(receipt_schema["required"]), RECEIPT_FIELDS)
        self.assertEqual(set(receipt_schema["properties"]), RECEIPT_FIELDS)


if __name__ == "__main__":
    unittest.main()
