from __future__ import annotations

import copy
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from mtr_dogfood.app_server_experiment import (
    APP_SERVER_BINDING_FIELDS,
    OUTCOME_FIELDS,
    PROPOSAL_FIELDS,
    AppServerExperimentError,
    build_app_server_proposal,
    summarize_app_server_outcome,
    validate_outcome,
    validate_proposal,
)
from mtr_dogfood.authorized_dispatcher import _assignment_bucket, plan_dispatch
from mtr_dogfood.config import json_digest


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 7, 27, 12, 0, tzinfo=timezone.utc)


def _authorization(repository: Path) -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "component_id": "MTR_CODEX_AUTHORIZED_MODEL_DISPATCH_R2",
        "authorization_id": "app-server-r1",
        "authorized_by": "local-user",
        "issued_at_utc": "2026-07-27T00:00:00Z",
        "expires_at_utc": "2026-08-27T00:00:00Z",
        "experiment_id": "app-server-model-experiment-r1",
        "allowed_repository_roots": [str(repository)],
        "allowed_models": ["gpt-5.6-terra", "gpt-5.6-sol"],
        "control_model": "gpt-5.6-sol",
        "control_reasoning_effort": "high",
        "router_share_basis_points": 5_000,
        "maximum_model_starts": 100,
        "model_selection_authorized": True,
        "new_process_launch_authorized": True,
        "permission_expansion_authorized": False,
        "authorized_write_scope": [],
        "network_access_authorized": False,
        "model_service_data_export_authorized": True,
    }


def _decision() -> dict[str, object]:
    return {
        "status": "recommended",
        "selected_profile": "balanced",
        "execution_authorized": False,
        "authorized_write_scope": [],
    }


def _model_map() -> dict[str, object]:
    return {
        "mapping_version": "app-server-fixture-r1",
        "logical_profiles": {
            "balanced": {
                "codex_model": "gpt-5.6-terra",
                "model_reasoning_effort": "medium",
                "next_escalation_profile": "premium",
            },
            "premium": {
                "codex_model": "gpt-5.6-sol",
                "model_reasoning_effort": "high",
                "next_escalation_profile": None,
            },
        },
    }


def _router_unit(experiment_id: str) -> str:
    for index in range(100_000):
        value = f"unit-{index}"
        if _assignment_bucket(experiment_id, value) < 5_000:
            return value
    raise AssertionError("router assignment fixture unavailable")


def _plan(repository: Path) -> dict[str, object]:
    authorization = _authorization(repository)
    unit = _router_unit(str(authorization["experiment_id"]))
    return plan_dispatch(
        authorization,
        _decision(),
        _model_map(),
        repository=repository,
        assignment_unit=unit,
        model_start_ordinal=1,
        now=NOW,
    )


def _catalog(**entry_changes: object) -> dict[str, object]:
    terra: dict[str, object] = {
        "id": "gpt-5.6-terra",
        "model": "gpt-5.6-terra",
        "displayName": "GPT-5.6 Terra",
        "description": "Everyday workhorse",
        "hidden": False,
        "isDefault": False,
        "defaultReasoningEffort": "medium",
        "supportedReasoningEfforts": [
            {"reasoningEffort": "low", "description": "Lower latency"},
            {"reasoningEffort": "medium", "description": "Balanced"},
            {"reasoningEffort": "high", "description": "Deeper"},
        ],
    }
    terra.update(entry_changes)
    return {
        "data": [
            terra,
            {
                "id": "gpt-5.6-sol",
                "model": "gpt-5.6-sol",
                "displayName": "GPT-5.6 Sol",
                "description": "Complex work",
                "hidden": False,
                "isDefault": True,
                "defaultReasoningEffort": "high",
                "supportedReasoningEfforts": [
                    {"reasoningEffort": "medium", "description": "Balanced"},
                    {"reasoningEffort": "high", "description": "Deeper"},
                ],
            },
        ],
        "nextCursor": None,
    }


def _proposal(repository: Path) -> dict[str, object]:
    return build_app_server_proposal(
        _plan(repository),
        _catalog(),
        codex_cli_version="0.144.5",
        protocol_schema_sha256="a" * 64,
        client_info_name="mtr_dogfood",
        origin_kind="product",
        origin_issuer="codex-desktop-host",
        origin_attestation_sha256="b" * 64,
        attestation_requested=True,
    )


def _usage(thread_id: str, turn_id: str) -> dict[str, object]:
    last = {
        "inputTokens": 120,
        "cachedInputTokens": 80,
        "outputTokens": 30,
        "reasoningOutputTokens": 10,
        "totalTokens": 150,
    }
    return {
        "method": "thread/tokenUsage/updated",
        "params": {
            "threadId": thread_id,
            "turnId": turn_id,
            "tokenUsage": {
                "last": last,
                "total": dict(last),
                "modelContextWindow": 200_000,
            },
        },
    }


def _completed(
    thread_id: str,
    turn_id: str,
    *,
    status: str = "completed",
    error: object = None,
) -> dict[str, object]:
    return {
        "method": "turn/completed",
        "params": {
            "threadId": thread_id,
            "turn": {
                "id": turn_id,
                "status": status,
                "items": [
                    {
                        "type": "commandExecution",
                        "status": "completed",
                        "aggregatedOutput": "private tool output",
                    },
                    {
                        "type": "agentMessage",
                        "text": "private model output",
                    },
                ],
                "startedAt": 100,
                "completedAt": 102,
                "durationMs": 2_000,
                "error": error,
            },
        },
    }


class AppServerExperimentTests(unittest.TestCase):
    def test_proposal_binds_catalog_protocol_origin_and_preserves_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            proposal = _proposal(Path(temporary))
        self.assertEqual(validate_proposal(proposal), proposal)
        self.assertEqual(set(proposal), PROPOSAL_FIELDS)
        self.assertEqual(
            set(proposal["app_server_binding"]), APP_SERVER_BINDING_FIELDS
        )
        self.assertEqual(
            proposal["thread_start_override"],
            {"model": "gpt-5.6-terra"},
        )
        self.assertEqual(
            proposal["turn_start_override"],
            {"model": "gpt-5.6-terra", "effort": "medium"},
        )
        self.assertEqual(proposal["status"], "host_review_required")
        self.assertFalse(proposal["authority_boundary"]["execution_authorized"])
        self.assertFalse(
            proposal["authority_boundary"]["permission_expansion_authorized"]
        )
        self.assertFalse(proposal["origin"]["opaque_token_persisted"])
        serialized = json.dumps(proposal, ensure_ascii=False)
        self.assertNotIn("Everyday workhorse", serialized)
        self.assertNotIn("opaque client attestation token", serialized)

    def test_catalog_and_proposal_fail_closed_on_unsupported_or_tampered_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            plan = _plan(repository)
            common = {
                "codex_cli_version": "0.144.5",
                "protocol_schema_sha256": "a" * 64,
                "client_info_name": "mtr_dogfood",
                "origin_kind": "product",
                "origin_issuer": "codex-desktop-host",
                "origin_attestation_sha256": "b" * 64,
                "attestation_requested": True,
            }
            cases = [
                (
                    {**_catalog(), "nextCursor": "page-2"},
                    "MODEL_CATALOG_INCOMPLETE",
                ),
                (_catalog(hidden=True), "SELECTED_MODEL_HIDDEN"),
                (
                    _catalog(
                        supportedReasoningEfforts=[
                            {"reasoningEffort": "low", "description": "Fast"}
                        ],
                        defaultReasoningEffort="low",
                    ),
                    "SELECTED_EFFORT_NOT_SUPPORTED",
                ),
            ]
            for catalog, message in cases:
                with self.subTest(message=message):
                    with self.assertRaisesRegex(AppServerExperimentError, message):
                        build_app_server_proposal(plan, catalog, **common)
            with self.assertRaisesRegex(
                AppServerExperimentError, "ORIGIN_ATTESTATION_REQUIRED"
            ):
                build_app_server_proposal(
                    plan, _catalog(), **{**common, "attestation_requested": False}
                )
            proposal = _proposal(repository)
            proposal["authority_boundary"]["sandbox_override_authorized"] = True
            proposal["proposal_sha256"] = json_digest(
                {key: value for key, value in proposal.items() if key != "proposal_sha256"}
            )
            with self.assertRaisesRegex(
                AppServerExperimentError, "PROPOSAL_AUTHORITY_DRIFT"
            ):
                validate_proposal(proposal)

    def test_outcome_records_reroute_usage_and_status_without_raw_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            proposal = _proposal(Path(temporary))
        thread_id = "thread-private-1"
        turn_id = "turn-private-1"
        notifications = [
            {
                "method": "model/rerouted",
                "params": {
                    "threadId": thread_id,
                    "turnId": turn_id,
                    "fromModel": "gpt-5.6-terra",
                    "toModel": "gpt-5.6-sol",
                    "reason": "highRiskCyberActivity",
                },
            },
            _usage(thread_id, turn_id),
            _completed(thread_id, turn_id),
        ]
        outcome = summarize_app_server_outcome(proposal, notifications)
        self.assertEqual(validate_outcome(outcome, proposal=proposal), outcome)
        self.assertEqual(set(outcome), OUTCOME_FIELDS)
        self.assertEqual(outcome["model"]["requested_model"], "gpt-5.6-terra")
        self.assertEqual(outcome["model"]["resolved_model"], "gpt-5.6-sol")
        self.assertEqual(outcome["model"]["reroute_count"], 1)
        self.assertEqual(outcome["terminal"]["outcome_class"], "success")
        self.assertEqual(outcome["usage"]["input_tokens"], 120)
        self.assertEqual(outcome["usage"]["notification_count"], 1)
        self.assertEqual(
            outcome["items"]["type_counts"],
            {"agentMessage": 1, "commandExecution": 1},
        )
        serialized = json.dumps(outcome, ensure_ascii=False)
        for raw_value in (
            thread_id,
            turn_id,
            "private tool output",
            "private model output",
        ):
            self.assertNotIn(raw_value, serialized)

    def test_failed_outcome_preserves_only_error_presence(self):
        with tempfile.TemporaryDirectory() as temporary:
            proposal = _proposal(Path(temporary))
        outcome = summarize_app_server_outcome(
            proposal,
            [
                _completed(
                    "thread-1",
                    "turn-1",
                    status="failed",
                    error={
                        "message": "credential-like private failure text",
                        "codexErrorInfo": {"kind": "private"},
                    },
                )
            ],
        )
        self.assertEqual(outcome["terminal"]["outcome_class"], "failure")
        self.assertTrue(outcome["terminal"]["error_present"])
        serialized = json.dumps(outcome, ensure_ascii=False)
        self.assertNotIn("credential-like private failure text", serialized)
        self.assertNotIn("codexErrorInfo", serialized)

    def test_total_token_usage_is_validated_even_when_not_persisted(self):
        with tempfile.TemporaryDirectory() as temporary:
            proposal = _proposal(Path(temporary))
        usage = _usage("thread-1", "turn-1")
        usage["params"]["tokenUsage"]["total"]["inputTokens"] = -1
        with self.assertRaisesRegex(
            AppServerExperimentError, "TOKEN_USAGE_INVALID"
        ):
            summarize_app_server_outcome(
                proposal,
                [usage, _completed("thread-1", "turn-1")],
            )

    def test_notification_identity_chain_and_allowlist_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            proposal = _proposal(Path(temporary))
        cases = [
            (
                [{"method": "item/completed", "params": {}}],
                "APP_SERVER_NOTIFICATION_NOT_ALLOWED",
            ),
            (
                [
                    {
                        "method": "model/rerouted",
                        "params": {
                            "threadId": "thread-1",
                            "turnId": "turn-1",
                            "fromModel": "gpt-5.6-sol",
                            "toModel": "gpt-5.6-terra",
                            "reason": "highRiskCyberActivity",
                        },
                    },
                    _completed("thread-1", "turn-1"),
                ],
                "MODEL_REROUTE_CHAIN_INVALID",
            ),
            (
                [
                    _usage("thread-1", "turn-1"),
                    _completed("thread-2", "turn-1"),
                ],
                "APP_SERVER_THREAD_ID_DRIFT",
            ),
            (
                [_completed("thread-1", "turn-1", status="failed", error=None)],
                "TURN_FAILURE_ERROR_MISSING",
            ),
        ]
        for notifications, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(AppServerExperimentError, message):
                    summarize_app_server_outcome(proposal, notifications)

    def test_json_schemas_match_runtime_top_level_contract(self):
        proposal_schema = json.loads(
            (
                ROOT
                / "schemas"
                / "codex-app-server-model-experiment-r1-proposal.schema.json"
            ).read_text(encoding="utf-8")
        )
        outcome_schema = json.loads(
            (
                ROOT
                / "schemas"
                / "codex-app-server-model-experiment-r1-outcome.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertFalse(proposal_schema["additionalProperties"])
        self.assertFalse(outcome_schema["additionalProperties"])
        self.assertEqual(set(proposal_schema["required"]), PROPOSAL_FIELDS)
        self.assertEqual(set(proposal_schema["properties"]), PROPOSAL_FIELDS)
        self.assertEqual(set(outcome_schema["required"]), OUTCOME_FIELDS)
        self.assertEqual(set(outcome_schema["properties"]), OUTCOME_FIELDS)


if __name__ == "__main__":
    unittest.main()
