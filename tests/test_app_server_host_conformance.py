from __future__ import annotations

import ast
import copy
import hashlib
import json
import unittest
from pathlib import Path

from mtr_dogfood.app_server_host_conformance import (
    AUTHORITY_BOUNDARY,
    CASE_IDS,
    COMPONENT_ID,
    CONFORMANCE_MODE,
    LOCAL_BOUNDARY,
    PRIVACY_BOUNDARY,
    REPORT_FIELDS,
    SUBJECT_FIELDS,
    HostConformanceCase,
    HostConformanceError,
    run_host_conformance_suite,
    validate_host_conformance_report,
)
from mtr_dogfood.config import json_digest
from tests.test_app_server_atomic_host_launch import (
    NOW,
    _base_params,
    _bindings,
    _outcome,
    _proposal,
    _request_binding,
    _sha256_text,
)


ROOT = Path(__file__).resolve().parents[1]
FAILURE_MARKER = "private-r6-host-failure-detail-must-not-persist"


def _subject() -> dict[str, object]:
    return {
        "implementation_id": "synthetic-codex-host-r6",
        "implementation_version": "1.0.0-test",
        "implementation_sha256": "a" * 64,
        "client_info_name": "mtr_dogfood",
        "protocol_schema_sha256": "3" * 64,
        "conformance_mode": CONFORMANCE_MODE,
    }


class SyntheticHostLauncher:
    def __init__(
        self,
        state: dict[str, object],
        case_id: str,
        *,
        mutation_blind: bool,
        replay_blind: bool,
        product_model_start: bool,
    ):
        self.state = state
        self.case_id = case_id
        self.mutation_blind = mutation_blind
        self.replay_blind = replay_blind
        self.product_model_start = product_model_start

    def launch(self, capability_envelope, request, launch_intent):
        envelope_sha256 = hashlib.sha256(capability_envelope).hexdigest()
        seen = self.state["seen_envelopes"]
        if (
            not self.mutation_blind
            and _request_binding(request)
            != launch_intent["host_bindings"][
                "host_request_binding_sha256"
            ]
        ):
            raise RuntimeError(FAILURE_MARKER + "-request-binding")
        if envelope_sha256 in seen and not self.replay_blind:
            raise RuntimeError(FAILURE_MARKER + "-replay")

        seen.add(envelope_sha256)
        self.state["transport_send_count"] += 1
        self.state["turn_start_count"] += 1
        if self.product_model_start:
            self.state["product_model_start_count"] += 1
        turn_id = (
            f"turn-private-r6-{self.case_id}-"
            f"{self.state['turn_start_count']}"
        )
        response = {
            "turn": {
                "id": turn_id,
                "items": [],
                "status": "inProgress",
                "startedAt": 100,
            }
        }
        result = {
            "capability_version": "2.0.0",
            "status": "turn_started",
            "issuer": "openai-codex-host-conformance-test",
            "audience": launch_intent["client_info_name"],
            "issued_at_utc": "2026-07-28T01:59:00Z",
            "expires_at_utc": "2026-07-28T02:05:00Z",
            "launched_at_utc": "2026-07-28T01:59:59Z",
            "capability_id_sha256": _sha256_text(
                "capability-" + self.case_id
            ),
            "capability_envelope_sha256": envelope_sha256,
            "nonce_sha256": _sha256_text("nonce-" + self.case_id),
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
        return response, result


class SyntheticHostDriver:
    def __init__(
        self,
        *,
        mutation_blind: bool = False,
        replay_blind: bool = False,
        product_model_start: bool = False,
        boolean_counters: bool = False,
        protocol_schema_sha256: str = "3" * 64,
    ):
        self.mutation_blind = mutation_blind
        self.replay_blind = replay_blind
        self.product_model_start = product_model_start
        self.boolean_counters = boolean_counters
        self.protocol_schema_sha256 = protocol_schema_sha256
        self.states: dict[str, dict[str, object]] = {}

    def prepare(self, case_id: str) -> HostConformanceCase:
        proposal = _proposal()
        proposal["app_server_binding"]["protocol_schema_sha256"] = (
            self.protocol_schema_sha256
        )
        proposal["proposal_sha256"] = json_digest(
            {
                key: value
                for key, value in proposal.items()
                if key != "proposal_sha256"
            }
        )
        base = _base_params()
        request_id = 100 + CASE_IDS.index(case_id)
        bindings = _bindings(proposal, base, request_id)
        from mtr_dogfood.app_server_atomic_host_launch import (
            build_atomic_launch_intent,
        )

        request, intent = build_atomic_launch_intent(
            proposal,
            base,
            bindings,
            request_id=request_id,
        )
        state: dict[str, object] = {
            "transport_send_count": 0,
            "turn_start_count": 0,
            "product_model_start_count": 0,
            "seen_envelopes": set(),
        }
        self.states[case_id] = state
        launcher = SyntheticHostLauncher(
            state,
            case_id,
            mutation_blind=(
                self.mutation_blind
                and case_id == "post_capability_mutation_rejected"
            ),
            replay_blind=(
                self.replay_blind
                and case_id == "capability_replay_rejected"
            ),
            product_model_start=self.product_model_start,
        )
        envelope = ("opaque-r6-capability-" + case_id).encode("ascii")
        return HostConformanceCase(
            case_id=case_id,
            proposal=proposal,
            base_params=base,
            request=request,
            launch_intent=intent,
            capability_envelope=envelope,
            launcher=launcher,
            private_markers=(
                "private prompt excluded from every durable receipt",
                r"C:\private\r5-workspace",
                envelope,
                FAILURE_MARKER,
            ),
        )

    def snapshot(self, case_id: str):
        state = self.states[case_id]
        if self.boolean_counters:
            return {
                "transport_send_count": False,
                "turn_start_count": state["turn_start_count"],
                "product_model_start_count": state[
                    "product_model_start_count"
                ],
            }
        return {
            "transport_send_count": state["transport_send_count"],
            "turn_start_count": state["turn_start_count"],
            "product_model_start_count": state[
                "product_model_start_count"
            ],
        }

    def build_terminal_outcome(
        self,
        case_id,
        *,
        proposal,
        response,
        launch_receipt,
    ):
        del case_id, launch_receipt
        return _outcome(proposal, turn_id=response["turn"]["id"])


class AppServerHostConformanceTests(unittest.TestCase):
    def _case(self, report, case_id):
        return next(case for case in report["cases"] if case["case_id"] == case_id)

    def test_conformant_synthetic_host_passes_all_required_cases(self):
        driver = SyntheticHostDriver()
        report = run_host_conformance_suite(
            _subject(),
            driver,
            now=NOW,
        )
        self.assertEqual(
            validate_host_conformance_report(
                report,
                expected_subject=_subject(),
            ),
            report,
        )
        self.assertEqual(report["status"], "conformant")
        self.assertEqual(
            report["summary"],
            {"required": 8, "passed": 8, "failed": 0},
        )
        self.assertEqual(
            [case["case_id"] for case in report["cases"]],
            list(CASE_IDS),
        )
        self.assertEqual(set(report), REPORT_FIELDS)
        self.assertEqual(set(report["subject"]), SUBJECT_FIELDS)
        self.assertEqual(report["authority_boundary"], AUTHORITY_BOUNDARY)
        self.assertEqual(report["local_boundary"], LOCAL_BOUNDARY)
        self.assertEqual(report["privacy"], PRIVACY_BOUNDARY)
        serialized = json.dumps(report, ensure_ascii=False)
        for private_value in (
            "private prompt excluded from every durable receipt",
            r"C:\private\r5-workspace",
            "opaque-r6-capability",
            FAILURE_MARKER,
            "turn-private-r6",
        ):
            self.assertNotIn(private_value, serialized)
        self.assertTrue(
            all(
                state["product_model_start_count"] == 0
                for state in driver.states.values()
            )
        )

    def test_request_mutation_and_replay_blind_hosts_fail_closed(self):
        mutation_report = run_host_conformance_suite(
            _subject(),
            SyntheticHostDriver(mutation_blind=True),
            now=NOW,
        )
        self.assertEqual(mutation_report["status"], "non_conformant")
        self.assertEqual(
            self._case(
                mutation_report,
                "post_capability_mutation_rejected",
            )["status"],
            "failed",
        )
        self.assertEqual(mutation_report["summary"]["failed"], 1)

        replay_report = run_host_conformance_suite(
            _subject(),
            SyntheticHostDriver(replay_blind=True),
            now=NOW,
        )
        self.assertEqual(replay_report["status"], "non_conformant")
        self.assertEqual(
            self._case(
                replay_report,
                "capability_replay_rejected",
            )["status"],
            "failed",
        )
        self.assertEqual(replay_report["summary"]["failed"], 1)

    def test_boolean_counters_and_product_model_start_do_not_pass(self):
        boolean_report = run_host_conformance_suite(
            _subject(),
            SyntheticHostDriver(boolean_counters=True),
            now=NOW,
        )
        self.assertEqual(boolean_report["status"], "non_conformant")
        self.assertGreater(boolean_report["summary"]["failed"], 0)

        product_report = run_host_conformance_suite(
            _subject(),
            SyntheticHostDriver(product_model_start=True),
            now=NOW,
        )
        self.assertEqual(product_report["status"], "non_conformant")
        self.assertEqual(
            self._case(
                product_report,
                "host_only_action_boundary_enforced",
            )["status"],
            "failed",
        )

    def test_report_digest_summary_and_subject_fail_closed(self):
        report = run_host_conformance_suite(
            _subject(),
            SyntheticHostDriver(),
            now=NOW,
        )
        tampered = copy.deepcopy(report)
        tampered["summary"]["passed"] = True
        tampered["report_sha256"] = json_digest(
            {
                key: value
                for key, value in tampered.items()
                if key != "report_sha256"
            }
        )
        with self.assertRaisesRegex(
            HostConformanceError,
            "CONFORMANCE_REPORT_SUMMARY_INVALID",
        ):
            validate_host_conformance_report(
                tampered,
                expected_subject=_subject(),
            )

        for field, replacement in (
            ("implementation_sha256", "b" * 64),
            ("protocol_schema_sha256", "c" * 64),
            ("client_info_name", "different_client"),
        ):
            with self.subTest(subject_field=field):
                rebound = copy.deepcopy(report)
                rebound["subject"][field] = replacement
                rebound["report_sha256"] = json_digest(
                    {
                        key: value
                        for key, value in rebound.items()
                        if key != "report_sha256"
                    }
                )
                with self.assertRaisesRegex(
                    HostConformanceError,
                    "CONFORMANCE_REPORT_SUBJECT_BINDING_INVALID",
                ):
                    validate_host_conformance_report(
                        rebound,
                        expected_subject=_subject(),
                    )

        invalid_subject = _subject()
        invalid_subject["conformance_mode"] = "real_model"
        with self.assertRaisesRegex(
            HostConformanceError,
            "CONFORMANCE_MODE_INVALID",
        ):
            run_host_conformance_suite(
                invalid_subject,
                SyntheticHostDriver(),
                now=NOW,
            )

    def test_schema_and_source_preserve_the_local_action_boundary(self):
        schema = json.loads(
            (
                ROOT
                / "schemas"
                / "codex-app-server-host-conformance-r1-report.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(schema["required"]), REPORT_FIELDS)
        self.assertEqual(set(schema["properties"]), REPORT_FIELDS)
        self.assertEqual(schema["properties"]["cases"]["minItems"], 8)
        self.assertEqual(schema["properties"]["cases"]["maxItems"], 8)
        self.assertFalse(
            schema["$defs"]["local_boundary"]["additionalProperties"]
        )

        source_path = (
            ROOT / "src" / "mtr_dogfood" / "app_server_host_conformance.py"
        )
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        imported_roots = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported_roots.update(
            node.module.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        )
        self.assertTrue(
            imported_roots.isdisjoint(
                {"socket", "subprocess", "urllib", "http", "requests"}
            )
        )
        self.assertTrue(all(value is False for value in LOCAL_BOUNDARY.values()))


if __name__ == "__main__":
    unittest.main()
