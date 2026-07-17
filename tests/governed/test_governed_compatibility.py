from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from model_tier_router import GovernedRouter, assess_mapping, route_mapping
from model_tier_router.compat.legacy import TASK_SCHEMA_VERSION
from model_tier_router.governed import (
    ApprovalResult,
    DispatchBindingResult,
    ReceiptResult,
    RouterPorts,
    ValidationResult,
)
from model_tier_router.schema_validation import (
    SchemaValidationError,
    validate_advisory_decision,
    validate_router_assessment,
    validate_router_decision,
)


def sample(name: str) -> dict[str, str]:
    return {
        "schema_version": TASK_SCHEMA_VERSION,
        "task_id": "compat-" + name,
        "sample": name,
    }


class Approval:
    def __init__(self, result: ApprovalResult | None = None) -> None:
        self.result = result or ApprovalResult(True, "")

    def verify(self, **_: object) -> ApprovalResult:
        return self.result


class Validation:
    def __init__(self, downgrade: bool = False) -> None:
        self.downgrade = downgrade

    def verify(
        self, *, obligation: str, supervised_full_suite_required: bool, **_: object
    ) -> ValidationResult:
        if self.downgrade:
            return ValidationResult(True, "not_required", False, "")
        return ValidationResult(True, obligation, supervised_full_suite_required, "")


class Dispatch:
    def __init__(self, canonical: bool = True) -> None:
        self.canonical = canonical

    def verify(self, **_: object) -> DispatchBindingResult:
        return DispatchBindingResult(
            self.canonical,
            "" if self.canonical else "CANONICAL_PATH_NOT_VERIFIED",
        )


class Receipt:
    def __init__(self, valid: bool = True, state: str = "valid_unconsumed") -> None:
        self.valid = valid
        self.state = state

    def verify(self, **_: object) -> ReceiptResult:
        code = ""
        if not self.valid:
            code = (
                "AUTHORITY_RECEIPT_ALREADY_CONSUMED"
                if self.state == "consumed"
                else "AUTHORITY_RECEIPT_REJECTED"
            )
        return ReceiptResult(self.valid, self.state, code)


def ports(**replacements: object) -> RouterPorts:
    values = {
        "approval": Approval(),
        "validation": Validation(),
        "canonical_dispatch": Dispatch(),
        "authority_receipt": Receipt(),
    }
    values.update(replacements)
    return RouterPorts(**values)


class CompatibilityTests(unittest.TestCase):
    EXPECTED = {
        "read_only_packet_summary": ("packet_summary", "fast", "cheap", "minimal", "small"),
        "simple_docs_manifest": ("simple_docs_manifest", "fast", "cheap", "minimal", "small"),
        "bounded_source_test_change": (
            "bounded_source_test_change", "controlled", "medium", "medium", "normal"
        ),
        "ambiguous_command_status_unknown": (
            "command_status_unknown", "controlled", "expensive", "xhigh", "locked"
        ),
        "validation_supervisor_task": (
            "validation_supervisor", "controlled", "expensive", "high", "elevated"
        ),
        "live_deploy_capability_binding": (
            "capability_binding", "locked", "expensive", "xhigh", "locked"
        ),
    }

    def test_six_historical_assessment_samples(self):
        for name, expected in self.EXPECTED.items():
            with self.subTest(name=name):
                result = assess_mapping(sample(name))
                validate_router_assessment(result)
                observed = (
                    result["task_class"], result["risk_class"], result["model_tier"],
                    result["reasoning_budget"], result["budget_class"],
                )
                self.assertEqual(observed, expected)
                self.assertIs(result["execution_authorized"], False)
                self.assertEqual(result["authorized_write_scope"], [])

    def test_bounded_scope_remains_proposed_not_authorized(self):
        result = assess_mapping(sample("bounded_source_test_change"))
        self.assertTrue(result["proposed_mutation_scope"])
        self.assertEqual(result["authorized_write_scope"], [])
        self.assertIs(result["write_allowed"], False)

    def test_all_ports_produce_schema_valid_clear_decisions(self):
        for name in self.EXPECTED:
            with self.subTest(name=name):
                result = route_mapping(sample(name), ports())
                validate_router_decision(result)
                self.assertEqual(result["fail_closed"], {"status": "clear", "code": "OK"})
                self.assertEqual(result["provider_or_model_call_count"], 0)
                self.assertEqual(result["network_request_count"], 0)

    def test_missing_ports_fail_closed(self):
        result = route_mapping(sample("read_only_packet_summary"))
        validate_router_decision(result)
        self.assertEqual(result["fail_closed"]["status"], "hard_stop")
        self.assertEqual(result["fail_closed"]["code"], "CANONICAL_ROUTE_PORT_FAILURE")

    def test_missing_approval_fails_closed(self):
        result = route_mapping(
            sample("ambiguous_command_status_unknown"),
            ports(approval=None),
        )
        self.assertEqual(result["fail_closed"]["code"], "APPROVAL_PORT_FAILURE")

    def test_approval_rejection_fails_closed(self):
        result = route_mapping(
            sample("ambiguous_command_status_unknown"),
            ports(approval=Approval(ApprovalResult(False, "APPROVAL_NOT_VERIFIED"))),
        )
        self.assertEqual(result["fail_closed"]["code"], "APPROVAL_NOT_VERIFIED")

    def test_validation_downgrade_fails_closed(self):
        result = route_mapping(
            sample("bounded_source_test_change"),
            ports(validation=Validation(downgrade=True)),
        )
        self.assertEqual(result["fail_closed"]["code"], "VALIDATION_OBLIGATION_DOWNGRADE")

    def test_noncanonical_binding_fails_closed(self):
        result = route_mapping(
            sample("read_only_packet_summary"),
            ports(canonical_dispatch=Dispatch(False)),
        )
        self.assertEqual(result["fail_closed"]["code"], "CANONICAL_PATH_NOT_VERIFIED")

    def test_consumed_receipt_fails_closed(self):
        result = route_mapping(
            sample("read_only_packet_summary"),
            ports(authority_receipt=Receipt(False, "consumed")),
        )
        self.assertEqual(
            result["fail_closed"]["code"], "AUTHORITY_RECEIPT_ALREADY_CONSUMED"
        )

    def test_port_exceptions_are_normalized(self):
        class Exploding:
            def verify(self, **_: object) -> object:
                raise RuntimeError("private detail")

        result = route_mapping(
            sample("read_only_packet_summary"),
            ports(canonical_dispatch=Exploding()),
        )
        self.assertEqual(result["fail_closed"]["code"], "CANONICAL_ROUTE_PORT_FAILURE")

    def test_governed_router_class_is_preserved(self):
        result = GovernedRouter(ports()).route(sample("read_only_packet_summary"))
        self.assertEqual(result["fail_closed"]["status"], "clear")

    def test_historical_import_paths_are_preserved(self):
        from model_tier_router.contracts import RouterPorts as HistoricalPorts
        from model_tier_router.router import route_mapping as historical_route

        self.assertIs(HistoricalPorts, RouterPorts)
        self.assertIs(historical_route, route_mapping)

    def test_advisory_and_governed_schemas_cross_reject(self):
        compatibility = assess_mapping(sample("read_only_packet_summary"))
        governed = route_mapping(sample("read_only_packet_summary"), ports())
        with self.assertRaises(SchemaValidationError):
            validate_router_decision(compatibility)
        with self.assertRaises(SchemaValidationError):
            validate_router_assessment(governed)
        with self.assertRaises(SchemaValidationError):
            validate_advisory_decision(compatibility)

    def test_malformed_envelopes_return_sanitized_hard_stops(self):
        for value in ({}, [], {"schema_version": TASK_SCHEMA_VERSION}):
            with self.subTest(type=type(value).__name__):
                assessment = assess_mapping(value)
                decision = route_mapping(value)
                validate_router_assessment(assessment)
                validate_router_decision(decision)
                self.assertEqual(assessment["fail_closed"]["status"], "hard_stop")
                self.assertEqual(decision["fail_closed"]["status"], "hard_stop")

    def test_migrated_legacy_file_and_internal_adapter_are_absent(self):
        self.assertFalse((SRC / "model_tier_router" / "legacy_router.py").exists())
        self.assertFalse(
            (SRC / "model_tier_router" / "adapters" / "harness_console").exists()
        )


if __name__ == "__main__":
    unittest.main()
