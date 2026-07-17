from __future__ import annotations

import ast
import copy
import hashlib
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from model_tier_router import assess
from model_tier_router.core.decision import REQUEST_SCHEMA_VERSION
from model_tier_router.core.policy import DEFAULT_POLICY, PolicyValidationError, validate_policy
from model_tier_router.core.profiles import DEFAULT_PROFILES, ProfileValidationError, validate_profiles
from model_tier_router.schema_validation import (
    SchemaValidationError,
    validate_advisory_decision,
    validate_advisory_request,
    validate_router_assessment,
)
from model_tier_router.strict_json import (
    DuplicateKeyError,
    JSONResourceLimitError,
    MAX_JSON_BYTES,
    canonical_json_bytes,
    strict_json_loads,
)


def request(**requirements: object) -> dict[str, object]:
    return {
        "schema_version": REQUEST_SCHEMA_VERSION,
        "request_id": "core-test",
        "requirements": requirements,
        "preferences": [],
        "evidence": {},
    }


class AdvisoryCoreTests(unittest.TestCase):
    def test_default_decision_is_schema_valid_and_non_authorizing(self):
        result = assess(request())
        validate_advisory_decision(result)
        self.assertEqual(result["status"], "recommended")
        self.assertEqual(result["selected_profile"], "economy")
        self.assertIs(result["execution_authorized"], False)
        self.assertEqual(result["authorized_write_scope"], [])

    def test_hard_constraints_filter_before_preferences(self):
        payload = request(
            modalities=["text"],
            tool_support=True,
            maximum_cost_class="medium",
        )
        payload["preferences"] = ["higher_reasoning"]
        result = assess(payload)
        self.assertEqual(result["selected_profile"], "balanced")
        rejected = {item["profile_id"] for item in result["trace"]["rejected_alternatives"]}
        self.assertIn("economy", rejected)
        self.assertIn("premium", rejected)

    def test_higher_reasoning_preference_selects_premium_when_unbounded(self):
        payload = request()
        payload["preferences"] = ["higher_reasoning"]
        self.assertEqual(assess(payload)["selected_profile"], "premium")

    def test_stable_lexical_tie_break(self):
        profiles = copy.deepcopy(DEFAULT_PROFILES[:1])
        first = copy.deepcopy(profiles[0])
        second = copy.deepcopy(profiles[0])
        first["profile_id"] = "zeta"
        second["profile_id"] = "alpha"
        policy = copy.deepcopy(DEFAULT_POLICY)
        policy["escalation"]["maximum_profile"] = "zeta"
        result = assess(request(), policy=policy, profiles=[first, second])
        self.assertEqual(result["selected_profile"], "alpha")
        self.assertEqual(result["trace"]["stable_tie_break"], "preference_tuple_then_profile_id")

    def test_catalog_order_invariance(self):
        first = assess(request(), profiles=DEFAULT_PROFILES)
        second = assess(request(), profiles=list(reversed(DEFAULT_PROFILES)))
        self.assertEqual(first, second)

    def test_dictionary_order_invariance(self):
        payload = request(modalities=["text"], tool_support=True)
        reversed_payload = {
            "evidence": {},
            "preferences": [],
            "requirements": {"tool_support": True, "modalities": ["text"]},
            "request_id": "core-test",
            "schema_version": REQUEST_SCHEMA_VERSION,
        }
        self.assertEqual(assess(payload), assess(reversed_payload))

    def test_needs_input_is_distinct_from_policy_blocked(self):
        policy = copy.deepcopy(DEFAULT_POLICY)
        policy["required_evidence"] = ["privacy"]
        needs = assess(request(), policy=policy)
        blocked = assess(request(modalities=["video"]))
        self.assertEqual(needs["status"], "needs_input")
        self.assertEqual(needs["trace"]["missing_evidence"], ["privacy"])
        self.assertEqual(blocked["status"], "policy_blocked")
        self.assertEqual(blocked["trace"]["missing_evidence"], [])

    def test_bounded_escalation_never_authorizes(self):
        result = assess(request())
        self.assertEqual(result["escalation"]["maximum_profile"], "premium")
        self.assertEqual(result["escalation"]["maximum_attempts"], 2)
        self.assertIs(result["escalation"]["requires_new_assessment"], True)
        self.assertIs(result["execution_authorized"], False)

    def test_deterministic_repetition_and_input_nonmutation(self):
        payload = request(modalities=["text"], tool_support=True)
        original = copy.deepcopy(payload)
        first = assess(payload)
        second = assess(payload)
        self.assertEqual(first, second)
        self.assertEqual(payload, original)

    def test_digest_binding_is_self_consistent(self):
        result = assess(request(tool_support=True))
        view = copy.deepcopy(result)
        view["decision_id"] = None
        view["trace"]["decision_digest"] = None
        expected = hashlib.sha256(canonical_json_bytes(view)).hexdigest()
        self.assertEqual(result["trace"]["decision_digest"], expected)
        self.assertEqual(result["decision_id"], "decision_" + expected)
        self.assertEqual(result["policy"]["policy_digest"], result["trace"]["policy_digest"])

    def test_unicode_nfc_normalization_stabilizes_digest(self):
        composed = request()
        decomposed = request()
        composed["request_id"] = "caf\u00e9"
        decomposed["request_id"] = "cafe\u0301"
        self.assertEqual(
            assess(composed)["trace"]["request_digest"],
            assess(decomposed)["trace"]["request_digest"],
        )

    def test_lone_surrogate_is_normalized_to_invalid_request(self):
        payload = request()
        payload["request_id"] = "\ud800"
        result = assess(payload)
        self.assertEqual(result["status"], "invalid_request")
        validate_advisory_decision(result)

    def test_invalid_request_is_closed_and_non_authorizing(self):
        result = assess({"schema_version": REQUEST_SCHEMA_VERSION})
        self.assertEqual(result["status"], "invalid_request")
        self.assertIs(result["execution_authorized"], False)
        with self.assertRaises(SchemaValidationError):
            validate_router_assessment(result)

    def test_invalid_policy_and_catalog_are_integration_failures(self):
        bad_policy = copy.deepcopy(DEFAULT_POLICY)
        bad_policy["imports"] = ["unsafe"]
        bad_profiles = copy.deepcopy(DEFAULT_PROFILES)
        bad_profiles[0]["provider"] = "unsafe"
        self.assertEqual(assess(request(), policy=bad_policy)["status"], "integration_failure")
        self.assertEqual(assess(request(), profiles=bad_profiles)["status"], "integration_failure")

    def test_risk_constraint_monotonicity(self):
        basic = assess(request())
        constrained = assess(request(tool_support=True))
        order = {"economy": 0, "balanced": 1, "premium": 2}
        self.assertGreaterEqual(
            order[constrained["selected_profile"]],
            order[basic["selected_profile"]],
        )

    def test_public_request_schema_is_closed(self):
        payload = request()
        validate_advisory_request(payload)
        payload["unknown"] = True
        with self.assertRaises(SchemaValidationError):
            validate_advisory_request(payload)

    def test_policy_rejects_unknown_fields_and_duplicate_rule_ids(self):
        bad = copy.deepcopy(DEFAULT_POLICY)
        bad["templates"] = []
        with self.assertRaises(PolicyValidationError):
            validate_policy(bad)
        bad = copy.deepcopy(DEFAULT_POLICY)
        rule = {"rule_id": "same", "field": "tool_support", "operator": "equals", "value": True}
        bad["hard_constraints"] = [rule, rule]
        with self.assertRaises(PolicyValidationError):
            validate_policy(bad)

    def test_profile_catalog_is_closed_and_unique(self):
        bad = copy.deepcopy(DEFAULT_PROFILES)
        bad[0]["provider_name"] = "forbidden"
        with self.assertRaises(ProfileValidationError):
            validate_profiles(bad)
        with self.assertRaises(ProfileValidationError):
            validate_profiles([DEFAULT_PROFILES[0], DEFAULT_PROFILES[0]])

    def test_pure_core_has_no_external_or_mutating_imports(self):
        forbidden = {
            "http", "os", "pathlib", "requests", "shutil", "socket",
            "subprocess", "urllib",
        }
        for path in (SRC / "model_tier_router" / "core").glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            imports = {
                alias.name.split(".", 1)[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.Import)
                for alias in node.names
            } | {
                (node.module or "").lstrip(".").split(".", 1)[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom)
            }
            self.assertTrue(imports.isdisjoint(forbidden), path.name)
            calls = {
                node.func.id
                for node in ast.walk(tree)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            }
            self.assertTrue(calls.isdisjoint({"open", "exec", "eval", "compile"}), path.name)


class StrictJSONTests(unittest.TestCase):
    def test_duplicate_keys_are_rejected(self):
        with self.assertRaises(DuplicateKeyError):
            strict_json_loads('{"a":1,"a":2}')

    def test_non_finite_numbers_are_rejected(self):
        for value in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                strict_json_loads(value)

    def test_maximum_byte_limit(self):
        with self.assertRaises(JSONResourceLimitError):
            strict_json_loads(b" " * (MAX_JSON_BYTES + 1))

    def test_maximum_nesting_limit(self):
        document = "[" * 65 + "0" + "]" * 65
        with self.assertRaises(JSONResourceLimitError):
            strict_json_loads(document)

    def test_canonical_json_rejects_floats_and_surrogates(self):
        with self.assertRaises(ValueError):
            canonical_json_bytes(1.5)
        with self.assertRaises(UnicodeError):
            canonical_json_bytes("\ud800")


if __name__ == "__main__":
    unittest.main()
