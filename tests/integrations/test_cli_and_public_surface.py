from __future__ import annotations

import ast
import copy
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
SKILL = ROOT / "integrations" / "codex" / "model-tier-route"
sys.path.insert(0, str(SRC))

from model_tier_router import assess
from model_tier_router.core.decision import REQUEST_SCHEMA_VERSION
from model_tier_router.core.policy import DEFAULT_POLICY
from model_tier_router.core.profiles import DEFAULT_PROFILES
from model_tier_router.schema_validation import (
    load_project_schema,
    validate,
    validate_advisory_decision,
)
from model_tier_router.strict_json import canonical_json_bytes, strict_json_loads


def request() -> dict[str, object]:
    return {
        "schema_version": REQUEST_SCHEMA_VERSION,
        "request_id": "cli-test",
        "requirements": {"modalities": ["text"], "tool_support": True},
        "preferences": ["higher_reasoning"],
        "evidence": {"modalities": True, "tool_support": True},
    }


def run_cli(
    payload: bytes,
    *arguments: str,
) -> subprocess.CompletedProcess[bytes]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(SRC)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        [sys.executable, "-B", "-m", "model_tier_router.cli", "assess", *arguments],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=ROOT,
        env=environment,
        check=False,
        timeout=20,
    )


class CLITests(unittest.TestCase):
    def test_valid_stdin_is_one_canonical_document(self):
        completed = run_cli(canonical_json_bytes(request()))
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, b"")
        self.assertEqual(completed.stdout.count(b"\n"), 1)
        value = strict_json_loads(completed.stdout)
        validate_advisory_decision(value)
        self.assertEqual(completed.stdout, canonical_json_bytes(value) + b"\n")
        self.assertEqual(value, assess(request()))

    def test_repeated_cli_stdout_is_byte_identical(self):
        payload = canonical_json_bytes(request())
        self.assertEqual(run_cli(payload).stdout, run_cli(payload).stdout)

    def test_invalid_and_duplicate_json_exit_two(self):
        for payload in (b"{", b'{"a":1,"a":2}', b"[]", b"NaN"):
            with self.subTest(payload=payload):
                completed = run_cli(payload)
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(completed.stderr, b"")
                value = strict_json_loads(completed.stdout)
                self.assertEqual(value["status"], "invalid_request")

    def test_explicit_input_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "request.json"
            path.write_bytes(canonical_json_bytes(request()))
            completed = run_cli(b"", "--input", str(path))
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(strict_json_loads(completed.stdout), assess(request()))

    def test_invalid_policy_file_exits_three(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "policy.json"
            path.write_text('{"invalid":true}', encoding="utf-8")
            completed = run_cli(canonical_json_bytes(request()), "--policy", str(path))
        self.assertEqual(completed.returncode, 3)
        value = strict_json_loads(completed.stdout)
        self.assertEqual(value["status"], "integration_failure")
        self.assertEqual(value["trace"]["error_code"], "INVALID_CONFIGURATION")

    def test_cli_does_not_mutate_input_object(self):
        payload = request()
        original = copy.deepcopy(payload)
        run_cli(canonical_json_bytes(payload))
        self.assertEqual(payload, original)


class PublicSurfaceTests(unittest.TestCase):
    def test_all_project_schemas_are_strict_and_self_validating(self):
        names = (
            "advisory-request.schema.json",
            "advisory-decision.schema.json",
            "capability-profile.schema.json",
            "policy.schema.json",
            "task-envelope.schema.json",
            "router-decision.schema.json",
            "router-assessment.schema.json",
        )
        for name in names:
            with self.subTest(name=name):
                schema = load_project_schema(name)
                self.assertIs(schema["additionalProperties"], False)
        validate(DEFAULT_POLICY, load_project_schema("policy.schema.json"))
        for profile in DEFAULT_PROFILES:
            validate(profile, load_project_schema("capability-profile.schema.json"))

    def test_default_example_data_matches_code_defaults(self):
        policy = strict_json_loads((ROOT / "examples/policies/default-policy.json").read_bytes())
        profiles = strict_json_loads((ROOT / "examples/profiles/default-profiles.json").read_bytes())
        self.assertEqual(policy, DEFAULT_POLICY)
        self.assertEqual(profiles, DEFAULT_PROFILES)

    def test_codex_skill_is_explicit_only_and_uses_cli(self):
        skill = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        metadata = (SKILL / "agents/openai.yaml").read_text(encoding="utf-8")
        wrapper = (SKILL / "scripts/route_task.py").read_text(encoding="utf-8")
        self.assertIn("explicitly invokes", skill)
        self.assertIn("execution_authorized=false", skill)
        self.assertIn("allow_implicit_invocation: false", metadata)
        self.assertIn("model_tier_router.cli", wrapper)
        self.assertNotIn("route_mapping", wrapper)

    def test_codex_wrapper_matches_supported_cli(self):
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(SRC)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        completed = subprocess.run(
            [sys.executable, "-B", str(SKILL / "scripts/route_task.py")],
            input=canonical_json_bytes(request()),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=ROOT,
            env=environment,
            check=False,
            timeout=20,
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, b"")
        self.assertEqual(strict_json_loads(completed.stdout), assess(request()))

    def test_package_metadata_has_no_runtime_dependency(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        for required in (
            'build-backend = "setuptools.build_meta"',
            'version = "0.1.0"',
            'dependencies = []',
            'model-tier-router = "model_tier_router.cli:main"',
            'license = "Apache-2.0"',
        ):
            self.assertIn(required, text)
        self.assertNotIn("email =", text)

    def test_no_notice_without_attribution_requirement(self):
        self.assertFalse((ROOT / "NOTICE").exists())
        self.assertIn(
            "does not include a NOTICE file",
            (ROOT / "PROVENANCE.md").read_text(encoding="utf-8"),
        )

    def test_public_files_have_no_private_path_or_internal_lineage_marker(self):
        forbidden = (
            "C:" + chr(92) + "Users" + chr(92),
            "C:/" + "Users/",
            "Agent" + " Harness",
            "MODEL_TIER_ROUTER_" + "MIGRATION",
        )
        for path in ROOT.rglob("*"):
            if not path.is_file() or ".git" in path.parts:
                continue
            if path.suffix.lower() in {".pyc", ".pyo"}:
                self.fail(f"generated bytecode present: {path}")
            text = path.read_text(encoding="utf-8")
            for marker in forbidden:
                self.assertNotIn(marker, text, str(path.relative_to(ROOT)))

    def test_core_source_does_not_import_provider_or_network_modules(self):
        forbidden = {"requests", "socket", "urllib", "httpx", "openai", "anthropic"}
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
            self.assertTrue(imports.isdisjoint(forbidden))


if __name__ == "__main__":
    unittest.main()
