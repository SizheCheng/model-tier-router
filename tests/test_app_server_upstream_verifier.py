from __future__ import annotations

import ast
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from mtr_dogfood.app_server_host_conformance import (
    run_host_conformance_suite,
)
from mtr_dogfood.app_server_upstream_verifier import (
    BINDING_FIELDS,
    CODEX_FIELDS,
    RECEIPT_FIELDS,
    SCHEMA_FIELDS,
    AppServerUpstreamVerificationError,
    build_schema_binding,
    main,
    validate_schema_binding,
    validate_upstream_verification_receipt,
    verify_upstream_conformance_artifacts,
)
from mtr_dogfood.config import json_digest, load_json
from tests.test_app_server_host_conformance import (
    NOW,
    SyntheticHostDriver,
    _subject,
)


ROOT = Path(__file__).resolve().parents[1]
VERSION = "codex-cli 0.144.5"
BUILD_SHA256 = "d" * 64
SCHEMA_NAME = "codex_app_server_protocol.v2.schemas.json"


def _definition(*properties: str) -> dict[str, object]:
    return {
        "type": "object",
        "properties": {
            name: {"type": ["string", "null"]} for name in properties
        },
    }


def _schema() -> dict[str, object]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "CodexAppServerProtocolV2",
        "type": "object",
        "definitions": {
            "InitializeParams": _definition("clientInfo"),
            "ModelListParams": _definition("cursor", "includeHidden"),
            "ModelListResponse": _definition("data", "nextCursor"),
            "TurnStartParams": _definition(
                "threadId",
                "input",
                "model",
                "effort",
            ),
            "TurnStartResponse": _definition("turn"),
            "TurnStartedNotification": _definition("threadId", "turn"),
        },
    }


def _experimental_schema() -> dict[str, object]:
    value = _schema()
    definitions = value["definitions"]
    definitions["MockExperimentalMethodParams"] = {
        "type": "object",
        "title": "MockExperimentalMethodParams",
        "properties": {"value": {"type": ["string", "null"]}},
    }
    definitions["MockExperimentalMethodResponse"] = {
        "type": "object",
        "title": "MockExperimentalMethodResponse",
        "properties": {"echoed": {"type": ["string", "null"]}},
    }
    definitions["ThreadStartParams"] = {
        "type": "object",
        "properties": {
            "mockExperimentalField": {"type": ["string", "null"]}
        },
    }
    definitions["ClientRequest"] = {
        "oneOf": [
            {
                "type": "object",
                "properties": {
                    "method": {"enum": ["mock/experimentalMethod"]}
                },
            }
        ]
    }
    return value


def _write_schema(
    root: Path,
    value: dict[str, object],
    *,
    sort_keys: bool,
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / SCHEMA_NAME
    path.write_text(
        json.dumps(value, indent=2, sort_keys=sort_keys) + "\n",
        encoding="utf-8",
    )
    return path


class AppServerUpstreamVerifierTests(unittest.TestCase):
    def test_semantic_schema_binding_ignores_generator_key_order(self):
        with tempfile.TemporaryDirectory() as raw_temp:
            temp = Path(raw_temp)
            first_path = _write_schema(
                temp / "first",
                _schema(),
                sort_keys=False,
            )
            second_path = _write_schema(
                temp / "second",
                _schema(),
                sort_keys=True,
            )
            self.assertNotEqual(
                hashlib.sha256(first_path.read_bytes()).hexdigest(),
                hashlib.sha256(second_path.read_bytes()).hexdigest(),
            )

            first = build_schema_binding(
                first_path,
                codex_version=VERSION,
                codex_build_sha256=BUILD_SHA256,
                experimental_api_included=False,
            )
            second = build_schema_binding(
                second_path,
                codex_version=VERSION,
                codex_build_sha256=BUILD_SHA256,
                experimental_api_included=False,
            )
            self.assertEqual(first, second)
            self.assertEqual(
                first["schema"]["protocol_schema_sha256"],
                json_digest(_schema()),
            )
            self.assertEqual(
                validate_schema_binding(
                    first,
                    schema_path=second_path,
                    expected_codex_version=VERSION,
                    expected_codex_build_sha256=BUILD_SHA256,
                    expected_experimental_api_included=False,
                ),
                first,
            )

            changed = _schema()
            changed["definitions"]["TurnStartParams"]["properties"][
                "summary"
            ] = {"type": "string"}
            changed_path = _write_schema(
                temp / "changed",
                changed,
                sort_keys=True,
            )
            changed_binding = build_schema_binding(
                changed_path,
                codex_version=VERSION,
                codex_build_sha256=BUILD_SHA256,
                experimental_api_included=False,
            )
            self.assertNotEqual(
                first["schema"]["protocol_schema_sha256"],
                changed_binding["schema"]["protocol_schema_sha256"],
            )

    def test_experimental_mode_is_bound_to_stable_generator_markers(self):
        with tempfile.TemporaryDirectory() as raw_temp:
            temp = Path(raw_temp)
            default_path = _write_schema(
                temp / "default",
                _schema(),
                sort_keys=False,
            )
            experimental_path = _write_schema(
                temp / "experimental",
                _experimental_schema(),
                sort_keys=False,
            )

            default_binding = build_schema_binding(
                default_path,
                codex_version=VERSION,
                codex_build_sha256=BUILD_SHA256,
                experimental_api_included=False,
            )
            self.assertFalse(
                default_binding["codex"]["experimental_api_included"]
            )
            with self.assertRaisesRegex(
                AppServerUpstreamVerificationError,
                "APP_SERVER_SCHEMA_EXPERIMENTAL_MODE_MISMATCH",
            ):
                build_schema_binding(
                    default_path,
                    codex_version=VERSION,
                    codex_build_sha256=BUILD_SHA256,
                    experimental_api_included=True,
                )

            experimental_binding = build_schema_binding(
                experimental_path,
                codex_version=VERSION,
                codex_build_sha256=BUILD_SHA256,
                experimental_api_included=True,
            )
            self.assertTrue(
                experimental_binding["codex"]["experimental_api_included"]
            )
            with self.assertRaisesRegex(
                AppServerUpstreamVerificationError,
                "APP_SERVER_SCHEMA_EXPERIMENTAL_MODE_MISMATCH",
            ):
                build_schema_binding(
                    experimental_path,
                    codex_version=VERSION,
                    codex_build_sha256=BUILD_SHA256,
                    experimental_api_included=False,
                )

            partial = _experimental_schema()
            del partial["definitions"]["MockExperimentalMethodResponse"]
            partial_path = _write_schema(
                temp / "partial",
                partial,
                sort_keys=True,
            )
            with self.assertRaisesRegex(
                AppServerUpstreamVerificationError,
                "APP_SERVER_SCHEMA_EXPERIMENTAL_SURFACE_INVALID",
            ):
                build_schema_binding(
                    partial_path,
                    codex_version=VERSION,
                    codex_build_sha256=BUILD_SHA256,
                    experimental_api_included=True,
                )

    def test_schema_parser_fails_closed_on_ambiguity_and_surface_drift(self):
        with tempfile.TemporaryDirectory() as raw_temp:
            temp = Path(raw_temp)
            duplicate = temp / "duplicate" / SCHEMA_NAME
            duplicate.parent.mkdir()
            duplicate.write_text(
                (
                    '{"title":"CodexAppServerProtocolV2",'
                    '"title":"CodexAppServerProtocolV2",'
                    '"type":"object","definitions":{}}\n'
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                AppServerUpstreamVerificationError,
                "APP_SERVER_SCHEMA_JSON_INVALID",
            ):
                build_schema_binding(
                    duplicate,
                    codex_version=VERSION,
                    codex_build_sha256=BUILD_SHA256,
                    experimental_api_included=False,
                )

            missing_model = _schema()
            del missing_model["definitions"]["TurnStartParams"]["properties"][
                "model"
            ]
            missing_path = _write_schema(
                temp / "missing",
                missing_model,
                sort_keys=True,
            )
            with self.assertRaisesRegex(
                AppServerUpstreamVerificationError,
                "APP_SERVER_SCHEMA_REQUIRED_SURFACE_INVALID",
            ):
                build_schema_binding(
                    missing_path,
                    codex_version=VERSION,
                    codex_build_sha256=BUILD_SHA256,
                    experimental_api_included=False,
                )

    def test_upstream_receipt_binds_report_to_independent_build_and_schema(self):
        with tempfile.TemporaryDirectory() as raw_temp:
            schema_path = _write_schema(
                Path(raw_temp),
                _schema(),
                sort_keys=False,
            )
            binding = build_schema_binding(
                schema_path,
                codex_version=VERSION,
                codex_build_sha256=BUILD_SHA256,
                experimental_api_included=False,
            )
            subject = _subject()
            subject["protocol_schema_sha256"] = binding["schema"][
                "protocol_schema_sha256"
            ]
            report = run_host_conformance_suite(
                subject,
                SyntheticHostDriver(
                    protocol_schema_sha256=subject[
                        "protocol_schema_sha256"
                    ]
                ),
                now=NOW,
            )
            receipt = verify_upstream_conformance_artifacts(
                schema_path=schema_path,
                schema_binding=binding,
                expected_subject=subject,
                report=report,
                expected_codex_version=VERSION,
                expected_codex_build_sha256=BUILD_SHA256,
                expected_experimental_api_included=False,
            )
            self.assertEqual(receipt["status"], "verified_conformant")
            self.assertTrue(receipt["verified"])
            self.assertEqual(receipt["report_sha256"], report["report_sha256"])
            self.assertEqual(
                validate_upstream_verification_receipt(
                    receipt,
                    schema_binding=binding,
                    expected_subject=subject,
                    report=report,
                ),
                receipt,
            )

            raw_bound_subject = copy.deepcopy(subject)
            raw_bound_subject["protocol_schema_sha256"] = hashlib.sha256(
                schema_path.read_bytes()
            ).hexdigest()
            raw_bound_report = run_host_conformance_suite(
                raw_bound_subject,
                SyntheticHostDriver(
                    protocol_schema_sha256=raw_bound_subject[
                        "protocol_schema_sha256"
                    ]
                ),
                now=NOW,
            )
            with self.assertRaisesRegex(
                AppServerUpstreamVerificationError,
                "UPSTREAM_PROTOCOL_BINDING_MISMATCH",
            ):
                verify_upstream_conformance_artifacts(
                    schema_path=schema_path,
                    schema_binding=binding,
                    expected_subject=raw_bound_subject,
                    report=raw_bound_report,
                    expected_codex_version=VERSION,
                    expected_codex_build_sha256=BUILD_SHA256,
                    expected_experimental_api_included=False,
                )

            with self.assertRaisesRegex(
                AppServerUpstreamVerificationError,
                "SCHEMA_BINDING_EXPECTED_VALUES_MISMATCH",
            ):
                validate_schema_binding(
                    binding,
                    schema_path=schema_path,
                    expected_codex_version=VERSION,
                    expected_codex_build_sha256="e" * 64,
                    expected_experimental_api_included=False,
                )

    def test_cli_creates_binding_once_without_starting_a_host(self):
        with tempfile.TemporaryDirectory() as raw_temp:
            temp = Path(raw_temp)
            schema_path = _write_schema(
                temp / "schema",
                _schema(),
                sort_keys=False,
            )
            output = temp / "binding.json"
            exit_code = main(
                [
                    "bind-schema",
                    "--schema",
                    str(schema_path),
                    "--codex-version",
                    VERSION,
                    "--codex-build-sha256",
                    BUILD_SHA256,
                    "--output",
                    str(output),
                ]
            )
            self.assertEqual(exit_code, 0)
            self.assertEqual(
                load_json(output),
                build_schema_binding(
                    schema_path,
                    codex_version=VERSION,
                    codex_build_sha256=BUILD_SHA256,
                    experimental_api_included=False,
                ),
            )

    def test_schemas_entrypoint_and_source_preserve_offline_boundary(self):
        binding_schema = load_json(
            ROOT
            / "schemas"
            / "codex-app-server-schema-binding-r1.schema.json"
        )
        receipt_schema = load_json(
            ROOT
            / "schemas"
            / "codex-app-server-upstream-verification-r1-receipt.schema.json"
        )
        self.assertFalse(binding_schema["additionalProperties"])
        self.assertEqual(set(binding_schema["required"]), BINDING_FIELDS)
        self.assertEqual(set(binding_schema["properties"]), BINDING_FIELDS)
        self.assertEqual(
            set(binding_schema["$defs"]["codex"]["required"]),
            CODEX_FIELDS,
        )
        self.assertEqual(
            set(binding_schema["$defs"]["schema"]["required"]),
            SCHEMA_FIELDS,
        )
        self.assertFalse(receipt_schema["additionalProperties"])
        self.assertEqual(set(receipt_schema["required"]), RECEIPT_FIELDS)
        self.assertEqual(set(receipt_schema["properties"]), RECEIPT_FIELDS)

        canonical_digest = (
            "66ab7534f29e1ee7c065eb15c799d5f6"
            "e93fdd1d0ba86c262c3842a6a8f3d0c8"
        )
        for relative in (
            "README.md",
            "docs/openai-predispatch-model-selection-rfc-r3-app-server.md",
            "docs/openai-app-server-host-adapter-r4.md",
            "docs/openai-app-server-atomic-host-launch-r5.md",
            "docs/openai-app-server-host-conformance-r6.md",
            "docs/openai-app-server-upstream-verifier-r7.md",
            "docs/openai-app-server-experimental-schema-binding-r8.md",
        ):
            with self.subTest(canonical_binding_document=relative):
                self.assertIn(
                    canonical_digest,
                    (ROOT / relative).read_text(encoding="utf-8"),
                )

        source_path = (
            ROOT
            / "src"
            / "mtr_dogfood"
            / "app_server_upstream_verifier.py"
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
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn(
            'mtr-dogfood-verify-app-server-conformance = '
            '"mtr_dogfood.app_server_upstream_verifier:main"',
            pyproject,
        )


if __name__ == "__main__":
    unittest.main()
