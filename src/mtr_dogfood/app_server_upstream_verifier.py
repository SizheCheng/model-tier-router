from __future__ import annotations

import argparse
import copy
import hashlib
import re
import sys
from pathlib import Path
from typing import Any, Mapping

from .app_server_host_conformance import (
    HostConformanceError,
    validate_host_conformance_report,
)
from .config import (
    ContractError,
    canonical_json_bytes,
    json_digest,
    load_json,
    strict_json_loads,
)


SCHEMA_BINDING_COMPONENT_ID = "MTR_CODEX_APP_SERVER_SCHEMA_BINDING_R1"
VERIFIER_COMPONENT_ID = "MTR_CODEX_APP_SERVER_UPSTREAM_VERIFIER_R1"
SCHEMA_VERSION = "1.0.0"
CONSOLIDATED_V2_FILENAME = "codex_app_server_protocol.v2.schemas.json"
CONSOLIDATED_V2_TITLE = "CodexAppServerProtocolV2"
CANONICALIZATION = "mtr-canonical-json-utf8-lf-v1"
MAX_SCHEMA_BYTES = 16 * 1024 * 1024
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
VERSION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._+/-]{0,127}")

REQUIRED_DEFINITIONS = (
    "InitializeParams",
    "ModelListParams",
    "ModelListResponse",
    "TurnStartParams",
    "TurnStartResponse",
    "TurnStartedNotification",
)
REQUIRED_DEFINITION_PROPERTIES = {
    "InitializeParams": ("clientInfo",),
    "ModelListParams": ("includeHidden",),
    "ModelListResponse": ("data", "nextCursor"),
    "TurnStartParams": ("effort", "input", "model", "threadId"),
    "TurnStartResponse": ("turn",),
    "TurnStartedNotification": ("threadId", "turn"),
}
EXPERIMENTAL_MARKER_DEFINITIONS = {
    "MockExperimentalMethodParams": "MockExperimentalMethodParams",
    "MockExperimentalMethodResponse": "MockExperimentalMethodResponse",
}
EXPERIMENTAL_MARKER_FIELD_OWNER = "ThreadStartParams"
EXPERIMENTAL_MARKER_FIELD = "mockExperimentalField"
EXPERIMENTAL_MARKER_METHOD_OWNER = "ClientRequest"
EXPERIMENTAL_MARKER_METHOD = "mock/experimentalMethod"

BINDING_AUTHORITY_BOUNDARY = {
    "execution_authorized": False,
    "product_model_start_authorized": False,
    "host_build_attested_by_binding": False,
    "independent_expected_values_required": True,
}
VERIFICATION_AUTHORITY_BOUNDARY = {
    "execution_authorized": False,
    "product_model_start_authorized": False,
    "host_owned_driver_required": True,
    "permission_expansion_authorized": False,
    "network_expansion_authorized": False,
}
VERIFICATION_PRIVACY_BOUNDARY = {
    "raw_schema_persisted": False,
    "raw_report_persisted": False,
    "raw_subject_persisted": False,
    "only_digest_evidence_persisted": True,
}

BINDING_FIELDS = {
    "schema_version",
    "component_id",
    "status",
    "codex",
    "schema",
    "required_surface",
    "authority_boundary",
    "binding_sha256",
}
CODEX_FIELDS = {
    "version",
    "build_sha256",
    "experimental_api_included",
}
SCHEMA_FIELDS = {
    "file",
    "title",
    "canonicalization",
    "canonical_bytes",
    "protocol_schema_sha256",
}
RECEIPT_FIELDS = {
    "schema_version",
    "component_id",
    "status",
    "codex",
    "schema_binding_sha256",
    "protocol_schema_sha256",
    "subject_sha256",
    "report_sha256",
    "conformance_status",
    "verified",
    "authority_boundary",
    "privacy",
    "verification_sha256",
}


class AppServerUpstreamVerificationError(RuntimeError):
    pass


def _fail(code: str) -> None:
    raise AppServerUpstreamVerificationError(code)


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        _fail(f"{field}_INVALID")
    return value


def _version(value: Any) -> str:
    if not isinstance(value, str) or VERSION_PATTERN.fullmatch(value) is None:
        _fail("CODEX_VERSION_INVALID")
    return value


def _exact_bool(value: Any, field: str) -> bool:
    if type(value) is not bool:
        _fail(f"{field}_INVALID")
    return value


def _mapping(value: Any, fields: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        _fail(code)
    return copy.deepcopy(dict(value))


def _contains_exact_string(value: Any, expected: str) -> bool:
    if isinstance(value, Mapping):
        return any(
            _contains_exact_string(item, expected) for item in value.values()
        )
    if isinstance(value, list):
        return any(_contains_exact_string(item, expected) for item in value)
    return value == expected


def _experimental_surface_included(schema: Mapping[str, Any]) -> bool:
    definitions = schema["definitions"]
    markers = [
        isinstance(definitions.get(name), Mapping)
        and definitions[name].get("title") == expected_title
        for name, expected_title in EXPERIMENTAL_MARKER_DEFINITIONS.items()
    ]
    field_owner = definitions.get(EXPERIMENTAL_MARKER_FIELD_OWNER)
    markers.append(
        isinstance(field_owner, Mapping)
        and isinstance(field_owner.get("properties"), Mapping)
        and EXPERIMENTAL_MARKER_FIELD in field_owner["properties"]
    )
    markers.append(
        _contains_exact_string(
            definitions.get(EXPERIMENTAL_MARKER_METHOD_OWNER),
            EXPERIMENTAL_MARKER_METHOD,
        )
    )
    if any(markers) and not all(markers):
        _fail("APP_SERVER_SCHEMA_EXPERIMENTAL_SURFACE_INVALID")
    return all(markers)


def _schema_value(path: str | Path) -> tuple[bytes, dict[str, Any]]:
    schema_path = Path(path)
    if schema_path.name != CONSOLIDATED_V2_FILENAME:
        _fail("CONSOLIDATED_V2_SCHEMA_REQUIRED")
    try:
        raw = schema_path.read_bytes()
    except OSError:
        _fail("APP_SERVER_SCHEMA_READ_FAILED")
    if not 1 <= len(raw) <= MAX_SCHEMA_BYTES:
        _fail("APP_SERVER_SCHEMA_SIZE_INVALID")
    try:
        text = raw.decode("utf-8")
        value = strict_json_loads(text)
    except (UnicodeError, ContractError):
        _fail("APP_SERVER_SCHEMA_JSON_INVALID")
    if (
        not isinstance(value, dict)
        or value.get("title") != CONSOLIDATED_V2_TITLE
        or value.get("type") != "object"
        or not isinstance(value.get("definitions"), dict)
    ):
        _fail("APP_SERVER_SCHEMA_ROOT_INVALID")
    definitions = value["definitions"]
    for name in REQUIRED_DEFINITIONS:
        definition = definitions.get(name)
        if (
            not isinstance(definition, dict)
            or definition.get("type") != "object"
            or not isinstance(definition.get("properties"), dict)
        ):
            _fail("APP_SERVER_SCHEMA_REQUIRED_SURFACE_INVALID")
        properties = definition["properties"]
        if any(
            property_name not in properties
            for property_name in REQUIRED_DEFINITION_PROPERTIES[name]
        ):
            _fail("APP_SERVER_SCHEMA_REQUIRED_SURFACE_INVALID")
    return raw, value


def build_schema_binding(
    schema_path: str | Path,
    *,
    codex_version: str,
    codex_build_sha256: str,
    experimental_api_included: bool,
) -> dict[str, Any]:
    """Build a deterministic semantic binding for generated App Server v2 JSON."""

    _, schema = _schema_value(schema_path)
    version = _version(codex_version)
    build_digest = _sha256(codex_build_sha256, "CODEX_BUILD_SHA256")
    experimental = _exact_bool(
        experimental_api_included,
        "EXPERIMENTAL_API_INCLUDED",
    )
    if _experimental_surface_included(schema) != experimental:
        _fail("APP_SERVER_SCHEMA_EXPERIMENTAL_MODE_MISMATCH")
    canonical = canonical_json_bytes(schema)
    binding: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "component_id": SCHEMA_BINDING_COMPONENT_ID,
        "status": "schema_bound",
        "codex": {
            "version": version,
            "build_sha256": build_digest,
            "experimental_api_included": experimental,
        },
        "schema": {
            "file": CONSOLIDATED_V2_FILENAME,
            "title": CONSOLIDATED_V2_TITLE,
            "canonicalization": CANONICALIZATION,
            "canonical_bytes": len(canonical),
            "protocol_schema_sha256": hashlib.sha256(canonical).hexdigest(),
        },
        "required_surface": {
            name: list(REQUIRED_DEFINITION_PROPERTIES[name])
            for name in REQUIRED_DEFINITIONS
        },
        "authority_boundary": copy.deepcopy(BINDING_AUTHORITY_BOUNDARY),
    }
    binding["binding_sha256"] = json_digest(binding)
    return binding


def validate_schema_binding(
    value: Mapping[str, Any],
    *,
    schema_path: str | Path,
    expected_codex_version: str,
    expected_codex_build_sha256: str,
    expected_experimental_api_included: bool,
) -> dict[str, Any]:
    candidate = _mapping(value, BINDING_FIELDS, "SCHEMA_BINDING_FIELDS_INVALID")
    if (
        candidate.get("schema_version") != SCHEMA_VERSION
        or candidate.get("component_id") != SCHEMA_BINDING_COMPONENT_ID
        or candidate.get("status") != "schema_bound"
    ):
        _fail("SCHEMA_BINDING_IDENTITY_INVALID")
    _mapping(candidate.get("codex"), CODEX_FIELDS, "SCHEMA_BINDING_CODEX_INVALID")
    _mapping(
        candidate.get("schema"),
        SCHEMA_FIELDS,
        "SCHEMA_BINDING_SCHEMA_INVALID",
    )
    if candidate.get("authority_boundary") != BINDING_AUTHORITY_BOUNDARY:
        _fail("SCHEMA_BINDING_AUTHORITY_INVALID")
    supplied_digest = _sha256(
        candidate.get("binding_sha256"),
        "SCHEMA_BINDING_SHA256",
    )
    unsigned = copy.deepcopy(candidate)
    unsigned.pop("binding_sha256")
    if json_digest(unsigned) != supplied_digest:
        _fail("SCHEMA_BINDING_DIGEST_INVALID")
    expected = build_schema_binding(
        schema_path,
        codex_version=expected_codex_version,
        codex_build_sha256=expected_codex_build_sha256,
        experimental_api_included=expected_experimental_api_included,
    )
    if candidate != expected:
        _fail("SCHEMA_BINDING_EXPECTED_VALUES_MISMATCH")
    return expected


def verify_upstream_conformance_artifacts(
    *,
    schema_path: str | Path,
    schema_binding: Mapping[str, Any],
    expected_subject: Mapping[str, Any],
    report: Mapping[str, Any],
    expected_codex_version: str,
    expected_codex_build_sha256: str,
    expected_experimental_api_included: bool,
) -> dict[str, Any]:
    """Verify an R6 report against independent host, build, and schema inputs."""

    binding = validate_schema_binding(
        schema_binding,
        schema_path=schema_path,
        expected_codex_version=expected_codex_version,
        expected_codex_build_sha256=expected_codex_build_sha256,
        expected_experimental_api_included=(
            expected_experimental_api_included
        ),
    )
    if not isinstance(expected_subject, Mapping):
        _fail("EXPECTED_SUBJECT_INVALID")
    subject = copy.deepcopy(dict(expected_subject))
    protocol_digest = binding["schema"]["protocol_schema_sha256"]
    if subject.get("protocol_schema_sha256") != protocol_digest:
        _fail("UPSTREAM_PROTOCOL_BINDING_MISMATCH")
    verified_report = validate_host_conformance_report(
        report,
        expected_subject=subject,
    )
    conformant = verified_report["status"] == "conformant"
    receipt: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "component_id": VERIFIER_COMPONENT_ID,
        "status": (
            "verified_conformant"
            if conformant
            else "verified_non_conformant"
        ),
        "codex": copy.deepcopy(binding["codex"]),
        "schema_binding_sha256": binding["binding_sha256"],
        "protocol_schema_sha256": protocol_digest,
        "subject_sha256": json_digest(subject),
        "report_sha256": verified_report["report_sha256"],
        "conformance_status": verified_report["status"],
        "verified": conformant,
        "authority_boundary": copy.deepcopy(
            VERIFICATION_AUTHORITY_BOUNDARY
        ),
        "privacy": copy.deepcopy(VERIFICATION_PRIVACY_BOUNDARY),
    }
    receipt["verification_sha256"] = json_digest(receipt)
    return receipt


def validate_upstream_verification_receipt(
    value: Mapping[str, Any],
    *,
    schema_binding: Mapping[str, Any],
    expected_subject: Mapping[str, Any],
    report: Mapping[str, Any],
) -> dict[str, Any]:
    receipt = _mapping(
        value,
        RECEIPT_FIELDS,
        "UPSTREAM_VERIFICATION_RECEIPT_FIELDS_INVALID",
    )
    binding = _mapping(
        schema_binding,
        BINDING_FIELDS,
        "SCHEMA_BINDING_FIELDS_INVALID",
    )
    if (
        receipt.get("schema_version") != SCHEMA_VERSION
        or receipt.get("component_id") != VERIFIER_COMPONENT_ID
        or receipt.get("status")
        not in {"verified_conformant", "verified_non_conformant"}
        or receipt.get("codex") != binding.get("codex")
        or receipt.get("schema_binding_sha256")
        != binding.get("binding_sha256")
        or receipt.get("protocol_schema_sha256")
        != binding.get("schema", {}).get("protocol_schema_sha256")
        or receipt.get("subject_sha256")
        != json_digest(dict(expected_subject))
        or receipt.get("report_sha256") != report.get("report_sha256")
        or receipt.get("conformance_status") != report.get("status")
        or receipt.get("authority_boundary")
        != VERIFICATION_AUTHORITY_BOUNDARY
        or receipt.get("privacy") != VERIFICATION_PRIVACY_BOUNDARY
        or type(receipt.get("verified")) is not bool
        or (receipt["status"] == "verified_conformant")
        != receipt["verified"]
        or (receipt["conformance_status"] == "conformant")
        != receipt["verified"]
    ):
        _fail("UPSTREAM_VERIFICATION_RECEIPT_INVALID")
    supplied_digest = _sha256(
        receipt.get("verification_sha256"),
        "UPSTREAM_VERIFICATION_SHA256",
    )
    unsigned = copy.deepcopy(receipt)
    unsigned.pop("verification_sha256")
    if json_digest(unsigned) != supplied_digest:
        _fail("UPSTREAM_VERIFICATION_DIGEST_INVALID")
    return receipt


def _load_artifact(path: str | Path, code: str) -> Any:
    try:
        return load_json(path)
    except (OSError, ContractError):
        _fail(code)


def _emit(value: Mapping[str, Any], output: str | None) -> None:
    content = canonical_json_bytes(dict(value))
    if output is None:
        sys.stdout.buffer.write(content)
        return
    try:
        with Path(output).open("xb") as stream:
            stream.write(content)
    except OSError:
        _fail("OUTPUT_CREATE_FAILED")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mtr-dogfood-verify-app-server-conformance"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    bind = subparsers.add_parser("bind-schema")
    bind.add_argument("--schema", required=True)
    bind.add_argument("--codex-version", required=True)
    bind.add_argument("--codex-build-sha256", required=True)
    bind.add_argument("--experimental-api-included", action="store_true")
    bind.add_argument("--output")

    verify = subparsers.add_parser("verify-report")
    verify.add_argument("--schema", required=True)
    verify.add_argument("--binding", required=True)
    verify.add_argument("--expected-subject", required=True)
    verify.add_argument("--report", required=True)
    verify.add_argument("--codex-version", required=True)
    verify.add_argument("--codex-build-sha256", required=True)
    verify.add_argument("--experimental-api-included", action="store_true")
    verify.add_argument("--output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "bind-schema":
            binding = build_schema_binding(
                args.schema,
                codex_version=args.codex_version,
                codex_build_sha256=args.codex_build_sha256,
                experimental_api_included=args.experimental_api_included,
            )
            _emit(binding, args.output)
            return 0
        binding = _load_artifact(args.binding, "SCHEMA_BINDING_READ_FAILED")
        subject = _load_artifact(
            args.expected_subject,
            "EXPECTED_SUBJECT_READ_FAILED",
        )
        report = _load_artifact(args.report, "CONFORMANCE_REPORT_READ_FAILED")
        receipt = verify_upstream_conformance_artifacts(
            schema_path=args.schema,
            schema_binding=binding,
            expected_subject=subject,
            report=report,
            expected_codex_version=args.codex_version,
            expected_codex_build_sha256=args.codex_build_sha256,
            expected_experimental_api_included=(
                args.experimental_api_included
            ),
        )
        _emit(receipt, args.output)
        return 0 if receipt["verified"] else 1
    except (AppServerUpstreamVerificationError, HostConformanceError) as exc:
        sys.stdout.buffer.write(
            canonical_json_bytes(
                {
                    "status": "error",
                    "error_type": type(exc).__name__,
                    "message": str(exc),
                }
            )
        )
        return 2
    except Exception:
        sys.stdout.buffer.write(
            canonical_json_bytes(
                {
                    "status": "error",
                    "error_type": "UnexpectedVerifierFailure",
                    "message": "UPSTREAM_VERIFIER_UNEXPECTED_FAILURE",
                }
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
