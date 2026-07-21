from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Any, Callable

from .bounded_writer import (
    POLICY_FILENAME,
    RECEIPT_DIRECTORY,
    BoundedWriteError,
    normalize_relative_target,
    validate_writer_receipts,
    write_bounded_file,
)
from .r2_contract import PayloadValidationError, validate_instance


PROTOCOL_CLASSIFICATIONS = frozenset({
    "MODEL_OUTPUT_INCOMPLETE",
    "MODEL_OUTPUT_MALFORMED",
    "MODEL_OUTPUT_SCHEMA_INVALID",
    "MODEL_WORKSPACE_MUTATION_BEFORE_MATERIALIZATION",
    "MODEL_DIRECT_WRITE_ATTEMPT",
    "MODEL_FILE_CHANGE_ATTEMPT",
    "PROPOSED_FILE_ALIAS_INVALID",
    "PROPOSED_FILE_SET_INCOMPLETE",
    "PROPOSED_FILE_SET_UNEXPECTED",
    "PROPOSED_FILE_CONTENT_LIMIT_EXCEEDED",
    "PROPOSED_FILE_AGGREGATE_LIMIT_EXCEEDED",
    "PROPOSED_FILE_DIGEST_MISMATCH",
    "PROPOSED_FILE_ENCODING_INVALID",
    "HOST_MATERIALIZATION_FAILED",
    "HOST_MATERIALIZATION_ROLLED_BACK",
    "HOST_MATERIALIZATION_RECEIPT_INVALID",
    "HOST_MATERIALIZATION_DIFF_MISMATCH",
    "LANE_VALIDATION_FAILED",
})

POLICY_FIELDS = {
    "schema_version",
    "model_output_success_guaranteed",
    "safety_independent_of_model_output_capacity",
    "lanes",
}
LANE_FIELDS = {
    "lane_id",
    "maximum_file_count",
    "maximum_aggregate_content_bytes",
    "maximum_serialized_result_bytes",
    "required_validation_expectations",
    "aliases",
}
ALIAS_REQUIRED_FIELDS = {
    "target_alias",
    "relative_path",
    "media_type",
    "encoding",
    "allowed_line_endings",
    "exact_content_bytes",
    "maximum_content_bytes",
    "maximum_serialized_bytes",
    "nul_prohibited",
}
ALIAS_OPTIONAL_FIELDS = {"content_requirements"}
CONTENT_REQUIREMENT_FIELDS = {
    "minimum_utf8_bytes",
    "exact_utf8_content",
    "required_casefold_substrings",
    "forbidden_casefold_substrings",
}
TRANSACTION_FIELDS = {
    "schema_version",
    "transaction_id",
    "expected_aliases",
    "staged_aliases",
    "committed_aliases",
    "writer_receipt_ids",
    "rollback_status",
    "final_status",
    "started_at",
    "completed_at",
    "error_classification",
}


class HostMaterializationError(ValueError):
    """Fail-closed protocol rejection with a stable classification."""

    def __init__(
        self,
        classification: str,
        detail: str,
        transaction_receipt: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(f"{classification}: {detail}")
        self.classification = classification
        self.detail = detail
        self.transaction_receipt = transaction_receipt


@dataclass(frozen=True)
class ProposedFile:
    target_alias: str
    relative_path: str
    media_type: str
    encoding: str
    line_endings: str
    content: bytes
    sha256: str


@dataclass(frozen=True)
class ValidatedProposal:
    lane_id: str
    serialized_byte_count: int
    serialized_sha256: str
    files: tuple[ProposedFile, ...]
    result: dict[str, Any]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _strict_json_bytes(raw: bytes, *, malformed_class: str) -> Any:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise HostMaterializationError(
            "PROPOSED_FILE_ENCODING_INVALID", "result is not valid UTF-8"
        ) from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=_pairs_no_duplicates,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise HostMaterializationError(malformed_class, str(exc)) from exc


def load_lane_policy(path: str | Path) -> dict[str, Any]:
    policy_path = Path(path)
    try:
        value = _strict_json_bytes(
            policy_path.read_bytes(), malformed_class="MODEL_OUTPUT_SCHEMA_INVALID"
        )
    except OSError as exc:
        raise HostMaterializationError(
            "MODEL_OUTPUT_SCHEMA_INVALID", f"lane policy unavailable: {exc}"
        ) from exc
    if not isinstance(value, dict) or set(value) != POLICY_FIELDS:
        raise HostMaterializationError(
            "MODEL_OUTPUT_SCHEMA_INVALID", "lane policy fields do not match"
        )
    if (
        value["schema_version"] != "1.0.0"
        or value["model_output_success_guaranteed"] is not False
        or value["safety_independent_of_model_output_capacity"] is not True
        or not isinstance(value["lanes"], list)
        or not value["lanes"]
    ):
        raise HostMaterializationError(
            "MODEL_OUTPUT_SCHEMA_INVALID", "lane policy proof model is invalid"
        )
    seen_lanes: set[str] = set()
    for lane in value["lanes"]:
        if not isinstance(lane, dict) or set(lane) != LANE_FIELDS:
            raise HostMaterializationError(
                "MODEL_OUTPUT_SCHEMA_INVALID", "lane policy lane fields do not match"
            )
        lane_id = lane["lane_id"]
        aliases = lane["aliases"]
        numeric = (
            "maximum_file_count",
            "maximum_aggregate_content_bytes",
            "maximum_serialized_result_bytes",
            "required_validation_expectations",
        )
        if (
            not isinstance(lane_id, str)
            or not lane_id
            or lane_id in seen_lanes
            or not isinstance(aliases, list)
            or not aliases
            or any(
                not isinstance(lane[name], int)
                or isinstance(lane[name], bool)
                or lane[name] < 1
                for name in numeric
            )
            or lane["maximum_file_count"] != len(aliases)
        ):
            raise HostMaterializationError(
                "MODEL_OUTPUT_SCHEMA_INVALID", "lane policy lane limits are invalid"
            )
        seen_lanes.add(lane_id)
        seen_aliases: set[str] = set()
        seen_paths: set[str] = set()
        alias_limit_sum = 0
        serialized_limit_sum = 0
        for alias in aliases:
            if (
                not isinstance(alias, dict)
                or not ALIAS_REQUIRED_FIELDS.issubset(alias)
                or not set(alias).issubset(
                    ALIAS_REQUIRED_FIELDS | ALIAS_OPTIONAL_FIELDS
                )
            ):
                raise HostMaterializationError(
                    "MODEL_OUTPUT_SCHEMA_INVALID", "lane alias fields do not match"
                )
            name = alias["target_alias"]
            try:
                relative = normalize_relative_target(alias["relative_path"])
            except (BoundedWriteError, TypeError) as exc:
                raise HostMaterializationError(
                    "MODEL_OUTPUT_SCHEMA_INVALID", "lane alias path is invalid"
                ) from exc
            exact = alias["exact_content_bytes"]
            maximum = alias["maximum_content_bytes"]
            serialized = alias["maximum_serialized_bytes"]
            requirements = alias.get("content_requirements")
            media_type = alias["media_type"]
            if (
                not isinstance(name, str)
                or not name
                or name in seen_aliases
                or relative != alias["relative_path"]
                or relative in seen_paths
                or alias["encoding"] != "UTF-8"
                or not isinstance(media_type, str)
                or "/" not in media_type
                or media_type != media_type.casefold()
                or media_type.split("/", 1)[0] not in {"text", "application"}
                or any(
                    character not in "abcdefghijklmnopqrstuvwxyz0123456789!#$&^_.+-/"
                    for character in media_type
                )
                or not isinstance(alias["allowed_line_endings"], list)
                or not alias["allowed_line_endings"]
                or not set(alias["allowed_line_endings"]).issubset({"LF", "CRLF"})
                or len(set(alias["allowed_line_endings"]))
                != len(alias["allowed_line_endings"])
                or not isinstance(maximum, int)
                or isinstance(maximum, bool)
                or maximum < 1
                or not isinstance(serialized, int)
                or isinstance(serialized, bool)
                or serialized < maximum * 6 + 2048
                or exact is not None
                and (
                    not isinstance(exact, int)
                    or isinstance(exact, bool)
                    or exact < 1
                    or exact > maximum
                )
                or alias["nul_prohibited"] is not True
                or requirements is not None
                and (
                    not isinstance(requirements, dict)
                    or set(requirements) != CONTENT_REQUIREMENT_FIELDS
                    or not isinstance(requirements["minimum_utf8_bytes"], int)
                    or isinstance(requirements["minimum_utf8_bytes"], bool)
                    or requirements["minimum_utf8_bytes"] < 1
                    or requirements["minimum_utf8_bytes"] > maximum
                    or requirements["exact_utf8_content"] is not None
                    and not isinstance(requirements["exact_utf8_content"], str)
                    or not isinstance(
                        requirements["required_casefold_substrings"], list
                    )
                    or not isinstance(
                        requirements["forbidden_casefold_substrings"], list
                    )
                    or any(
                        not isinstance(token, str) or not token
                        for token in requirements["required_casefold_substrings"]
                        + requirements["forbidden_casefold_substrings"]
                    )
                    or len(set(requirements["required_casefold_substrings"]))
                    != len(requirements["required_casefold_substrings"])
                    or len(set(requirements["forbidden_casefold_substrings"]))
                    != len(requirements["forbidden_casefold_substrings"])
                )
            ):
                raise HostMaterializationError(
                    "MODEL_OUTPUT_SCHEMA_INVALID", "lane alias contract is invalid"
                )
            seen_aliases.add(name)
            seen_paths.add(relative)
            alias_limit_sum += maximum
            serialized_limit_sum += serialized
        required_serialized = serialized_limit_sum + (4096 if len(aliases) > 1 else 0)
        if (
            lane["maximum_aggregate_content_bytes"] != alias_limit_sum
            or lane["maximum_serialized_result_bytes"]
            < alias_limit_sum * 6 + 8192
            or lane["maximum_serialized_result_bytes"]
            < required_serialized
        ):
            raise HostMaterializationError(
                "MODEL_OUTPUT_SCHEMA_INVALID", "lane aggregate limits are inconsistent"
            )
    return value


def lane_contract(policy: dict[str, Any], lane_id: str) -> dict[str, Any]:
    matching = [lane for lane in policy["lanes"] if lane["lane_id"] == lane_id]
    if len(matching) != 1:
        raise HostMaterializationError(
            "PROPOSED_FILE_ALIAS_INVALID", f"unknown lane: {lane_id}"
        )
    return matching[0]


def alias_map(lane: dict[str, Any]) -> dict[str, str]:
    return {
        item["target_alias"]: item["relative_path"]
        for item in lane["aliases"]
    }


def _line_endings_match(content: str, declared: str) -> bool:
    if declared == "LF":
        return "\r" not in content
    if declared == "CRLF":
        without_pairs = content.replace("\r\n", "")
        return "\r" not in without_pairs and "\n" not in without_pairs
    return False


def validate_proposed_result(
    raw: bytes,
    *,
    lane: dict[str, Any],
    schema: dict[str, Any],
) -> ValidatedProposal:
    if len(raw) > lane["maximum_serialized_result_bytes"]:
        raise HostMaterializationError(
            "PROPOSED_FILE_AGGREGATE_LIMIT_EXCEEDED",
            "serialized final result exceeds the lane limit",
        )
    value = _strict_json_bytes(raw, malformed_class="MODEL_OUTPUT_MALFORMED")
    try:
        validate_instance(value, schema)
    except PayloadValidationError as exc:
        raise HostMaterializationError("MODEL_OUTPUT_SCHEMA_INVALID", str(exc)) from exc
    if value["status"] != "completed":
        raise HostMaterializationError(
            "MODEL_OUTPUT_INCOMPLETE", "model result did not report completed"
        )
    expectations = value["validation_expectations"]
    if (
        len(expectations) < lane["required_validation_expectations"]
        or any(
            not item["name"].strip()
            or not item["expectation"].strip()
            or item["required"] is not True
            for item in expectations
        )
    ):
        raise HostMaterializationError(
            "MODEL_OUTPUT_SCHEMA_INVALID", "required validation expectations are missing"
        )
    records = value["proposed_files"]
    if len(records) > lane["maximum_file_count"]:
        raise HostMaterializationError(
            "PROPOSED_FILE_SET_UNEXPECTED", "too many proposed files"
        )
    expected = {item["target_alias"]: item for item in lane["aliases"]}
    supplied_names = [item["target_alias"] for item in records]
    if len(supplied_names) != len(set(supplied_names)):
        raise HostMaterializationError(
            "PROPOSED_FILE_ALIAS_INVALID", "duplicate proposed-file alias"
        )
    unknown = set(supplied_names) - set(expected)
    if unknown:
        classification = (
            "PROPOSED_FILE_SET_UNEXPECTED"
            if any(name in {a for a in _all_policy_aliases(lane)} for name in unknown)
            else "PROPOSED_FILE_ALIAS_INVALID"
        )
        raise HostMaterializationError(classification, f"unexpected aliases: {sorted(unknown)}")
    missing = set(expected) - set(supplied_names)
    if missing:
        raise HostMaterializationError(
            "PROPOSED_FILE_SET_INCOMPLETE", f"missing aliases: {sorted(missing)}"
        )
    prepared: list[ProposedFile] = []
    aggregate = 0
    by_name = {item["target_alias"]: item for item in records}
    for alias_policy in lane["aliases"]:
        name = alias_policy["target_alias"]
        record = by_name[name]
        if record["representation"] != "utf8_text":
            raise HostMaterializationError(
                "MODEL_OUTPUT_SCHEMA_INVALID", f"unsupported representation for {name}"
            )
        if record["encoding"] != alias_policy["encoding"]:
            raise HostMaterializationError(
                "PROPOSED_FILE_ENCODING_INVALID", f"encoding mismatch for {name}"
            )
        if record["media_type"] != alias_policy["media_type"]:
            raise HostMaterializationError(
                "MODEL_OUTPUT_SCHEMA_INVALID", f"media type mismatch for {name}"
            )
        if record["line_endings"] not in alias_policy["allowed_line_endings"]:
            raise HostMaterializationError(
                "PROPOSED_FILE_ENCODING_INVALID", f"line ending is not allowed for {name}"
            )
        content_text = record["content"]
        try:
            content = content_text.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise HostMaterializationError(
                "PROPOSED_FILE_ENCODING_INVALID", f"invalid Unicode for {name}"
            ) from exc
        if alias_policy["nul_prohibited"] and b"\x00" in content:
            raise HostMaterializationError(
                "PROPOSED_FILE_ENCODING_INVALID", f"embedded NUL for {name}"
            )
        if not _line_endings_match(content_text, record["line_endings"]):
            raise HostMaterializationError(
                "PROPOSED_FILE_ENCODING_INVALID", f"line ending declaration mismatch for {name}"
            )
        exact = alias_policy["exact_content_bytes"]
        if (
            not content
            or len(content) > alias_policy["maximum_content_bytes"]
            or exact is not None
            and len(content) != exact
        ):
            raise HostMaterializationError(
                "PROPOSED_FILE_CONTENT_LIMIT_EXCEEDED", f"content limit failed for {name}"
            )
        digest = hashlib.sha256(content).hexdigest()
        record_bytes = json.dumps(
            record, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        if len(record_bytes) > alias_policy["maximum_serialized_bytes"]:
            raise HostMaterializationError(
                "PROPOSED_FILE_AGGREGATE_LIMIT_EXCEEDED",
                f"serialized proposed-file record exceeds the limit for {name}",
            )
        aggregate += len(content)
        prepared.append(ProposedFile(
            target_alias=name,
            relative_path=alias_policy["relative_path"],
            media_type=alias_policy["media_type"],
            encoding=alias_policy["encoding"],
            line_endings=record["line_endings"],
            content=content,
            sha256=digest,
        ))
    if aggregate > lane["maximum_aggregate_content_bytes"]:
        raise HostMaterializationError(
            "PROPOSED_FILE_AGGREGATE_LIMIT_EXCEEDED",
            "aggregate content exceeds the lane limit",
        )
    by_alias = {item.target_alias: item.content for item in prepared}
    substantive = True
    for alias_policy in lane["aliases"]:
        content = by_alias[alias_policy["target_alias"]]
        requirements = alias_policy.get("content_requirements")
        if requirements is None:
            alias_substantive = bool(content)
        else:
            text = content.decode("utf-8")
            folded = text.casefold()
            exact = requirements["exact_utf8_content"]
            alias_substantive = bool(
                len(content) >= requirements["minimum_utf8_bytes"]
                and (exact is None or text == exact)
                and all(
                    token.casefold() in folded
                    for token in requirements["required_casefold_substrings"]
                )
                and all(
                    token.casefold() not in folded
                    for token in requirements["forbidden_casefold_substrings"]
                )
            )
        if not alias_substantive:
            substantive = False
            break
    if not substantive:
        raise HostMaterializationError(
            "LANE_VALIDATION_FAILED", "proposed files are empty or substantively incomplete"
        )
    host_result = dict(value)
    host_result["lane_id"] = lane["lane_id"]
    host_result["proposed_files"] = [
        {
            **record,
            "utf8_byte_count": len(file.content),
            "sha256": file.sha256,
        }
        for record, file in zip(value["proposed_files"], prepared, strict=True)
    ]
    return ValidatedProposal(
        lane_id=lane["lane_id"],
        serialized_byte_count=len(raw),
        serialized_sha256=hashlib.sha256(raw).hexdigest(),
        files=tuple(prepared),
        result=host_result,
    )


def _all_policy_aliases(lane: dict[str, Any]) -> set[str]:
    # The lane-local validator intentionally has no ambient alias authority.
    return {item["target_alias"] for item in lane["aliases"]}


def validate_model_phase(
    *,
    process_result: dict[str, Any],
    output_path: Path,
    lane: dict[str, Any],
    schema: dict[str, Any],
    command_scan: dict[str, Any],
    workspace_mutated: bool,
    immutable_hashes_match: bool,
) -> ValidatedProposal:
    if not process_result.get("child_process_started"):
        raise HostMaterializationError("MODEL_OUTPUT_INCOMPLETE", "model process did not start")
    if process_result.get("exit_code") != 0:
        raise HostMaterializationError("MODEL_OUTPUT_INCOMPLETE", "model process exit code was not zero")
    if process_result.get("model_execution_completed") is not True:
        raise HostMaterializationError("MODEL_OUTPUT_INCOMPLETE", "terminal completion was not proven")
    if workspace_mutated:
        raise HostMaterializationError(
            "MODEL_WORKSPACE_MUTATION_BEFORE_MATERIALIZATION",
            "disposable workspace changed during the model phase",
        )
    if command_scan.get("model_file_change_attempt_detected"):
        raise HostMaterializationError("MODEL_FILE_CHANGE_ATTEMPT", "model attempted file_change")
    if command_scan.get("model_direct_write_attempt_detected"):
        raise HostMaterializationError("MODEL_DIRECT_WRITE_ATTEMPT", "model attempted a direct write")
    if any(command_scan.get(name) for name in (
        "forbidden_action_detected",
        "external_path_access_detected",
        "credential_access_detected",
        "remote_operation_attempted",
        "unparseable_command_detected",
        "bounded_write_violation_detected",
    )):
        raise HostMaterializationError("MODEL_DIRECT_WRITE_ATTEMPT", "model command safety scan failed")
    if not immutable_hashes_match:
        raise HostMaterializationError(
            "MODEL_WORKSPACE_MUTATION_BEFORE_MATERIALIZATION",
            "helper, policy, schema, or metadata hash changed",
        )
    try:
        raw = output_path.read_bytes()
    except OSError as exc:
        raise HostMaterializationError("MODEL_OUTPUT_INCOMPLETE", "final output file is missing") from exc
    return validate_proposed_result(raw, lane=lane, schema=schema)


def _write_atomic(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.mtr-host-{secrets.token_hex(8)}.tmp"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _transaction_bytes(receipt: dict[str, Any]) -> bytes:
    return (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _target(workspace: Path, relative_path: str) -> Path:
    target = workspace.joinpath(*PureWindowsPath(relative_path).parts)
    root = workspace.resolve(strict=True)
    resolved = target.resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise HostMaterializationError(
            "HOST_MATERIALIZATION_FAILED", "target resolves outside workspace"
        ) from exc
    if target.is_symlink():
        raise HostMaterializationError(
            "HOST_MATERIALIZATION_FAILED", "reparse or symbolic-link target rejected"
        )
    return target


def validate_transaction_receipt(receipt: dict[str, Any]) -> None:
    if not isinstance(receipt, dict) or set(receipt) != TRANSACTION_FIELDS:
        raise HostMaterializationError(
            "HOST_MATERIALIZATION_RECEIPT_INVALID", "transaction receipt fields mismatch"
        )
    expected = receipt["expected_aliases"]
    staged = receipt["staged_aliases"]
    committed = receipt["committed_aliases"]
    writer_ids = receipt["writer_receipt_ids"]
    if (
        receipt["schema_version"] != "1.0.0"
        or not isinstance(receipt["transaction_id"], str)
        or len(receipt["transaction_id"]) != 32
        or any(not isinstance(items, list) for items in (expected, staged, committed, writer_ids))
        or any(len(items) != len(set(items)) for items in (expected, staged, committed, writer_ids))
        or receipt["rollback_status"] not in {"not_required", "completed", "failed"}
        or receipt["final_status"] not in {"committed", "rolled_back", "failed"}
        or receipt["error_classification"] is not None
        and not isinstance(receipt["error_classification"], str)
        or receipt["final_status"] == "committed"
        and (staged != expected or committed != expected or len(writer_ids) != len(expected))
    ):
        raise HostMaterializationError(
            "HOST_MATERIALIZATION_RECEIPT_INVALID", "transaction receipt semantics invalid"
        )


Writer = Callable[..., dict[str, Any]]


def materialize_transaction(
    *,
    workspace: Path,
    metadata: Path,
    proposal: ValidatedProposal,
    lane: dict[str, Any],
    helper_sha256: str,
    policy_sha256: str,
    receipt_schema_path: Path,
    receipt_schema_sha256: str,
    writer: Writer = write_bounded_file,
    protected_roots: tuple[Path, ...] = (),
) -> dict[str, Any]:
    root = workspace.resolve(strict=True)
    for protected in protected_roots:
        protected_root = protected.resolve(strict=False)
        try:
            root.relative_to(protected_root)
        except ValueError:
            continue
        raise HostMaterializationError(
            "HOST_MATERIALIZATION_FAILED",
            "source-repository or protected workspace target rejected",
        )
    helper_path = metadata / "bounded-writer.py"
    policy_path = metadata / POLICY_FILENAME
    transaction_id = secrets.token_hex(16)
    expected = [item["target_alias"] for item in lane["aliases"]]
    started_at = _utc_now()
    receipt = {
        "schema_version": "1.0.0",
        "transaction_id": transaction_id,
        "expected_aliases": expected,
        "staged_aliases": [],
        "committed_aliases": [],
        "writer_receipt_ids": [],
        "rollback_status": "not_required",
        "final_status": "failed",
        "started_at": started_at,
        "completed_at": started_at,
        "error_classification": "HOST_MATERIALIZATION_FAILED",
    }
    transaction_path = metadata / "host-materialization-transaction.json"
    staging = metadata / "host-staging" / transaction_id
    snapshots: dict[str, bytes | None] = {}
    committed: list[str] = []
    write_attempted: list[str] = []
    receipt_root = metadata / RECEIPT_DIRECTORY
    try:
        if (
            hashlib.sha256(helper_path.read_bytes()).hexdigest() != helper_sha256
            or hashlib.sha256(policy_path.read_bytes()).hexdigest() != policy_sha256
            or hashlib.sha256(receipt_schema_path.read_bytes()).hexdigest()
            != receipt_schema_sha256
        ):
            raise HostMaterializationError(
                "HOST_MATERIALIZATION_RECEIPT_INVALID",
                "helper, policy, or receipt-schema hash mismatch",
            )
        policy_value = _strict_json_bytes(
            policy_path.read_bytes(), malformed_class="HOST_MATERIALIZATION_RECEIPT_INVALID"
        )
        if (
            not isinstance(policy_value, dict)
            or policy_value.get("workspace") != str(root)
            or policy_value.get("target_aliases") != alias_map(lane)
            or policy_value.get("max_content_bytes")
            != max(item["maximum_content_bytes"] for item in lane["aliases"])
        ):
            raise HostMaterializationError(
                "HOST_MATERIALIZATION_RECEIPT_INVALID", "bounded-writer policy mismatch"
            )
        if receipt_root.exists() and any(receipt_root.iterdir()):
            raise HostMaterializationError(
                "HOST_MATERIALIZATION_RECEIPT_INVALID", "receipt predates parent materialization"
            )
        by_alias = {item.target_alias: item for item in proposal.files}
        if list(by_alias) != expected:
            raise HostMaterializationError(
                "HOST_MATERIALIZATION_FAILED", "proposal alias order or set mismatch"
            )
        for name in expected:
            proposed = by_alias[name]
            target = _target(root, proposed.relative_path)
            snapshots[name] = target.read_bytes() if target.exists() else None
            stage = staging / f"{name}.utf8"
            _write_atomic(stage, proposed.content)
            if hashlib.sha256(stage.read_bytes()).hexdigest() != proposed.sha256:
                raise HostMaterializationError(
                    "HOST_MATERIALIZATION_FAILED", f"staged digest mismatch for {name}"
                )
            receipt["staged_aliases"].append(name)
        previous_cwd = Path.cwd()
        try:
            os.chdir(root)
            for name in expected:
                proposed = by_alias[name]
                write_attempted.append(name)
                writer_receipt = writer(
                    script_path=helper_path,
                    slot=name,
                    content_base64=base64.b64encode(proposed.content).decode("ascii"),
                )
                committed.append(name)
                receipt["committed_aliases"].append(name)
                receipt["writer_receipt_ids"].append(writer_receipt["invocation_id"])
        finally:
            os.chdir(previous_cwd)
        validation = validate_writer_receipts(
            workspace=root,
            helper_sha256=helper_sha256,
            policy_sha256=policy_sha256,
            target_aliases=alias_map(lane),
        )
        if (
            not validation["valid"]
            or validation["receipt_count"] != len(expected)
            or sorted(item["target_alias"] for item in validation["receipts"])
            != sorted(expected)
            or sorted(item["invocation_id"] for item in validation["receipts"])
            != sorted(receipt["writer_receipt_ids"])
        ):
            raise HostMaterializationError(
                "HOST_MATERIALIZATION_RECEIPT_INVALID", "writer receipt set is invalid"
            )
        started = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
        try:
            receipt_times = [
                datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00"))
                for item in validation["receipts"]
            ]
        except (TypeError, ValueError) as exc:
            raise HostMaterializationError(
                "HOST_MATERIALIZATION_RECEIPT_INVALID", "writer receipt timestamp is invalid"
            ) from exc
        if any(timestamp < started for timestamp in receipt_times):
            raise HostMaterializationError(
                "HOST_MATERIALIZATION_RECEIPT_INVALID", "writer receipt predates transaction"
            )
        for item in proposal.files:
            actual = _target(root, item.relative_path).read_bytes()
            if actual != item.content or hashlib.sha256(actual).hexdigest() != item.sha256:
                raise HostMaterializationError(
                    "HOST_MATERIALIZATION_FAILED", f"actual file mismatch for {item.target_alias}"
                )
        receipt.update({
            "rollback_status": "not_required",
            "final_status": "committed",
            "completed_at": _utc_now(),
            "error_classification": None,
        })
        validate_transaction_receipt(receipt)
        _write_atomic(transaction_path, _transaction_bytes(receipt))
        return receipt
    except (OSError, BoundedWriteError, HostMaterializationError, KeyError, TypeError) as exc:
        rollback_failed = False
        if write_attempted:
            for name in reversed(expected):
                if name not in snapshots:
                    continue
                target = _target(root, alias_map(lane)[name])
                try:
                    before = snapshots[name]
                    if before is None:
                        target.unlink(missing_ok=True)
                    else:
                        _write_atomic(target, before)
                except OSError:
                    rollback_failed = True
            if receipt_root.exists():
                shutil.rmtree(receipt_root, ignore_errors=True)
        classification = (
            "HOST_MATERIALIZATION_ROLLED_BACK"
            if write_attempted and not rollback_failed
            else "HOST_MATERIALIZATION_FAILED"
        )
        if isinstance(exc, HostMaterializationError) and not write_attempted:
            classification = exc.classification
        receipt.update({
            "rollback_status": (
                "failed" if rollback_failed else "completed" if write_attempted else "not_required"
            ),
            "final_status": "rolled_back" if write_attempted and not rollback_failed else "failed",
            "completed_at": _utc_now(),
            "error_classification": classification,
        })
        _write_atomic(transaction_path, _transaction_bytes(receipt))
        raise HostMaterializationError(classification, str(exc), receipt) from exc
    finally:
        shutil.rmtree(staging, ignore_errors=True)


__all__ = [
    "HostMaterializationError",
    "PROTOCOL_CLASSIFICATIONS",
    "ProposedFile",
    "ValidatedProposal",
    "alias_map",
    "lane_contract",
    "load_lane_policy",
    "materialize_transaction",
    "validate_model_phase",
    "validate_proposed_result",
    "validate_transaction_receipt",
]
