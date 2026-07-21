from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
import os
import re
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Any


POLICY_FILENAME = "bounded-write-policy.json"
RECEIPT_DIRECTORY = "writer-receipts"
MAX_CONTENT_BYTES = 1_000_000
ALIAS_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
INVOCATION_RE = re.compile(r"^[0-9a-f]{32}$")
RESERVED_WINDOWS_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}
RECEIPT_FIELDS = {
    "schema_version", "invocation_id", "helper_sha256", "policy_sha256",
    "target_alias", "relative_path", "canonical_workspace",
    "content_encoding", "content_byte_count", "content_sha256",
    "preexisting_target", "post_write_file_sha256", "write_status",
    "timestamp", "error_classification",
}


class BoundedWriteError(ValueError):
    """Raised when a requested write is outside the frozen local policy."""


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BoundedWriteError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise BoundedWriteError(f"non-finite JSON number: {value}")


def _load_json_strict(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_pairs_no_duplicates,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BoundedWriteError(f"invalid {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise BoundedWriteError(f"{label} must be an object")
    return value


def normalize_relative_target(value: str) -> str:
    if not value or "\x00" in value:
        raise BoundedWriteError("target path is empty or contains NUL")
    pure = PureWindowsPath(value.replace("/", "\\"))
    if pure.drive or pure.root or pure.is_absolute():
        raise BoundedWriteError("target path must be workspace-relative")
    parts = pure.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise BoundedWriteError("target path traversal is forbidden")
    for part in parts:
        if part.endswith((" ", ".")):
            raise BoundedWriteError("target path has a Windows-ambiguous component")
        if part.split(".", 1)[0].upper() in RESERVED_WINDOWS_NAMES:
            raise BoundedWriteError("target path uses a reserved Windows name")
    return "/".join(parts)


def _load_policy(path: Path) -> dict[str, Any]:
    value = _load_json_strict(path, "bounded-write policy")
    if any(isinstance(item, float) and not math.isfinite(item) for item in value.values()):
        raise BoundedWriteError("bounded-write policy contains a non-finite number")
    if set(value) != {
        "schema_version", "workspace", "target_aliases", "max_content_bytes",
    }:
        raise BoundedWriteError("bounded-write policy fields do not match schema")
    if value["schema_version"] != "2.0.0":
        raise BoundedWriteError("unsupported bounded-write policy version")
    if not isinstance(value["workspace"], str):
        raise BoundedWriteError("policy workspace must be a string")
    aliases = value["target_aliases"]
    if (
        not isinstance(aliases, dict)
        or not aliases
        or not all(isinstance(alias, str) and ALIAS_RE.fullmatch(alias) for alias in aliases)
        or not all(isinstance(target, str) for target in aliases.values())
    ):
        raise BoundedWriteError("policy target_aliases must be a non-empty alias object")
    normalized = [normalize_relative_target(target) for target in aliases.values()]
    if len(set(normalized)) != len(normalized):
        raise BoundedWriteError("policy aliases must resolve to unique paths")
    if any(
        target.replace("\\", "/") != canonical
        for target, canonical in zip(aliases.values(), normalized)
    ):
        raise BoundedWriteError("policy target path is not canonically spelled")
    if any(
        target.casefold().startswith((".mtr-dogfood-r4/", ".codex/", ".git/"))
        for target in normalized
    ):
        raise BoundedWriteError("policy target overlaps protected metadata")
    if (
        not isinstance(value["max_content_bytes"], int)
        or isinstance(value["max_content_bytes"], bool)
        or not 1 <= value["max_content_bytes"] <= MAX_CONTENT_BYTES
    ):
        raise BoundedWriteError("policy max_content_bytes is out of bounds")
    return value


def _require_contained(workspace: Path, candidate: Path) -> Path:
    root = workspace.resolve(strict=True)
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise BoundedWriteError("target resolves outside the workspace") from exc
    return resolved


def _atomic_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.mtr-bounded-{secrets.token_hex(8)}.tmp"
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
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _receipt_bytes(receipt: dict[str, Any]) -> bytes:
    return (
        json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def write_bounded_file(
    *, script_path: Path, slot: str, content_base64: str
) -> dict[str, Any]:
    script = script_path.resolve(strict=True)
    metadata = script.parent
    workspace = metadata.parent.resolve(strict=True)
    policy_path = metadata / POLICY_FILENAME
    policy = _load_policy(policy_path)
    policy_workspace = Path(policy["workspace"]).resolve(strict=True)
    if workspace != policy_workspace or Path.cwd().resolve(strict=True) != workspace:
        raise BoundedWriteError("policy, helper, and current workspace are not bound")
    if slot not in policy["target_aliases"]:
        raise BoundedWriteError("unknown target alias")

    normalized = normalize_relative_target(policy["target_aliases"][slot])
    try:
        encoded = content_base64.encode("ascii")
        content = base64.b64decode(encoded, validate=True)
        content.decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError, binascii.Error) as exc:
        raise BoundedWriteError("content must be canonical base64 for UTF-8 text") from exc
    if base64.b64encode(content) != encoded:
        raise BoundedWriteError("content base64 is not canonical")
    if not content:
        raise BoundedWriteError("empty text content is prohibited")
    if len(content) > policy["max_content_bytes"]:
        raise BoundedWriteError("content exceeds the bounded-write size limit")
    if b"\x00" in content:
        raise BoundedWriteError("NUL bytes are not allowed in text content")

    destination = workspace.joinpath(*PureWindowsPath(normalized).parts)
    _require_contained(workspace, destination)
    if destination.is_symlink():
        raise BoundedWriteError("symbolic-link targets are forbidden")
    preexisting = destination.exists()
    if preexisting:
        stat = destination.stat()
        if not destination.is_file() or stat.st_nlink != 1:
            raise BoundedWriteError("target must be a regular single-link file")
    destination.parent.mkdir(parents=True, exist_ok=True)
    _require_contained(workspace, destination.parent)
    if destination.is_symlink():
        raise BoundedWriteError("target became a symbolic link")
    try:
        _atomic_bytes(destination, content)
    except OSError as exc:
        raise BoundedWriteError(f"bounded file write failed: {exc}") from exc
    written = destination.read_bytes()
    if written != content:
        raise BoundedWriteError("post-write byte verification failed")

    invocation_id = secrets.token_hex(16)
    digest = hashlib.sha256(written).hexdigest()
    receipt = {
        "schema_version": "1.0.0",
        "invocation_id": invocation_id,
        "helper_sha256": hashlib.sha256(script.read_bytes()).hexdigest(),
        "policy_sha256": hashlib.sha256(policy_path.read_bytes()).hexdigest(),
        "target_alias": slot,
        "relative_path": normalized,
        "canonical_workspace": str(workspace),
        "content_encoding": "base64-utf8",
        "content_byte_count": len(written),
        "content_sha256": digest,
        "preexisting_target": preexisting,
        "post_write_file_sha256": digest,
        "write_status": "written",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "error_classification": None,
    }
    receipt_path = metadata / RECEIPT_DIRECTORY / f"{invocation_id}.json"
    try:
        _atomic_bytes(receipt_path, _receipt_bytes(receipt))
    except OSError as exc:
        raise BoundedWriteError(f"writer receipt creation failed: {exc}") from exc
    return receipt


def validate_writer_receipts(
    *, workspace: Path, helper_sha256: str, policy_sha256: str,
    target_aliases: dict[str, str],
) -> dict[str, Any]:
    """Validate receipts as corroboration; a receipt alone never grants authority."""
    root = workspace.resolve(strict=True)
    receipt_root = root / ".mtr-dogfood-r4" / RECEIPT_DIRECTORY
    paths = sorted(receipt_root.glob("*.json")) if receipt_root.is_dir() else []
    valid: list[dict[str, Any]] = []
    errors: list[str] = []
    seen_aliases: set[str] = set()
    seen_invocations: set[str] = set()
    for path in paths:
        try:
            receipt = _load_json_strict(path, "writer receipt")
            if set(receipt) != RECEIPT_FIELDS:
                raise BoundedWriteError("writer receipt fields do not match schema")
            invocation = receipt["invocation_id"]
            alias = receipt["target_alias"]
            if not isinstance(invocation, str) or not INVOCATION_RE.fullmatch(invocation):
                raise BoundedWriteError("writer receipt invocation ID is invalid")
            if path.name != f"{invocation}.json" or invocation in seen_invocations:
                raise BoundedWriteError("writer receipt invocation is duplicated or misnamed")
            if not isinstance(alias, str) or alias in seen_aliases:
                raise BoundedWriteError("writer receipt target alias is duplicated")
            if alias not in target_aliases:
                raise BoundedWriteError("writer receipt target alias is unknown")
            expected_path = normalize_relative_target(target_aliases[alias])
            if receipt["relative_path"] != expected_path:
                raise BoundedWriteError("writer receipt path does not match its alias")
            if receipt["helper_sha256"] != helper_sha256 or receipt["policy_sha256"] != policy_sha256:
                raise BoundedWriteError("writer receipt transport hash mismatch")
            if receipt["canonical_workspace"] != str(root):
                raise BoundedWriteError("writer receipt workspace mismatch")
            if receipt["schema_version"] != "1.0.0" or receipt["content_encoding"] != "base64-utf8":
                raise BoundedWriteError("writer receipt contract version or encoding is invalid")
            if receipt["write_status"] != "written" or receipt["error_classification"] is not None:
                raise BoundedWriteError("writer receipt does not record a successful write")
            if not isinstance(receipt["content_byte_count"], int) or isinstance(receipt["content_byte_count"], bool):
                raise BoundedWriteError("writer receipt byte count is invalid")
            if not isinstance(receipt["preexisting_target"], bool) or not isinstance(receipt["timestamp"], str):
                raise BoundedWriteError("writer receipt metadata types are invalid")
            target = root.joinpath(*PureWindowsPath(expected_path).parts)
            _require_contained(root, target)
            data = target.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            if (
                len(data) != receipt["content_byte_count"]
                or digest != receipt["content_sha256"]
                or digest != receipt["post_write_file_sha256"]
            ):
                raise BoundedWriteError("writer receipt does not match the actual file")
            seen_invocations.add(invocation)
            seen_aliases.add(alias)
            valid.append(receipt)
        except (BoundedWriteError, OSError, UnicodeError) as exc:
            errors.append(f"{path.name}: {exc}")
    return {
        "valid": not errors,
        "receipt_count": len(paths),
        "receipts": valid,
        "errors": errors,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--slot", required=True)
    parser.add_argument("--content-base64", required=True)
    arguments = parser.parse_args(argv)
    try:
        receipt = write_bounded_file(
            script_path=Path(__file__), slot=arguments.slot,
            content_base64=arguments.content_base64,
        )
    except BoundedWriteError as exc:
        sys.stderr.write(json.dumps({
            "schema_version": "1.0.0",
            "status": "rejected",
            "error_classification": "BOUNDED_WRITE_REJECTED",
            "error": str(exc),
        }, sort_keys=True) + "\n")
        return 2
    sys.stdout.buffer.write(_receipt_bytes(receipt))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
