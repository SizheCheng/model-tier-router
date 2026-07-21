from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
import os
import secrets
import sys
from pathlib import Path, PureWindowsPath
from typing import Any


POLICY_FILENAME = "bounded-write-policy.json"
MAX_CONTENT_BYTES = 1_000_000
RESERVED_WINDOWS_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}


class BoundedWriteError(ValueError):
    """Raised when a requested write is outside the frozen local policy."""


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BoundedWriteError(f"duplicate policy key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise BoundedWriteError(f"non-finite policy number: {value}")


def _load_policy(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_pairs_no_duplicates,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BoundedWriteError(f"invalid bounded-write policy: {exc}") from exc
    if not isinstance(value, dict):
        raise BoundedWriteError("bounded-write policy must be an object")
    if any(
        isinstance(item, float) and not math.isfinite(item)
        for item in value.values()
    ):
        raise BoundedWriteError("bounded-write policy contains a non-finite number")
    if set(value) != {
        "schema_version", "workspace", "allowed_paths", "max_content_bytes",
    }:
        raise BoundedWriteError("bounded-write policy fields do not match schema")
    if value["schema_version"] != "1.0.0":
        raise BoundedWriteError("unsupported bounded-write policy version")
    if not isinstance(value["workspace"], str):
        raise BoundedWriteError("policy workspace must be a string")
    if (
        not isinstance(value["allowed_paths"], list)
        or not value["allowed_paths"]
        or not all(isinstance(item, str) for item in value["allowed_paths"])
    ):
        raise BoundedWriteError("policy allowed_paths must be a non-empty string array")
    if (
        not isinstance(value["max_content_bytes"], int)
        or isinstance(value["max_content_bytes"], bool)
        or not 1 <= value["max_content_bytes"] <= MAX_CONTENT_BYTES
    ):
        raise BoundedWriteError("policy max_content_bytes is out of bounds")
    return value


def normalize_relative_target(value: str) -> str:
    if not value or "\x00" in value:
        raise BoundedWriteError("target path is empty or contains NUL")
    windows = value.replace("/", "\\")
    pure = PureWindowsPath(windows)
    if pure.drive or pure.root or pure.is_absolute():
        raise BoundedWriteError("target path must be workspace-relative")
    parts = pure.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise BoundedWriteError("target path traversal is forbidden")
    for part in parts:
        if part.endswith((" ", ".")):
            raise BoundedWriteError("target path has a Windows-ambiguous component")
        stem = part.split(".", 1)[0].upper()
        if stem in RESERVED_WINDOWS_NAMES:
            raise BoundedWriteError("target path uses a reserved Windows name")
    return "/".join(parts)


def _require_contained(workspace: Path, candidate: Path) -> Path:
    root = workspace.resolve(strict=True)
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise BoundedWriteError("target resolves outside the workspace") from exc
    return resolved


def write_bounded_file(
    *, script_path: Path, target: str, content_base64: str
) -> dict[str, Any]:
    script = script_path.resolve(strict=True)
    metadata = script.parent
    workspace = metadata.parent.resolve(strict=True)
    policy = _load_policy(metadata / POLICY_FILENAME)
    policy_workspace = Path(policy["workspace"]).resolve(strict=True)
    if workspace != policy_workspace or Path.cwd().resolve(strict=True) != workspace:
        raise BoundedWriteError("policy, helper, and current workspace are not bound")

    normalized = normalize_relative_target(target)
    allowed = [normalize_relative_target(item) for item in policy["allowed_paths"]]
    if len(set(allowed)) != len(allowed) or normalized not in allowed:
        raise BoundedWriteError("target is not an exact contract-declared path")
    if target.replace("\\", "/") != normalized:
        raise BoundedWriteError("target must use its canonical relative spelling")

    try:
        encoded = content_base64.encode("ascii")
        content = base64.b64decode(encoded, validate=True)
        content.decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError, binascii.Error) as exc:
        raise BoundedWriteError("content must be canonical base64 for UTF-8 text") from exc
    if base64.b64encode(content) != encoded:
        raise BoundedWriteError("content base64 is not canonical")
    if len(content) > policy["max_content_bytes"]:
        raise BoundedWriteError("content exceeds the bounded-write size limit")
    if b"\x00" in content:
        raise BoundedWriteError("NUL bytes are not allowed in text content")

    destination = workspace.joinpath(*PureWindowsPath(normalized).parts)
    _require_contained(workspace, destination)
    if destination.is_symlink():
        raise BoundedWriteError("symbolic-link targets are forbidden")
    if destination.exists():
        stat = destination.stat()
        if not destination.is_file() or stat.st_nlink != 1:
            raise BoundedWriteError("target must be a regular single-link file")

    destination.parent.mkdir(parents=True, exist_ok=True)
    _require_contained(workspace, destination.parent)
    if destination.is_symlink():
        raise BoundedWriteError("target became a symbolic link")

    temporary = destination.parent / (
        f".{destination.name}.mtr-bounded-{secrets.token_hex(8)}.tmp"
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
        _require_contained(workspace, temporary)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        _require_contained(workspace, destination.parent)
        os.replace(temporary, destination)
    except OSError as exc:
        raise BoundedWriteError(f"bounded file write failed: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass

    written = destination.read_bytes()
    if written != content:
        raise BoundedWriteError("post-write byte verification failed")
    return {
        "schema_version": "1.0.0",
        "status": "written",
        "target": normalized,
        "bytes": len(written),
        "sha256": hashlib.sha256(written).hexdigest(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--content-base64", required=True)
    arguments = parser.parse_args(argv)
    try:
        receipt = write_bounded_file(
            script_path=Path(__file__),
            target=arguments.target,
            content_base64=arguments.content_base64,
        )
    except BoundedWriteError as exc:
        sys.stderr.write(json.dumps({
            "schema_version": "1.0.0",
            "status": "rejected",
            "error": str(exc),
        }, sort_keys=True) + "\n")
        return 2
    sys.stdout.write(json.dumps(receipt, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
