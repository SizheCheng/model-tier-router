"""Strict, bounded JSON parsing and canonical serialization."""

from __future__ import annotations

import json
from typing import Any, Iterable

MAX_JSON_BYTES = 1_048_576
MAX_JSON_NESTING = 64


class DuplicateKeyError(ValueError):
    """Raised when an object contains the same JSON member twice."""


class JSONResourceLimitError(ValueError):
    """Raised when a JSON document exceeds a deterministic resource limit."""


def _reject_duplicates(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def strict_json_loads(
    text: str | bytes,
    *,
    max_bytes: int = MAX_JSON_BYTES,
    max_nesting: int = MAX_JSON_NESTING,
) -> Any:
    """Parse one strict JSON document with byte and nesting limits."""

    if isinstance(text, bytes):
        raw = text
        decoded = raw.decode("utf-8", errors="strict")
    elif isinstance(text, str):
        decoded = text
        raw = text.encode("utf-8", errors="strict")
    else:
        raise TypeError("strict JSON input must be str or bytes")
    if len(raw) > max_bytes:
        raise JSONResourceLimitError("JSON input exceeds the byte limit")
    try:
        value = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number: {token}")
            ),
        )
    except RecursionError as exc:
        raise JSONResourceLimitError("JSON input exceeds the nesting limit") from exc
    _check_nesting(value, max_nesting)
    return value


def canonical_json_bytes(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON bytes for the no-float JCS subset."""

    _validate_canonical_subset(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8", errors="strict")


def _check_nesting(value: Any, maximum: int) -> None:
    stack = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > maximum:
            raise JSONResourceLimitError("JSON input exceeds the nesting limit")
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)


def _validate_canonical_subset(value: Any) -> None:
    stack = [value]
    while stack:
        current = stack.pop()
        if current is None or isinstance(current, bool):
            continue
        if isinstance(current, str):
            current.encode("utf-8", errors="strict")
            continue
        if isinstance(current, int):
            if abs(current) > 9_007_199_254_740_991:
                raise ValueError("integer exceeds the interoperable JSON range")
            continue
        if isinstance(current, float):
            raise ValueError("floating-point canonicalization is unsupported")
        if isinstance(current, (list, tuple)):
            stack.extend(current)
            continue
        if isinstance(current, dict):
            for key, item in current.items():
                if not isinstance(key, str):
                    raise TypeError("JSON object keys must be strings")
                key.encode("utf-8", errors="strict")
                stack.append(item)
            continue
        raise TypeError(f"unsupported JSON value: {type(current).__name__}")


__all__ = [
    "DuplicateKeyError",
    "JSONResourceLimitError",
    "MAX_JSON_BYTES",
    "MAX_JSON_NESTING",
    "canonical_json_bytes",
    "strict_json_loads",
]
