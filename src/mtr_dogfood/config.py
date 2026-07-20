from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
from typing import Any


class ContractError(ValueError):
    """Raised when local configuration violates a closed contract."""


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ContractError(f"non-finite JSON number: {value}")


def strict_json_loads(text: str) -> Any:
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs_no_duplicates,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ContractError(f"invalid JSON: {exc}") from exc
    _reject_non_finite(value)
    return value


def _reject_non_finite(value: Any) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ContractError("non-finite JSON number")
    if isinstance(value, dict):
        for child in value.values():
            _reject_non_finite(child)
    elif isinstance(value, list):
        for child in value:
            _reject_non_finite(child)


def load_json(path: str | Path) -> Any:
    return strict_json_loads(Path(path).read_text(encoding="utf-8"))


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def json_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def normalized_path(path: str | Path) -> Path:
    return Path(path).expanduser().resolve(strict=False)


def is_contained(root: str | Path, candidate: str | Path) -> bool:
    root_path = normalized_path(root)
    candidate_path = normalized_path(candidate)
    try:
        candidate_path.relative_to(root_path)
        return True
    except ValueError:
        return False


def same_path(left: str | Path, right: str | Path) -> bool:
    return os.path.normcase(str(normalized_path(left))) == os.path.normcase(
        str(normalized_path(right))
    )


def ensure_repository_allowed(
    path: str | Path,
    repositories: dict[str, str],
    denylist: list[str],
) -> str:
    if any(same_path(path, denied) for denied in denylist):
        raise ContractError("known external repository is denied")
    for repository_id, allowed in repositories.items():
        if same_path(path, allowed):
            return repository_id
    raise ContractError("repository is outside the exact allowlist")


def harness_root() -> Path:
    return Path(__file__).resolve().parents[2]
