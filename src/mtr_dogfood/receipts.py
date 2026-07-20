from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from .config import canonical_json_bytes, load_json


SENSITIVE_KEYS = {
    "command_line",
    "raw_command_line",
    "stdout",
    "stderr",
    "prompt",
    "diff_patch",
    "environment",
}


def sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: sanitize(child)
            for key, child in value.items()
            if key.lower() not in SENSITIVE_KEYS
        }
    if isinstance(value, list):
        return [sanitize(child) for child in value]
    return value


def write_json(path: str | Path, value: Any, *, sanitized: bool = True) -> str:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = sanitize(value) if sanitized else value
    data = canonical_json_bytes(payload)
    temporary = target.with_name(f".{target.name}.tmp-{os.getpid()}")
    temporary.write_bytes(data)
    os.replace(temporary, target)
    return hashlib.sha256(data).hexdigest()


def validate_required_fields(path: str | Path, required: list[str]) -> dict[str, Any]:
    value = load_json(path)
    if not isinstance(value, dict):
        raise ValueError("receipt must be an object")
    missing = sorted(set(required) - set(value))
    if missing:
        raise ValueError(f"receipt missing required fields: {missing}")
    return value
