"""Strict JSON command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from .api import assess
from .core.decision import failure_decision
from .schema_validation import validate_advisory_decision
from .strict_json import canonical_json_bytes, strict_json_loads


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="model-tier-router")
    commands = parser.add_subparsers(dest="command", required=True)
    assess_parser = commands.add_parser("assess", help="produce one advisory decision")
    assess_parser.add_argument("--input", type=Path, help="request file; default is stdin")
    assess_parser.add_argument("--policy", type=Path, help="optional policy JSON file")
    assess_parser.add_argument("--profiles", type=Path, help="optional profile-catalog JSON file")
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = build_parser().parse_args(argv)
        request = _read_json(arguments.input)
    except (OSError, UnicodeError, TypeError, ValueError):
        return _emit(failure_decision("invalid_request", "INVALID_REQUEST"), 2)
    policy: Any = None
    profiles: Any = None
    try:
        if arguments.policy is not None:
            policy = _read_json(arguments.policy)
        if arguments.profiles is not None:
            profiles = _read_json(arguments.profiles)
    except (OSError, UnicodeError, TypeError, ValueError):
        return _emit(failure_decision("integration_failure", "INVALID_CONFIGURATION"), 3)
    try:
        decision = assess(request, policy=policy, profiles=profiles)
        status = decision["status"]
        code = 0
        if status == "invalid_request":
            code = 2
        elif status == "integration_failure":
            code = 3 if decision["trace"].get("error_code") == "INVALID_CONFIGURATION" else 4
        return _emit(decision, code)
    except Exception:
        return _emit(failure_decision("integration_failure", "INTEGRATION_FAILURE"), 4)


def _read_json(path: Path | None) -> Any:
    raw = sys.stdin.buffer.read() if path is None else path.read_bytes()
    return strict_json_loads(raw)


def _emit(decision: dict[str, Any], exit_code: int) -> int:
    try:
        validate_advisory_decision(decision)
        sys.stdout.buffer.write(canonical_json_bytes(decision) + b"\n")
        return exit_code
    except Exception:
        fallback = failure_decision("integration_failure", "INTEGRATION_FAILURE")
        sys.stdout.buffer.write(canonical_json_bytes(fallback) + b"\n")
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
