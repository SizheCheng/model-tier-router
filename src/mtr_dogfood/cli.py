from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from .config import canonical_json_bytes, harness_root, load_json
from .r2_contract import InvocationBudget
from .r2_execution import execute_lane, preflight_r2, run_r2_batch
from .receipts import write_json
from .reporting import build_r2_report, write_r2_reports


FORBIDDEN_ACTION_RE = re.compile(
    r"\bgit\s+(commit|merge|rebase|reset|clean|push|remote|tag|stash)\b"
    r"|\b(publish|deploy|release|customer\s+delivery)\b",
    re.I,
)


def _root() -> Path:
    return harness_root()


def _json_print(value: Any) -> None:
    sys.stdout.buffer.write(canonical_json_bytes(value))


def _forbidden_action_detected(events_path: Path) -> bool:
    if not events_path.exists():
        return False
    for line in events_path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        command = None
        item = event.get("item")
        if isinstance(item, dict) and item.get("type") == "command_execution":
            command = item.get("command")
        elif event.get("type") == "command_execution":
            command = event.get("command")
        if isinstance(command, str) and FORBIDDEN_ACTION_RE.search(command):
            return True
    return False


def command_preflight(_: argparse.Namespace) -> int:
    _json_print(preflight_r2())
    return 0


def command_run(args: argparse.Namespace) -> int:
    if args.arm != "ROUTER_AUTO":
        raise RuntimeError("UNAUTHORIZED_CONTROL_RERUN_OR_MERGE")
    result = execute_lane(args.case_id, InvocationBudget(maximum=5))
    _json_print(result)
    return 0 if result.get("final_status") == "VALIDATED" else 1


def command_batch(_: argparse.Namespace) -> int:
    result = run_r2_batch()
    _json_print(result)
    return 0 if any(
        lane.get("final_status") == "VALIDATED"
        for lane in result.get("lanes", [])
    ) else 1


def command_report(_: argparse.Namespace) -> int:
    batch_path = _root() / "runs" / "receipts" / "r2" / "batch.json"
    batch = load_json(batch_path)
    report = build_r2_report(batch, _root() / "runs" / "receipts")
    paths = write_r2_reports(report, _root() / "reports")
    _json_print({"report": report, "paths": paths})
    return 0


def command_record_outcome(args: argparse.Namespace) -> int:
    matches = sorted(
        (_root() / "runs" / "receipts" / "r2" / args.case_id).glob(
            "attempt-*/outcome.json"
        )
    )
    if not matches:
        raise ValueError("R2 outcome not found")
    for path in matches:
        value = load_json(path)
        value["human_review_state"] = args.state
        value["human_accepted"] = (
            True
            if args.state == "accepted"
            else False
            if args.state == "rejected"
            else None
        )
        write_json(path, value)
    _json_print({"updated": [str(path) for path in matches]})
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mtr-dogfood")
    subparsers = parser.add_subparsers(dest="command", required=True)
    preflight = subparsers.add_parser("preflight")
    preflight.set_defaults(function=command_preflight)
    run = subparsers.add_parser("run")
    run.add_argument("--case-id", required=True)
    run.add_argument("--arm", choices=["ROUTER_AUTO"], default="ROUTER_AUTO")
    run.set_defaults(function=command_run)
    batch = subparsers.add_parser("batch")
    batch.set_defaults(function=command_batch)
    report = subparsers.add_parser("report")
    report.set_defaults(function=command_report)
    outcome = subparsers.add_parser("record-outcome")
    outcome.add_argument("--case-id", required=True)
    outcome.add_argument(
        "--state", choices=["pending", "accepted", "rejected"], required=True
    )
    outcome.set_defaults(function=command_record_outcome)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.function(args))
    except Exception as exc:
        _json_print(
            {
                "status": "error",
                "error_type": type(exc).__name__,
                "message": str(exc),
            }
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
