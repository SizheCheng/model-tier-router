from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from .config import canonical_json_bytes


FORBIDDEN_COMMAND_WORDS = {
    "push",
    "remote",
    "tag",
    "reset",
    "clean",
    "rebase",
    "stash",
}


def freeze_validator_plan(plan: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(plan)).hexdigest()


def paths_allowed(paths: list[str], patterns: list[str]) -> bool:
    return bool(paths) and all(
        any(fnmatch.fnmatchcase(path.replace("\\", "/"), pattern) for pattern in patterns)
        for path in paths
    )


def validate_command(command: list[str]) -> None:
    lowered = [part.lower() for part in command]
    if lowered and Path(lowered[0]).name in {"git", "git.exe"}:
        if any(word in lowered[1:] for word in FORBIDDEN_COMMAND_WORDS):
            raise ValueError("forbidden Git command in validator plan")


def run_validator(
    worktree: str | Path,
    validator: dict[str, Any],
    raw_directory: str | Path,
) -> dict[str, Any]:
    command = [str(part) for part in validator["command"]]
    validate_command(command)
    raw = Path(raw_directory)
    raw.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    env.update({str(k): str(v) for k, v in validator.get("env", {}).items()})
    if validator.get("pythonpath_src", False):
        env["PYTHONPATH"] = str(Path(worktree, "src").resolve())
    started = time.monotonic()
    completed = subprocess.run(
        command,
        cwd=worktree,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=int(validator.get("timeout_seconds", 900)),
        env=env,
        check=False,
    )
    elapsed = time.monotonic() - started
    name = validator["name"]
    (raw / f"validator-{name}.stdout.log").write_text(completed.stdout, encoding="utf-8")
    (raw / f"validator-{name}.stderr.log").write_text(completed.stderr, encoding="utf-8")
    return {
        "name": name,
        "layer": validator.get("layer", "focused"),
        "exit_code": completed.returncode,
        "passed": completed.returncode == 0,
        "wall_time_seconds": round(elapsed, 3),
        "stdout_sha256": hashlib.sha256(completed.stdout.encode("utf-8")).hexdigest(),
        "stderr_sha256": hashlib.sha256(completed.stderr.encode("utf-8")).hexdigest(),
    }


def run_plan(
    worktree: str | Path,
    plan: dict[str, Any],
    raw_directory: str | Path,
) -> list[dict[str, Any]]:
    return [run_validator(worktree, validator, raw_directory) for validator in plan["commands"]]


def summarize_validation(
    baseline_passed: bool,
    changed_paths_ok: bool,
    results: list[dict[str, Any]],
    forbidden_action_detected: bool,
) -> dict[str, Any]:
    def layer_passed(layer: str) -> bool | None:
        matches = [item for item in results if item.get("layer") == layer]
        if not matches:
            return None
        return all(item["passed"] for item in matches)

    all_passed = bool(results) and all(item["passed"] for item in results)
    return {
        "baseline_passed": baseline_passed,
        "focused_tests_passed": layer_passed("focused"),
        "full_tests_passed": layer_passed("full"),
        "artifact_checks_passed": layer_passed("artifact"),
        "changed_paths_allowed": changed_paths_ok,
        "unrelated_paths_changed": not changed_paths_ok,
        "forbidden_action_detected": forbidden_action_detected,
        "validator_results": results,
        "automated_acceptance": bool(
            baseline_passed
            and changed_paths_ok
            and all_passed
            and not forbidden_action_detected
        ),
    }


def risk_allows_auto_merge(risk: str, change_class: str, arm: str) -> bool:
    return risk == "LOW_RISK" and change_class in {
        "documentation",
        "tests",
        "synthetic fixtures",
        "examples",
        "developer-only diagnostics",
    } and arm == "ROUTER_AUTO"
