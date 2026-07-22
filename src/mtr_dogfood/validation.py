from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
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


VALIDATOR_AUTHORITY = {
    "execution_model": "trusted_repository_test_process_v1",
    "repository_test_code_trusted": True,
    "environment_scrubbed": True,
    "os_sandbox_enforced": False,
    "shell_commands_allowed": False,
    "inline_code_allowed": False,
    "network_access_authorized": False,
    "external_path_access_authorized": False,
}

_VALIDATOR_EXECUTABLES = {
    "python",
    "python.exe",
    "py",
    "py.exe",
    "npm",
    "npm.cmd",
    "pnpm",
    "pnpm.cmd",
    "yarn",
    "yarn.cmd",
    "cargo",
    "cargo.exe",
    "dotnet",
    "dotnet.exe",
    "go",
    "go.exe",
}
_VALIDATOR_HOST_ENV_ALLOWLIST = {
    "COMSPEC",
    "LANG",
    "LC_ALL",
    "NUMBER_OF_PROCESSORS",
    "OS",
    "PATH",
    "PATHEXT",
    "PROCESSOR_ARCHITECTURE",
    "SYSTEMDRIVE",
    "SYSTEMROOT",
    "TZ",
    "WINDIR",
}
_SENSITIVE_ENV_MARKERS = {
    "AUTH",
    "CREDENTIAL",
    "KEY",
    "PASSWORD",
    "SECRET",
    "TOKEN",
}


def _validator_argument_crosses_boundary(value: str) -> bool:
    if "http://" in value.casefold() or "https://" in value.casefold():
        return True
    if value.startswith("@"):
        return True
    operand = value.split("=", 1)[-1] if "=" in value else value
    normalized = operand.replace("\\", "/")
    if (
        re.match(r"^[A-Za-z]:/", normalized)
        or normalized.startswith("//")
        or normalized.startswith("/")
    ):
        return True
    return ".." in Path(normalized).parts


def validate_validator_authority(
    plan: dict[str, Any], authority: dict[str, Any],
) -> None:
    if authority != VALIDATOR_AUTHORITY:
        raise ValueError("validator authority contract is invalid")
    commands = plan.get("commands") if isinstance(plan, dict) else None
    if not isinstance(commands, list) or not commands:
        raise ValueError("validator plan must contain commands")
    for validator in commands:
        if not isinstance(validator, dict):
            raise ValueError("validator entry must be an object")
        command = validator.get("command")
        if (
            not isinstance(command, list)
            or not command
            or any(not isinstance(part, str) or not part for part in command)
        ):
            raise ValueError("validator command must be non-empty argv")
        executable = command[0].casefold()
        if (
            executable not in _VALIDATOR_EXECUTABLES
            or Path(command[0]).name.casefold() != executable
            or any(marker in command[0] for marker in ("/", "\\", ":"))
        ):
            raise ValueError("validator executable is not allowlisted")
        arguments = command[1:]
        if executable in {"python", "python.exe", "py", "py.exe"}:
            normalized = list(arguments)
            if normalized and normalized[0] == "-B":
                normalized.pop(0)
            if (
                len(normalized) < 2
                or normalized[0] != "-m"
                or normalized[1] not in {"pytest", "unittest"}
            ):
                raise ValueError(
                    "Python validators must use a trusted test module"
                )
        elif executable in {
            "npm", "npm.cmd", "pnpm", "pnpm.cmd", "yarn", "yarn.cmd",
        }:
            if arguments != ["test"]:
                raise ValueError(
                    "package validators must use the repository test script"
                )
        elif not arguments or arguments[0] != "test":
            raise ValueError("compiled-language validators must use test")
        if any(_validator_argument_crosses_boundary(part) for part in arguments):
            raise ValueError("validator argument crosses a safety boundary")
        environment = validator.get("env", {})
        if not isinstance(environment, dict):
            raise ValueError("validator environment is not declarative")
        for key, value in environment.items():
            if (
                not isinstance(key, str)
                or re.fullmatch(r"[A-Z][A-Z0-9_]*", key) is None
                or any(marker in key for marker in _SENSITIVE_ENV_MARKERS)
                or key in {"PATH", "PATHEXT", "COMSPEC", "SYSTEMROOT", "WINDIR"}
                or not isinstance(value, str)
                or _validator_argument_crosses_boundary(value)
            ):
                raise ValueError("validator environment is not declarative")


def _validator_environment(
    validator: dict[str, Any], worktree: Path,
) -> dict[str, str]:
    host = {key.upper(): value for key, value in os.environ.items()}
    environment = {
        key: host[key]
        for key in sorted(_VALIDATOR_HOST_ENV_ALLOWLIST)
        if key in host
    }
    environment.update({
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
    })
    environment.update(
        {str(key): str(value) for key, value in validator.get("env", {}).items()}
    )
    if validator.get("pythonpath_src", False):
        environment["PYTHONPATH"] = str((worktree / "src").resolve())
    return environment

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
    env = _validator_environment(validator, Path(worktree).resolve())
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
