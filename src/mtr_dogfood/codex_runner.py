from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Iterable


RATE_LIMIT_PATTERNS = re.compile(r"rate limit|too many requests|quota|capacity", re.I)
MODEL_UNAVAILABLE_PATTERNS = re.compile(
    r"model unavailable|model not found|temporarily unavailable", re.I
)
AUTH_PATTERNS = re.compile(r"not authenticated|invalid token|login required", re.I)
SCHEMA_PATTERNS = re.compile(r"invalid_json_schema|invalid schema for response_format", re.I)
HOST_POLICY_PATTERNS = re.compile(
    r"HOST_POLICY_REJECTED_EXTERNAL_CODE_TRANSFER|external code transfer", re.I
)
HOST_FILESYSTEM_POLICY_PATTERNS = re.compile(
    r"writing is blocked by read-only sandbox|rejected: blocked by policy|"
    r"rejected by user approval settings",
    re.I,
)


def resolve_codex_executable() -> str:
    override = os.environ.get("MTR_DOGFOOD_CODEX_EXE")
    if override and Path(override).is_file():
        return str(Path(override).resolve())
    appdata = os.environ.get("APPDATA")
    if appdata:
        native = (
            Path(appdata)
            / "npm"
            / "node_modules"
            / "@openai"
            / "codex"
            / "node_modules"
            / "@openai"
            / "codex-win32-x64"
            / "vendor"
            / "x86_64-pc-windows-msvc"
            / "bin"
            / "codex.exe"
        )
        if native.is_file():
            return str(native.resolve())
    discovered = shutil.which("codex")
    if discovered and Path(discovered).suffix.lower() == ".exe":
        return str(Path(discovered).resolve())
    raise FileNotFoundError("native codex executable was not found")


def build_command(
    worktree: str | Path,
    model: str,
    reasoning_effort: str,
    output_schema: str | Path,
    output_file: str | Path,
) -> list[str]:
    return [
        resolve_codex_executable(),
        "exec",
        "--ignore-user-config",
        "--ignore-rules",
        "-C",
        str(Path(worktree).resolve()),
        "--ephemeral",
        "--model",
        model,
        "-c",
        f'model_reasoning_effort="{reasoning_effort}"',
        "-c",
        "memories.generate_memories=false",
        "-c",
        "memories.use_memories=false",
        "-c",
        'approval_policy="never"',
        "-c",
        'web_search="disabled"',
        "-c",
        "sandbox_workspace_write.network_access=false",
        "--disable",
        "memories",
        "--disable",
        "apps",
        "--disable",
        "browser_use",
        "--disable",
        "browser_use_external",
        "--disable",
        "computer_use",
        "--disable",
        "multi_agent",
        "--disable",
        "plugins",
        "--strict-config",
        "--sandbox",
        "workspace-write",
        "--json",
        "--output-schema",
        str(Path(output_schema).resolve()),
        "--output-last-message",
        str(Path(output_file).resolve()),
        "-",
    ]


def _walk_usage(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        usage = value.get("usage")
        if isinstance(usage, dict):
            yield usage
        for child in value.values():
            yield from _walk_usage(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_usage(child)


def extract_usage(lines: Iterable[str]) -> dict[str, int | None]:
    totals = {
        "input_tokens": 0,
        "cached_input_tokens": 0,
        "output_tokens": 0,
        "reasoning_output_tokens": 0,
    }
    found = False
    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("type") != "turn.completed":
            continue
        usages = list(_walk_usage(event))
        for usage in usages:
            if any(key in usage for key in totals):
                found = True
                for key in totals:
                    value = usage.get(key)
                    if isinstance(value, int):
                        totals[key] += value
    if not found:
        return {key: None for key in totals}
    return totals


def classify_infrastructure(events: str, stderr: str) -> dict[str, int | str | None]:
    structured_errors: list[str] = []
    parsed_event = False
    for line in events.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        parsed_event = True
        if event.get("type") in {"error", "turn.failed"}:
            structured_errors.append(json.dumps(event, ensure_ascii=False))
    if structured_errors:
        combined = f"{' '.join(structured_errors)}\n{stderr}"
    elif parsed_event:
        # Successful structured event payloads can echo task text containing
        # infrastructure vocabulary. Only stderr is a fallback error channel.
        combined = stderr
    else:
        combined = f"{events}\n{stderr}"
    rate = len(RATE_LIMIT_PATTERNS.findall(combined))
    unavailable = len(MODEL_UNAVAILABLE_PATTERNS.findall(combined))
    auth = len(AUTH_PATTERNS.findall(combined))
    schema = len(SCHEMA_PATTERNS.findall(combined))
    external_host_policy = len(HOST_POLICY_PATTERNS.findall(combined))
    filesystem_host_policy = len(HOST_FILESYSTEM_POLICY_PATTERNS.findall(combined))
    host_policy = external_host_policy + filesystem_host_policy
    failure = None
    if rate:
        failure = "RATE_LIMIT"
    elif unavailable:
        failure = "MODEL_UNAVAILABLE"
    elif auth:
        failure = "AUTHENTICATION_FAILURE"
    elif schema:
        failure = "VALIDATOR_DEFECT"
    elif external_host_policy:
        failure = "HOST_POLICY_REJECTED_EXTERNAL_CODE_TRANSFER"
    elif filesystem_host_policy:
        failure = "HOST_POLICY_REJECTED_CHILD_FILESYSTEM_ACCESS"
    return {
        "rate_limit_event_count": rate,
        "model_unavailable_event_count": unavailable,
        "authentication_event_count": auth,
        "output_schema_error_count": schema,
        "host_policy_failure_count": host_policy,
        "infrastructure_failure_class": failure,
    }


def observe_model_execution(lines: Iterable[str]) -> tuple[bool, bool]:
    observed = False
    completed = False
    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        event_type = event.get("type")
        item = event.get("item")
        item_type = item.get("type") if isinstance(item, dict) else None
        if event_type in {"item.started", "item.completed"} and item_type in {
            "agent_message",
            "reasoning",
            "command_execution",
            "file_change",
        }:
            observed = True
        if event_type == "turn.completed" and isinstance(event.get("usage"), dict):
            observed = True
            completed = True
    return observed, completed


def run_codex(
    command: list[str],
    prompt: str,
    raw_directory: str | Path,
    *,
    worktree: str | Path,
    timeout_seconds: int,
    on_process_started: Callable[[], None] | None = None,
    should_cancel: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    raw = Path(raw_directory)
    raw.mkdir(parents=True, exist_ok=True)
    events_path = raw / "codex-events.jsonl"
    stdout_path = raw / "stdout.log"
    stderr_path = raw / "stderr.log"
    child_temp = Path(worktree, ".mtr-dogfood-r2", "tmp")
    child_temp.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=worktree,
            text=True,
            encoding="utf-8",
            errors="replace",
            env={
                **os.environ,
                "PYTHONDONTWRITEBYTECODE": "1",
                "TEMP": str(child_temp.resolve()),
                "TMP": str(child_temp.resolve()),
            },
        )
    except OSError as exc:
        elapsed = time.monotonic() - started
        events_path.write_text("", encoding="utf-8")
        stdout_path.write_text("", encoding="utf-8")
        stderr_path.write_text(str(exc), encoding="utf-8")
        return {
            "exit_code": None,
            "wall_time_seconds": round(elapsed, 3),
            "child_process_started": False,
            "model_execution_observed": False,
            "model_execution_completed": False,
            "timed_out": False,
            "cancelled": False,
            "command_count": 0,
            "file_change_event_count": 0,
            **{key: None for key in (
                "input_tokens",
                "cached_input_tokens",
                "output_tokens",
                "reasoning_output_tokens",
            )},
            "rate_limit_event_count": 0,
            "model_unavailable_event_count": 0,
            "authentication_event_count": 0,
            "output_schema_error_count": 0,
            "host_policy_failure_count": 0,
            "infrastructure_failure_class": "SHELL_COMMAND_NOT_FOUND",
        }
    if on_process_started is not None:
        on_process_started()
    timed_out = False
    cancelled = False
    if should_cancel is None:
        try:
            stdout, stderr = process.communicate(input=prompt, timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            stdout, stderr = process.communicate()
    else:
        if process.stdin is None:
            process.kill()
            process.communicate()
            raise RuntimeError("CODEX_STDIN_UNAVAILABLE")
        process.stdin.write(prompt)
        process.stdin.close()
        process.stdin = None
        deadline = time.monotonic() + timeout_seconds
        while True:
            if should_cancel():
                cancelled = True
                process.kill()
                stdout, stderr = process.communicate()
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                process.kill()
                stdout, stderr = process.communicate()
                break
            try:
                stdout, stderr = process.communicate(timeout=min(0.25, remaining))
                break
            except subprocess.TimeoutExpired:
                continue
    elapsed = time.monotonic() - started
    events_path.write_text(stdout, encoding="utf-8")
    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")
    lines = stdout.splitlines()
    observed, completed = observe_model_execution(lines)
    result: dict[str, Any] = {
        "exit_code": process.returncode,
        "wall_time_seconds": round(elapsed, 3),
        "child_process_started": True,
        "model_execution_observed": observed,
        "model_execution_completed": completed,
        "timed_out": timed_out,
        "cancelled": cancelled,
        "command_count": sum(1 for line in lines if '"item.type":"command_execution"' in line),
        "file_change_event_count": sum(
            1 for line in lines if '"item.type":"file_change"' in line
        ),
        **extract_usage(lines),
        **classify_infrastructure(stdout, stderr),
    }
    if timed_out and result["infrastructure_failure_class"] is None and not observed:
        result["infrastructure_failure_class"] = "DEPENDENCY_OR_ENVIRONMENT_FAILURE"
    if cancelled and result["infrastructure_failure_class"] is None:
        result["infrastructure_failure_class"] = "OPERATOR_KILL_SWITCH"
    return result
