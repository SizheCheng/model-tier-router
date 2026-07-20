from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Iterable


RATE_LIMIT_PATTERNS = re.compile(r"rate limit|too many requests|quota|capacity", re.I)
MODEL_UNAVAILABLE_PATTERNS = re.compile(
    r"model unavailable|model not found|temporarily unavailable", re.I
)
AUTH_PATTERNS = re.compile(r"not authenticated|invalid token|login required", re.I)


def build_command(
    worktree: str | Path,
    model: str,
    reasoning_effort: str,
    output_schema: str | Path,
    output_file: str | Path,
) -> list[str]:
    return [
        "codex",
        "exec",
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
        'approval_policy="never"',
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
    combined = f"{events}\n{stderr}"
    rate = len(RATE_LIMIT_PATTERNS.findall(combined))
    unavailable = len(MODEL_UNAVAILABLE_PATTERNS.findall(combined))
    auth = len(AUTH_PATTERNS.findall(combined))
    failure = None
    if rate:
        failure = "RATE_LIMIT"
    elif unavailable:
        failure = "MODEL_UNAVAILABLE"
    elif auth:
        failure = "AUTHENTICATION_FAILURE"
    return {
        "rate_limit_event_count": rate,
        "model_unavailable_event_count": unavailable,
        "authentication_event_count": auth,
        "infrastructure_failure_class": failure,
    }


def run_codex(
    command: list[str],
    prompt: str,
    raw_directory: str | Path,
    *,
    timeout_seconds: int,
) -> dict[str, Any]:
    raw = Path(raw_directory)
    raw.mkdir(parents=True, exist_ok=True)
    events_path = raw / "codex-events.jsonl"
    stdout_path = raw / "stdout.log"
    stderr_path = raw / "stderr.log"
    started = time.monotonic()
    process = subprocess.run(
        command,
        input=prompt,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=timeout_seconds,
        check=False,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    elapsed = time.monotonic() - started
    events_path.write_text(process.stdout, encoding="utf-8")
    stdout_path.write_text(process.stdout, encoding="utf-8")
    stderr_path.write_text(process.stderr, encoding="utf-8")
    lines = process.stdout.splitlines()
    result: dict[str, Any] = {
        "exit_code": process.returncode,
        "wall_time_seconds": round(elapsed, 3),
        "command_count": sum(1 for line in lines if '"item.type":"command_execution"' in line),
        "file_change_event_count": sum(
            1 for line in lines if '"item.type":"file_change"' in line
        ),
        **extract_usage(lines),
        **classify_infrastructure(process.stdout, process.stderr),
    }
    return result
