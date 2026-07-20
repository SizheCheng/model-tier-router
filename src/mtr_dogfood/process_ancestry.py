from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Callable


class ProcessAncestryError(RuntimeError):
    """Raised when the external runner cannot prove its process ancestry."""


class NestedCodexAncestorError(ProcessAncestryError):
    """Raised before any fixture or worktree is created under nested Codex."""


ProcessProvider = Callable[[int], dict[str, Any] | None]

CODEX_IDENTITIES = (
    "codex",
    "codex-cli",
    "codex-app",
    "codex-code-mode-host",
    "chatgpt",
)
HARNESS_CHILD_IDENTITIES = (
    "mtr-dogfood",
    "model-tier-router-dogfood",
    "external-dogfood-runner",
)
POWERSHELL_IDENTITIES = {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}


def _basename(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        return "unknown"
    normalized = value.strip().strip('"').replace("/", "\\")
    return normalized.rsplit("\\", 1)[-1].casefold()


def sanitize_process_record(value: dict[str, Any]) -> dict[str, Any]:
    """Return only the four process-identity fields authorized by the contract."""

    try:
        pid = int(value.get("pid", value.get("ProcessId")))
        parent_pid = int(value.get("parent_pid", value.get("ParentProcessId", 0)))
    except (TypeError, ValueError) as exc:
        raise ProcessAncestryError("invalid process identity record") from exc
    executable_name = _basename(value.get("name", value.get("Name")))
    command_identity = _basename(
        value.get(
            "command_identity",
            value.get("executable_path", value.get("ExecutablePath", executable_name)),
        )
    )
    return {
        "pid": pid,
        "parent_pid": parent_pid,
        "executable_name": executable_name,
        "command_identity": command_identity,
    }


def windows_process_provider(pid: int) -> dict[str, Any] | None:
    """Read one Windows process identity without requesting its command line."""

    if os.name != "nt":
        raise ProcessAncestryError("Windows process ancestry is required")
    script = (
        "$p=Get-CimInstance Win32_Process -Filter \"ProcessId = "
        + str(int(pid))
        + "\" -ErrorAction Stop; "
        "if($null -eq $p){exit 3}; "
        "$p | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath | "
        "ConvertTo-Json -Compress"
    )
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
        timeout=15,
    )
    if completed.returncode == 3:
        return None
    if completed.returncode != 0:
        raise ProcessAncestryError("process ancestry query failed")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ProcessAncestryError("process ancestry query returned invalid JSON") from exc
    return value if isinstance(value, dict) else None


def walk_ancestor_chain(
    start_pid: int,
    provider: ProcessProvider = windows_process_provider,
    *,
    maximum_depth: int = 64,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[int] = set()
    current = int(start_pid)
    while current > 0:
        if current in seen:
            raise ProcessAncestryError("process ancestry cycle detected")
        if len(rows) >= maximum_depth:
            raise ProcessAncestryError("process ancestry depth exceeded")
        seen.add(current)
        raw = provider(current)
        if raw is None:
            if rows:
                break
            raise ProcessAncestryError("runner process identity unavailable")
        row = sanitize_process_record(raw)
        if row["pid"] != current:
            raise ProcessAncestryError("process ancestry PID mismatch")
        rows.append(row)
        parent = row["parent_pid"]
        if parent <= 0 or parent == current:
            break
        current = parent
    return rows


def _matches_identity(row: dict[str, Any], markers: tuple[str, ...]) -> bool:
    identities = (row["executable_name"], row["command_identity"])
    return any(marker in identity for marker in markers for identity in identities)


def nested_codex_ancestor(
    rows: list[dict[str, Any]],
) -> dict[str, Any] | None:
    for row in rows:
        if _matches_identity(row, CODEX_IDENTITIES + HARNESS_CHILD_IDENTITIES):
            return row
    return None


def verify_standalone_powershell(
    runner_pid: int,
    provider: ProcessProvider = windows_process_provider,
) -> dict[str, Any]:
    rows = walk_ancestor_chain(runner_pid, provider)
    runner = rows[0]
    if (
        runner["executable_name"] not in POWERSHELL_IDENTITIES
        and runner["command_identity"] not in POWERSHELL_IDENTITIES
    ):
        raise ProcessAncestryError("ordinary PowerShell runner identity not verified")
    match = nested_codex_ancestor(rows)
    receipt = {
        "schema_version": "1.0.0",
        "runner_pid": int(runner_pid),
        "ordinary_powershell_ancestor_verified": match is None,
        "nested_codex_ancestor_detected": match is not None,
        "ancestor_count": len(rows),
        "ancestors": rows,
        "hard_stop_code": "NESTED_CODEX_ANCESTOR_DETECTED" if match else "",
    }
    if match is not None:
        error = NestedCodexAncestorError("NESTED_CODEX_ANCESTOR_DETECTED")
        error.receipt = receipt  # type: ignore[attr-defined]
        raise error
    return receipt


__all__ = [
    "NestedCodexAncestorError",
    "ProcessAncestryError",
    "nested_codex_ancestor",
    "sanitize_process_record",
    "verify_standalone_powershell",
    "walk_ancestor_chain",
    "windows_process_provider",
]
