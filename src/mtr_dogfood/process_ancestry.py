from __future__ import annotations

import json
import ntpath
import os
import re
import subprocess
from datetime import datetime, timezone
from typing import Any, Callable


class ProcessAncestryError(RuntimeError):
    """Raised when the external runner cannot prove its process ancestry."""

    def __init__(
        self,
        code: str,
        detail: str | None = None,
        *,
        records: list[dict[str, Any]] | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail or ""
        self.records = list(records or [])


class NestedCodexAncestorError(ProcessAncestryError):
    """Raised before any fixture or worktree is created under nested Codex."""


ProcessProvider = Callable[[int], dict[str, Any] | None]

CODEX_EXECUTABLES = frozenset({
    "codex",
    "codex.exe",
    "codex-cli",
    "codex-cli.exe",
    "codex-app",
    "codex-app.exe",
    "codex-code-mode-host",
    "codex-code-mode-host.exe",
    "chatgpt",
    "chatgpt.exe",
})
CODEX_NODE_ENTRYPOINTS = frozenset({"codex.js", "codex-cli.js"})
HARNESS_CHILD_EXECUTABLES = frozenset({
    "mtr-dogfood",
    "mtr-dogfood.exe",
    "model-tier-router-dogfood",
    "model-tier-router-dogfood.exe",
    "external-dogfood-runner",
    "external-dogfood-runner.exe",
})
POWERSHELL_IDENTITIES = frozenset({
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
})
ORDINARY_SHELL_EXECUTABLES = frozenset({
    "explorer",
    "explorer.exe",
    "windowsterminal",
    "windowsterminal.exe",
    "wt",
    "wt.exe",
    "conhost",
    "conhost.exe",
    "cmd",
    "cmd.exe",
    *POWERSHELL_IDENTITIES,
})


def _basename(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        return ""
    normalized = value.strip().strip('"').replace("/", "\\")
    return normalized.rsplit("\\", 1)[-1].casefold()


def _creation_time(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        return ""
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProcessAncestryError(
            "PROCESS_ANCESTRY_CREATION_TIME_INVALID"
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _command_tokens(value: Any) -> tuple[str, ...]:
    if not isinstance(value, str) or not value.strip():
        return ()
    return tuple(
        token.strip().strip('"').strip("'")
        for token in re.findall(r'"[^"]*"|\'[^\']*\'|\S+', value)
    )


def _node_hosts_codex(executable_name: str, command_line: Any) -> bool:
    if executable_name not in {"node", "node.exe"}:
        return False
    for token in _command_tokens(command_line)[1:]:
        normalized = token.replace("/", "\\").casefold()
        if ntpath.basename(normalized) not in CODEX_NODE_ENTRYPOINTS:
            continue
        if (
            "\\@openai\\codex\\" in normalized
            or "\\codex\\bin\\" in normalized
            or "\\" not in normalized
        ):
            return True
    return False


def sanitize_process_record(value: dict[str, Any]) -> dict[str, Any]:
    """Return identity evidence without persisting the raw command line."""

    pid_value = value.get("pid", value.get("ProcessId"))
    if "parent_pid" in value:
        parent_value = value["parent_pid"]
    else:
        parent_value = value.get("ParentProcessId")
    try:
        pid = int(pid_value)
        parent_pid = int(parent_value)
    except (TypeError, ValueError) as exc:
        raise ProcessAncestryError(
            "PROCESS_ANCESTRY_IDENTITY_INVALID"
        ) from exc
    if pid <= 0 or parent_pid < 0:
        raise ProcessAncestryError("PROCESS_ANCESTRY_IDENTITY_INVALID")
    executable_name = _basename(value.get("name", value.get("Name")))
    executable_path_value = value.get(
        "executable_path", value.get("ExecutablePath", "")
    )
    executable_path = (
        str(executable_path_value).strip()
        if isinstance(executable_path_value, str)
        else ""
    )
    creation_time = _creation_time(
        value.get(
            "creation_time_utc",
            value.get("CreationTimeUtc", value.get("CreationDate")),
        )
    )
    if not executable_name:
        raise ProcessAncestryError("PROCESS_ANCESTRY_IMAGE_NAME_MISSING")
    node_hosts_codex = _node_hosts_codex(
        executable_name,
        value.get("command_line", value.get("CommandLine")),
    )
    return {
        "pid": pid,
        "parent_pid": parent_pid,
        "executable_name": executable_name,
        "executable_path": executable_path,
        "creation_time_utc": creation_time,
        "command_classification": (
            "node_hosted_codex_cli" if node_hosts_codex else "not_codex_launcher"
        ),
    }


def windows_process_provider(pid: int) -> dict[str, Any] | None:
    """Capture one Windows process identity for a fail-closed snapshot."""

    if os.name != "nt":
        raise ProcessAncestryError("WINDOWS_PROCESS_ANCESTRY_REQUIRED")
    script = (
        "$p=Get-CimInstance Win32_Process -Filter \"ProcessId = "
        + str(int(pid))
        + "\" -ErrorAction Stop; "
        "if($null -eq $p){exit 3}; "
        "$o=[ordered]@{ProcessId=$p.ProcessId;"
        "ParentProcessId=$p.ParentProcessId;Name=$p.Name;"
        "ExecutablePath=$p.ExecutablePath;CommandLine=$p.CommandLine;"
        "CreationTimeUtc=if($p.CreationDate){"
        "$p.CreationDate.ToUniversalTime().ToString('o')}else{$null}};"
        "$o | ConvertTo-Json -Compress"
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
        raise ProcessAncestryError("PROCESS_ANCESTRY_METADATA_INACCESSIBLE")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ProcessAncestryError(
            "PROCESS_ANCESTRY_QUERY_INVALID_JSON"
        ) from exc
    return value if isinstance(value, dict) else None


def _parsed_creation_time(row: dict[str, Any]) -> datetime:
    value = row.get("creation_time_utc")
    if not value:
        raise ProcessAncestryError("PROCESS_ANCESTRY_CREATION_TIME_MISSING")
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


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
            raise ProcessAncestryError(
                "PROCESS_ANCESTRY_CYCLE_DETECTED", records=rows
            )
        if len(rows) >= maximum_depth:
            raise ProcessAncestryError(
                "PROCESS_ANCESTRY_DEPTH_EXCEEDED", records=rows
            )
        seen.add(current)
        try:
            raw = provider(current)
        except ProcessAncestryError as exc:
            if not exc.records:
                exc.records = list(rows)
            raise
        if raw is None:
            code = (
                "PROCESS_ANCESTRY_INCOMPLETE"
                if rows
                else "RUNNER_PROCESS_IDENTITY_UNAVAILABLE"
            )
            raise ProcessAncestryError(code, records=rows)
        try:
            row = sanitize_process_record(raw)
            created = _parsed_creation_time(row)
        except ProcessAncestryError as exc:
            exc.records = list(rows)
            raise
        if row["pid"] != current:
            raise ProcessAncestryError(
                "PROCESS_ANCESTRY_PID_MISMATCH", records=rows
            )
        if rows and created > _parsed_creation_time(rows[-1]):
            raise ProcessAncestryError(
                "PROCESS_ANCESTRY_PID_REUSE_OR_SNAPSHOT_INCONSISTENT",
                records=[*rows, row],
            )
        rows.append(row)
        parent = row["parent_pid"]
        if parent == 0:
            return rows
        if parent == current:
            raise ProcessAncestryError(
                "PROCESS_ANCESTRY_CYCLE_DETECTED", records=rows
            )
        current = parent
    raise ProcessAncestryError("PROCESS_ANCESTRY_INCOMPLETE", records=rows)


def classify_process(row: dict[str, Any]) -> str:
    executable = str(row.get("executable_name", "")).casefold()
    path_identity = _basename(row.get("executable_path"))
    if (
        executable in CODEX_EXECUTABLES
        or path_identity in CODEX_EXECUTABLES
        or row.get("command_classification") == "node_hosted_codex_cli"
        or executable in HARNESS_CHILD_EXECUTABLES
        or path_identity in HARNESS_CHILD_EXECUTABLES
    ):
        return "prohibited_codex_ancestor"
    if executable in ORDINARY_SHELL_EXECUTABLES:
        return "ordinary_shell"
    return "ambiguous_unknown_host"


def nested_codex_ancestor(
    rows: list[dict[str, Any]],
) -> dict[str, Any] | None:
    return next(
        (row for row in rows if classify_process(row) == "prohibited_codex_ancestor"),
        None,
    )


def _receipt(
    runner_pid: int,
    rows: list[dict[str, Any]],
    *,
    evidence_complete: bool,
    hard_stop_code: str,
) -> dict[str, Any]:
    trigger = nested_codex_ancestor(rows)
    classified = [
        {**row, "process_class": classify_process(row)} for row in rows
    ]
    return {
        "schema_version": "2.0.0",
        "runner_pid": int(runner_pid),
        "evidence_complete": evidence_complete,
        "ordinary_powershell_ancestor_verified": (
            evidence_complete and not hard_stop_code
        ),
        "nested_codex_ancestor_detected": trigger is not None,
        "ancestor_count": len(rows),
        "ancestors": classified,
        "trigger_process": trigger,
        "hard_stop_code": hard_stop_code,
    }


def verify_standalone_powershell(
    runner_pid: int,
    provider: ProcessProvider = windows_process_provider,
) -> dict[str, Any]:
    try:
        rows = walk_ancestor_chain(runner_pid, provider)
    except ProcessAncestryError as exc:
        trigger = nested_codex_ancestor(exc.records)
        if trigger is not None:
            receipt = _receipt(
                runner_pid,
                exc.records,
                evidence_complete=False,
                hard_stop_code="NESTED_CODEX_ANCESTOR_DETECTED",
            )
            error = NestedCodexAncestorError(
                "NESTED_CODEX_ANCESTOR_DETECTED", records=exc.records
            )
            error.receipt = receipt  # type: ignore[attr-defined]
            raise error from exc
        exc.receipt = _receipt(  # type: ignore[attr-defined]
            runner_pid,
            exc.records,
            evidence_complete=False,
            hard_stop_code=exc.code,
        )
        raise

    runner = rows[0]
    if runner["executable_name"] not in POWERSHELL_IDENTITIES:
        error = ProcessAncestryError(
            "NONORDINARY_POWERSHELL_RUNNER", records=rows
        )
        error.receipt = _receipt(  # type: ignore[attr-defined]
            runner_pid,
            rows,
            evidence_complete=True,
            hard_stop_code=error.code,
        )
        raise error
    match = nested_codex_ancestor(rows)
    if match is not None:
        receipt = _receipt(
            runner_pid,
            rows,
            evidence_complete=True,
            hard_stop_code="NESTED_CODEX_ANCESTOR_DETECTED",
        )
        error = NestedCodexAncestorError(
            "NESTED_CODEX_ANCESTOR_DETECTED", records=rows
        )
        error.receipt = receipt  # type: ignore[attr-defined]
        raise error
    if any(classify_process(row) == "ambiguous_unknown_host" for row in rows):
        error = ProcessAncestryError(
            "PROCESS_ANCESTRY_CLASSIFICATION_AMBIGUOUS", records=rows
        )
        error.receipt = _receipt(  # type: ignore[attr-defined]
            runner_pid,
            rows,
            evidence_complete=True,
            hard_stop_code=error.code,
        )
        raise error
    return _receipt(
        runner_pid, rows, evidence_complete=True, hard_stop_code=""
    )


__all__ = [
    "NestedCodexAncestorError",
    "ProcessAncestryError",
    "classify_process",
    "nested_codex_ancestor",
    "sanitize_process_record",
    "verify_standalone_powershell",
    "walk_ancestor_chain",
    "windows_process_provider",
]
