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

TRUSTED_EXPLORER_EXECUTABLE = "explorer.exe"


def _basename(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        return ""
    normalized = value.strip().strip('"').replace("/", "\\")
    return normalized.rsplit("\\", 1)[-1].casefold()

def _optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ProcessAncestryError(
            "PROCESS_ANCESTRY_IDENTITY_INVALID"
        ) from exc


def _optional_bool(value: Any) -> bool | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().casefold()
        if normalized in {"true", "1"}:
            return True
        if normalized in {"false", "0"}:
            return False
    raise ProcessAncestryError("PROCESS_ANCESTRY_IDENTITY_INVALID")


def _identity_text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _canonical_windows_path(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        return ""
    return ntpath.normcase(ntpath.normpath(value.strip().strip('"')))


def expected_explorer_path() -> str:
    windows_root = os.environ.get("WINDIR", r"C:\Windows")
    return ntpath.join(windows_root, TRUSTED_EXPLORER_EXECUTABLE)


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
    session_id = _optional_int(
        value.get("session_id", value.get("SessionId"))
    )
    user_sid = _identity_text(
        value.get("user_sid", value.get("UserSid"))
    )
    process_alive = _optional_bool(
        value.get("process_alive", value.get("ProcessAlive"))
    )
    parent_present = _optional_bool(
        value.get(
            "parent_present_in_snapshot",
            value.get("ParentPresentInSnapshot"),
        )
    )
    shell_window_pid = _optional_int(
        value.get(
            "shell_window_process_id",
            value.get("ShellWindowProcessId"),
        )
    )
    is_current_shell = _optional_bool(
        value.get(
            "is_current_session_shell",
            value.get("IsCurrentSessionShell"),
        )
    )
    signature_status = _identity_text(
        value.get("signature_status", value.get("SignatureStatus"))
    )
    signer_subject = _identity_text(
        value.get("signer_subject", value.get("SignerSubject"))
    )
    executable_sha256 = _identity_text(
        value.get("executable_sha256", value.get("ExecutableSha256"))
    ).casefold()
    identity_query_status = _identity_text(
        value.get("identity_query_status", value.get("IdentityQueryStatus"))
    ).casefold()
    snapshot_captured_at_utc = _creation_time(
        value.get(
            "snapshot_captured_at_utc",
            value.get("SnapshotCapturedAtUtc"),
        )
    )
    return {
        "pid": pid,
        "parent_pid": parent_pid,
        "executable_name": executable_name,
        "executable_path": executable_path,
        "creation_time_utc": creation_time,
        "session_id": session_id,
        "user_sid": user_sid,
        "process_alive": process_alive,
        "parent_present_in_snapshot": parent_present,
        "shell_window_process_id": shell_window_pid,
        "is_current_session_shell": is_current_shell,
        "signature_status": signature_status,
        "signer_subject": signer_subject,
        "executable_sha256": executable_sha256,
        "identity_query_status": identity_query_status,
        "snapshot_captured_at_utc": snapshot_captured_at_utc,
        "command_classification": (
            "node_hosted_codex_cli" if node_hosts_codex else "not_codex_launcher"
        ),
    }


def _capture_windows_process_snapshot(
    start_pid: int,
) -> dict[int, dict[str, Any]]:
    """Capture the relevant chain from one Windows process snapshot."""

    if os.name != "nt":
        raise ProcessAncestryError("WINDOWS_PROCESS_ANCESTRY_REQUIRED")
    script = r"""
$ErrorActionPreference = 'Stop'
$startProcessId = __START_PID__
Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public static class R5GSnapshotNative { [DllImport("user32.dll")] public static extern IntPtr GetShellWindow(); [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId); }'
$snapshotTime = [DateTime]::UtcNow.ToString('o')
$all = @(Get-CimInstance Win32_Process -ErrorAction Stop)
$byPid = @{}
foreach ($item in $all) {
    $byPid[[int]$item.ProcessId] = $item
}
$window = [R5GSnapshotNative]::GetShellWindow()
[uint32]$shellPid = 0
if ($window -ne [IntPtr]::Zero) {
    [void][R5GSnapshotNative]::GetWindowThreadProcessId(
        $window, [ref]$shellPid)
}
$rows = @()
$seen = @{}
$current = $startProcessId
while ($current -gt 0 -and $byPid.ContainsKey([int]$current)) {
    if ($seen.ContainsKey([int]$current)) { break }
    $seen[[int]$current] = $true
    $p = $byPid[[int]$current]
    $ownerSid = ''
    try {
        $owner = Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid `
            -ErrorAction Stop
        if ($owner.ReturnValue -eq 0) { $ownerSid = [string]$owner.Sid }
    } catch {}
    $alive = $false
    $liveCreation = ''
    try {
        $live = Get-Process -Id ([int]$p.ProcessId) -ErrorAction Stop
        $alive = $true
        $liveCreation = $live.StartTime.ToUniversalTime().ToString('o')
    } catch {}
    $signatureStatus = ''
    $signerSubject = ''
    $executableSha256 = ''
    if ($p.Name -ieq 'explorer.exe' -and $p.ExecutablePath) {
        try {
            $signature = Get-AuthenticodeSignature -LiteralPath $p.ExecutablePath `
                -ErrorAction Stop
            $signatureStatus = $signature.Status.ToString()
            if ($signature.SignerCertificate) {
                $signerSubject = $signature.SignerCertificate.Subject
            }
        } catch {}
        try {
            $executableSha256 = (Get-FileHash -Algorithm SHA256 `
                -LiteralPath $p.ExecutablePath -ErrorAction Stop).Hash.ToLowerInvariant()
        } catch {}
    }
    $parentPresent = (
        [int]$p.ParentProcessId -eq 0 -or
        $byPid.ContainsKey([int]$p.ParentProcessId)
    )
    $isExplorer = $p.Name -ieq 'explorer.exe'
    $identityStatus = if (-not $isExplorer) {
        'captured'
    } elseif (
        $alive -and $ownerSid -and $shellPid -gt 0 -and
        $signatureStatus -and $signerSubject -and $executableSha256
    ) {
        'complete'
    } else {
        'incomplete'
    }
    $rows += [ordered]@{
        ProcessId = [int]$p.ProcessId
        ParentProcessId = [int]$p.ParentProcessId
        Name = [string]$p.Name
        ExecutablePath = [string]$p.ExecutablePath
        CommandLine = [string]$p.CommandLine
        CreationTimeUtc = if ($p.CreationDate) {
            $p.CreationDate.ToUniversalTime().ToString('o')
        } else { $liveCreation }
        SessionId = [int]$p.SessionId
        UserSid = $ownerSid
        ProcessAlive = $alive
        ParentPresentInSnapshot = [bool]$parentPresent
        ShellWindowProcessId = [int]$shellPid
        IsCurrentSessionShell = [bool](
            [int]$p.ProcessId -eq [int]$shellPid -and $shellPid -gt 0)
        SignatureStatus = $signatureStatus
        SignerSubject = $signerSubject
        ExecutableSha256 = $executableSha256
        IdentityQueryStatus = $identityStatus
        SnapshotCapturedAtUtc = $snapshotTime
    }
    if ([int]$p.ParentProcessId -eq 0) { break }
    $current = [int]$p.ParentProcessId
}
[ordered]@{
    SnapshotCapturedAtUtc = $snapshotTime
    StartPid = $startProcessId
    Records = @($rows)
} | ConvertTo-Json -Depth 6 -Compress
""".replace("__START_PID__", str(int(start_pid)))
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        raise ProcessAncestryError("PROCESS_ANCESTRY_METADATA_INACCESSIBLE")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ProcessAncestryError(
            "PROCESS_ANCESTRY_QUERY_INVALID_JSON"
        ) from exc
    if not isinstance(payload, dict):
        raise ProcessAncestryError("PROCESS_ANCESTRY_QUERY_INVALID_JSON")
    records = payload.get("Records", [])
    if isinstance(records, dict):
        records = [records]
    if not isinstance(records, list):
        raise ProcessAncestryError("PROCESS_ANCESTRY_QUERY_INVALID_JSON")
    captured: dict[int, dict[str, Any]] = {}
    for row in records:
        if not isinstance(row, dict):
            raise ProcessAncestryError("PROCESS_ANCESTRY_QUERY_INVALID_JSON")
        try:
            captured[int(row["ProcessId"])] = row
        except (KeyError, TypeError, ValueError) as exc:
            raise ProcessAncestryError(
                "PROCESS_ANCESTRY_QUERY_INVALID_JSON"
            ) from exc
    return captured


def windows_process_provider(pid: int) -> dict[str, Any] | None:
    """Capture one identity from a single fail-closed Windows snapshot."""

    return _capture_windows_process_snapshot(int(pid)).get(int(pid))


def _snapshot_provider(start_pid: int) -> ProcessProvider:
    captured = _capture_windows_process_snapshot(start_pid)

    def provider(pid: int) -> dict[str, Any] | None:
        return captured.get(int(pid))

    return provider


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
    """Legacy PID-zero traversal retained for immutable regression proof."""

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


def _trusted_explorer_anchor(
    row: dict[str, Any],
    runner: dict[str, Any],
    rows: list[dict[str, Any]],
    *,
    explorer_path: str,
    require_parent_absence: bool = True,
) -> dict[str, Any]:
    failures: list[str] = []
    if row.get("executable_name") != TRUSTED_EXPLORER_EXECUTABLE:
        failures.append("exact_executable_name")
    if _canonical_windows_path(row.get("executable_path")) != (
        _canonical_windows_path(explorer_path)
    ):
        failures.append("canonical_executable_path")
    if row.get("process_alive") is not True:
        failures.append("process_alive")
    if not row.get("creation_time_utc"):
        failures.append("creation_time")
    if row.get("session_id") is None or runner.get("session_id") is None:
        failures.append("session_identity")
    elif row["session_id"] != runner["session_id"]:
        failures.append("same_session")
    anchor_sid = str(row.get("user_sid", "")).casefold()
    runner_sid = str(runner.get("user_sid", "")).casefold()
    if not anchor_sid or not runner_sid:
        failures.append("user_identity")
    elif anchor_sid != runner_sid:
        failures.append("same_user")
    if row.get("shell_window_process_id") != row.get("pid"):
        failures.append("shell_window_process_id")
    if row.get("is_current_session_shell") is not True:
        failures.append("current_session_shell_identity")
    if str(row.get("signature_status", "")).casefold() != "valid":
        failures.append("authenticode_signature")
    signer = str(row.get("signer_subject", "")).casefold()
    if "microsoft" not in signer:
        failures.append("microsoft_signer_identity")
    executable_sha256 = str(row.get("executable_sha256", "")).casefold()
    if re.fullmatch(r"[0-9a-f]{64}", executable_sha256) is None:
        failures.append("executable_sha256")
    if row.get("identity_query_status") != "complete":
        failures.append("identity_query_status")
    if not row.get("snapshot_captured_at_utc"):
        failures.append("snapshot_timestamp")
    if require_parent_absence:
        if row.get("parent_present_in_snapshot") is not False:
            failures.append("parent_absence_not_proven_in_snapshot")
    if classify_process(row) == "prohibited_codex_ancestor":
        failures.append("anchor_classified_as_codex")
    if nested_codex_ancestor(rows) is not None:
        raise ProcessAncestryError("PROVEN_CODEX_ANCESTOR", records=rows)
    if failures:
        raise ProcessAncestryError(
            "TRUSTED_SHELL_ANCHOR_IDENTITY_FAILED",
            detail=",".join(failures),
            records=rows,
        )
    return {
        "process_class": "trusted_windows_explorer_shell",
        "pid": row["pid"],
        "parent_pid": row["parent_pid"],
        "executable_name": row["executable_name"],
        "executable_path": row["executable_path"],
        "expected_executable_path": explorer_path,
        "creation_time_utc": row["creation_time_utc"],
        "session_id": row["session_id"],
        "user_sid": row["user_sid"],
        "shell_window_process_id": row["shell_window_process_id"],
        "signature_status": row["signature_status"],
        "signer_subject": row["signer_subject"],
        "executable_sha256": row["executable_sha256"],
        "snapshot_captured_at_utc": row["snapshot_captured_at_utc"],
        "parent_absent_from_snapshot": require_parent_absence,
        "identity_verified": True,
    }


def _walk_to_supported_completion(
    start_pid: int,
    provider: ProcessProvider,
    *,
    maximum_depth: int = 64,
    explorer_path: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[int] = set()
    current = int(start_pid)
    pending: dict[str, Any] | None = None
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
            raw = pending if pending is not None else provider(current)
            pending = None
        except ProcessAncestryError as exc:
            if not exc.records:
                exc.records = list(rows)
            raise
        if raw is None:
            code = (
                "ANCESTRY_PARENT_MISSING_BEFORE_TRUST_ANCHOR"
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
                "ANCESTRY_PID_INCONSISTENT", records=rows
            )
        if rows and created > _parsed_creation_time(rows[-1]):
            raise ProcessAncestryError(
                "ANCESTRY_CREATION_TIME_INCONSISTENT",
                records=[*rows, row],
            )
        rows.append(row)
        parent = row["parent_pid"]
        if parent == 0:
            if row["executable_name"] == TRUSTED_EXPLORER_EXECUTABLE:
                anchor = _trusted_explorer_anchor(
                    row,
                    rows[0],
                    rows,
                    explorer_path=explorer_path,
                    require_parent_absence=False,
                )
                return rows, {
                    "completion_mode": "verified_interactive_shell_anchor",
                    "completion_classification": (
                        "ANCESTRY_VERIFIED_TO_TRUSTED_WINDOWS_SHELL_ANCHOR"
                    ),
                    "termination_reason": (
                        "verified_explorer_recorded_parent_pid_zero"
                    ),
                    "trusted_shell_anchor": anchor,
                }
            return rows, {
                "completion_mode": "operating_system_root",
                "completion_classification": "ANCESTRY_VERIFIED_TO_OS_ROOT",
                "termination_reason": "parent_pid_zero",
                "trusted_shell_anchor": None,
            }
        if parent == current:
            raise ProcessAncestryError(
                "PROCESS_ANCESTRY_CYCLE_DETECTED", records=rows
            )
        try:
            parent_raw = provider(parent)
        except ProcessAncestryError as exc:
            if not exc.records:
                exc.records = list(rows)
            raise
        if parent_raw is None:
            if row["executable_name"] != TRUSTED_EXPLORER_EXECUTABLE:
                raise ProcessAncestryError(
                    "ANCESTRY_PARENT_MISSING_BEFORE_TRUST_ANCHOR",
                    records=rows,
                )
            if row.get("parent_present_in_snapshot") is True:
                raise ProcessAncestryError(
                    "ANCESTRY_PID_INCONSISTENT",
                    detail="anchor parent marked present but unavailable",
                    records=rows,
                )
            anchor = _trusted_explorer_anchor(
                row, rows[0], rows, explorer_path=explorer_path
            )
            return rows, {
                "completion_mode": "verified_interactive_shell_anchor",
                "completion_classification": (
                    "ANCESTRY_VERIFIED_TO_TRUSTED_WINDOWS_SHELL_ANCHOR"
                ),
                "termination_reason": (
                    "verified_explorer_parent_absent_from_process_snapshot"
                ),
                "trusted_shell_anchor": anchor,
            }
        pending = parent_raw
        current = parent
    raise ProcessAncestryError(
        "ANCESTRY_PARENT_MISSING_BEFORE_TRUST_ANCHOR", records=rows
    )


def _terminal_classification(code: str) -> str:
    mapping = {
        "NESTED_CODEX_ANCESTOR_DETECTED": "PROVEN_CODEX_ANCESTOR",
        "PROVEN_CODEX_ANCESTOR": "PROVEN_CODEX_ANCESTOR",
        "PROCESS_ANCESTRY_PID_MISMATCH": "ANCESTRY_PID_INCONSISTENT",
        "PROCESS_ANCESTRY_PID_REUSE_OR_SNAPSHOT_INCONSISTENT": (
            "ANCESTRY_CREATION_TIME_INCONSISTENT"
        ),
        "PROCESS_ANCESTRY_INCOMPLETE": (
            "ANCESTRY_PARENT_MISSING_BEFORE_TRUST_ANCHOR"
        ),
        "PROCESS_ANCESTRY_CLASSIFICATION_AMBIGUOUS": (
            "ANCESTRY_CLASSIFICATION_AMBIGUOUS"
        ),
    }
    return mapping.get(code, code)


def _receipt(
    runner_pid: int,
    rows: list[dict[str, Any]],
    *,
    evidence_complete: bool,
    hard_stop_code: str,
    completion: dict[str, Any] | None = None,
    terminal_classification: str = "",
) -> dict[str, Any]:
    trigger = nested_codex_ancestor(rows)
    classified = [
        {**row, "process_class": classify_process(row)} for row in rows
    ]
    completion = completion or {}
    classification = terminal_classification or str(
        completion.get("completion_classification", "")
    )
    return {
        "schema_version": "3.0.0",
        "verification_semantics": "trusted_windows_shell_anchor_v1",
        "runner_pid": int(runner_pid),
        "evidence_complete": evidence_complete,
        "ordinary_powershell_ancestor_verified": (
            evidence_complete and not hard_stop_code
        ),
        "nested_codex_ancestor_detected": trigger is not None,
        "actual_codex_ancestor": trigger is not None,
        "ancestor_count": len(rows),
        "ancestors": classified,
        "trigger_process": trigger,
        "completion_mode": completion.get("completion_mode", ""),
        "completion_classification": classification,
        "termination_reason": completion.get("termination_reason", ""),
        "trusted_shell_anchor": completion.get("trusted_shell_anchor"),
        "hard_stop_code": hard_stop_code,
    }


def verify_standalone_powershell(
    runner_pid: int,
    provider: ProcessProvider = windows_process_provider,
    *,
    explorer_path: str | None = None,
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    completion: dict[str, Any] | None = None
    try:
        active_provider = (
            _snapshot_provider(runner_pid)
            if provider is windows_process_provider
            else provider
        )
        rows, completion = _walk_to_supported_completion(
            runner_pid,
            active_provider,
            explorer_path=explorer_path or expected_explorer_path(),
        )
    except ProcessAncestryError as exc:
        trigger = nested_codex_ancestor(exc.records)
        if trigger is not None:
            receipt = _receipt(
                runner_pid,
                exc.records,
                evidence_complete=False,
                hard_stop_code="NESTED_CODEX_ANCESTOR_DETECTED",
                terminal_classification="PROVEN_CODEX_ANCESTOR",
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
            terminal_classification=_terminal_classification(exc.code),
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
            completion=completion,
            terminal_classification=error.code,
        )
        raise error
    match = nested_codex_ancestor(rows)
    if match is not None:
        receipt = _receipt(
            runner_pid,
            rows,
            evidence_complete=True,
            hard_stop_code="NESTED_CODEX_ANCESTOR_DETECTED",
            completion=completion,
            terminal_classification="PROVEN_CODEX_ANCESTOR",
        )
        error = NestedCodexAncestorError(
            "NESTED_CODEX_ANCESTOR_DETECTED", records=rows
        )
        error.receipt = receipt  # type: ignore[attr-defined]
        raise error
    if any(classify_process(row) == "ambiguous_unknown_host" for row in rows):
        error = ProcessAncestryError(
            "ANCESTRY_CLASSIFICATION_AMBIGUOUS", records=rows
        )
        error.receipt = _receipt(  # type: ignore[attr-defined]
            runner_pid,
            rows,
            evidence_complete=True,
            hard_stop_code=error.code,
            completion=completion,
            terminal_classification=error.code,
        )
        raise error
    return _receipt(
        runner_pid,
        rows,
        evidence_complete=True,
        hard_stop_code="",
        completion=completion,
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
