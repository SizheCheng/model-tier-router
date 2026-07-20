from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any


def sanitize_process_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sanitized = []
    for row in rows:
        sanitized.append(
            {
                "name": str(row.get("name", "")),
                "pid": int(row.get("pid", 0)),
                "start_time": row.get("start_time"),
                "role": row.get("role", "other_observed_codex_process"),
                "repository_paths_exposed": sorted(
                    str(value) for value in row.get("repository_paths_exposed", [])
                ),
            }
        )
    return sanitized


def capture_process_metadata(
    known_paths: dict[str, str],
    target_ids: set[str],
) -> dict[str, Any]:
    path_lines = ";".join(
        f"'{key}'='{value.replace(chr(39), chr(39) * 2)}'"
        for key, value in known_paths.items()
    )
    target_array = ",".join(f"'{value}'" for value in sorted(target_ids))
    script = rf"""
$ErrorActionPreference='Stop'
$known=[ordered]@{{{path_lines}}}
$targetIds=@({target_array})
$all=@(Get-CimInstance Win32_Process)
$byPid=@{{}}
foreach($p in $all){{$byPid[[int]$p.ProcessId]=$p}}
$ancestors=@()
$cursor=[int]$PID
while($cursor -ne 0 -and $byPid.ContainsKey($cursor) -and $ancestors -notcontains $cursor){{
  $ancestors += $cursor
  $cursor=[int]$byPid[$cursor].ParentProcessId
}}
$rows=@()
foreach($p in @($all | Where-Object {{$_.Name -match '(?i)codex'}})){{
  $matches=@()
  $cmd=[string]$p.CommandLine
  foreach($entry in $known.GetEnumerator()){{
    if($cmd.IndexOf($entry.Value,[System.StringComparison]::OrdinalIgnoreCase) -ge 0){{$matches += $entry.Key}}
  }}
  $rows += [pscustomobject]@{{
    name=$p.Name
    pid=[int]$p.ProcessId
    start_time=if($p.CreationDate){{$p.CreationDate.ToUniversalTime().ToString('o')}}else{{$null}}
    role=if($ancestors -contains [int]$p.ProcessId){{'current_outer_session_ancestor'}}else{{'other_observed_codex_process'}}
    repository_paths_exposed=$matches
  }}
}}
$other=@($rows | Where-Object role -eq 'other_observed_codex_process')
$overlap=$false
foreach($row in $other){{foreach($id in $targetIds){{if($row.repository_paths_exposed -contains $id){{$overlap=$true}}}}}}
[pscustomobject]@{{
  captured_at=(Get-Date).ToUniversalTime().ToString('o')
  observable_codex_process_count=$rows.Count
  other_observable_codex_process_count=$other.Count
  target_overlap=$overlap
  sanitized_processes=$rows
}} | ConvertTo-Json -Depth 8 -Compress
"""
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-Command", script],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        return {
            "captured_at": None,
            "observable_codex_process_count": None,
            "other_observable_codex_process_count": None,
            "target_overlap": None,
            "capture_status": "UNAVAILABLE",
        }
    value = json.loads(completed.stdout)
    value["sanitized_processes"] = sanitize_process_rows(
        value.get("sanitized_processes", [])
    )
    value["capture_status"] = "CAPTURED"
    return value


def measurement_quality(external_sessions_declared_active: bool) -> str:
    if external_sessions_declared_active:
        return "CONTAMINATED_BY_CONCURRENT_CODEX_SESSIONS"
    return "OBSERVED_WITHOUT_DECLARED_EXTERNAL_SESSION_CONTAMINATION"
