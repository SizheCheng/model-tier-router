from __future__ import annotations

import argparse
import base64
import binascii
import csv
import hashlib
import json
import ntpath
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path, PureWindowsPath
from typing import Any, Callable

from .bounded_writer import (
    POLICY_FILENAME as BOUNDED_WRITE_POLICY_FILENAME,
    RECEIPT_DIRECTORY as BOUNDED_WRITE_RECEIPT_DIRECTORY,
    validate_writer_receipts,
)
from .codex_runner import resolve_codex_executable, run_codex
from .host_materialization import (
    HostMaterializationError,
    alias_map as host_alias_map,
    lane_contract as host_lane_contract,
    load_lane_policy,
    materialize_transaction,
    validate_model_phase,
)
from .config import ContractError, canonical_json_bytes, harness_root, is_contained, load_json, same_path
from .git_worktrees import (
    GitContractError, changed_paths, commit_exact_paths, create_worktree,
    delete_unadvanced_branch, diff_bytes, fast_forward, remove_worktree,
    repository_state, require_clean_baseline,
)
from .process_ancestry import (
    NestedCodexAncestorError, ProcessAncestryError, ProcessProvider,
    verify_standalone_powershell, windows_process_provider,
)
from .r2_contract import (
    PayloadValidationError, classify_model_reported_blocker,
    validate_child_transport, validate_launch_payloads,
)
from .receipts import write_json
from .router_adapter import assess_live
from .runtime_contract import (
    RUNTIME_ROUTE_ID, ProcessAccounting, assert_control_action_allowed,
    load_runtime_contract, next_escalation_profile, validate_closeout,
    validate_contract_paths,
)
from .validation import (
    freeze_validator_plan, paths_allowed, risk_allows_auto_merge, run_plan,
    summarize_validation,
)
from .writable_smoke import (
    Launcher, build_external_codex_command, run_writable_smoke,
    validate_external_command_shape,
)


FORBIDDEN_ACTION_RE = re.compile(
    r"\bgit\s+(commit|merge|rebase|reset|clean|push|remote|tag|stash)\b"
    r"|\b(publish|deploy|release|customer\s+delivery)\b", re.I,
)
CREDENTIAL_ACCESS_RE = re.compile(
    r"auth\.json|\.ssh|credential|cookie|token|secret|Get-ChildItem\s+Env:|"
    r"\$env:(?:CODEX|OPENAI|GITHUB|GH)_", re.I,
)
REMOTE_OPERATION_RE = re.compile(r"\bgit(?:\.exe)?\s+(push|fetch|pull|remote)\b", re.I)
WINDOWS_PATH_RE = re.compile(
    r'''(?P<double>"(?:[a-z]:[\\/]|\\\\[^\\/\s"]+[\\/])[^"]+")'''
    r'''|(?P<single>'(?:[a-z]:[\\/]|\\\\[^\\/\s']+[\\/])[^']+')'''
    r'''|(?P<bare>(?:\b[a-z]:[\\/]|(?<![\w.\\])\\\\[^\\/\s"']+[\\/])'''
    r'''[^\s"'<>|,;(){}\[\]]+)''',
    re.I,
)
POWERSHELL_PATH_ARGUMENT_RE = re.compile(
    r'''(?ix)(?<!\S)-(?:literal)?path\s+'''
    r'''(?P<value>"[^"\r\n]*"|'[^'\r\n]*'|[^\s|;&]+)''',
)
CONFIDENTIAL_CONTENT_RE = re.compile(
    rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
    rb"|\bAKIA[0-9A-Z]{16}\b|\bsk-[A-Za-z0-9_-]{20,}\b"
    rb"|\bBearer\s+[A-Za-z0-9._-]{20,}",
    re.I,
)
BOUNDED_WRITER_RELATIVE = ".mtr-dogfood-r4/bounded-writer.py"
BOUNDED_WRITE_COMMAND_RE = re.compile(
    r"(?i)^python(?:\.exe)?\s+-B\s+"
    r"\.mtr-dogfood-r4[\\/]bounded-writer\.py\s+"
    r"--slot\s+(?P<alias>[a-z][a-z0-9_]{0,63})\s+"
    r"--content-base64\s+(?P<content>[A-Za-z0-9+/]*={0,2})$"
)
BOUNDED_WRITER_MENTION_RE = re.compile(
    r"(?i)\bbounded-writer\.py\b"
)
SHELL_WRITE_OPERATION_RE = re.compile(
    r"(?ix)"
    r"\b(?:set-content|add-content|out-file|writealltext|writeallbytes|"
    r"write_text|write_bytes|new-item|copy-item|move-item|remove-item|"
    r"mkdir|makedirs|touch|unlink|rmtree|copyfile|rename|replace|openwrite|"
    r"apply_patch|file_change|"
    r"tee|truncate|git\s+(?:add|apply|checkout|switch|branch|restore|mv|rm|init))\b"
    r"|(?:^|[^\w])open\s*\(|\.write\s*\(|(?<![<>=])>{1,2}(?![=])"
)


def default_launcher(**kwargs: Any) -> dict[str, Any]:
    return run_codex(**kwargs)


def _git(repository: str | Path, *arguments: str, check: bool = True) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments], text=True,
        encoding="utf-8", errors="replace", capture_output=True, check=False,
    )
    if check and completed.returncode != 0:
        raise GitContractError(completed.stderr.strip() or completed.stdout.strip())
    return completed.stdout.strip()


def _normalize_infrastructure(value: Any) -> str | None:
    mapping = {
        "SHELL_COMMAND_NOT_FOUND": "MISSING_COMMAND",
        "DEPENDENCY_OR_ENVIRONMENT_FAILURE": "ENVIRONMENT_FAILURE",
        "VALIDATOR_DEFECT": "SCHEMA_REJECTION",
        "MODEL_OUTPUT_SCHEMA_FAILURE": "SCHEMA_REJECTION",
    }
    return None if value is None else mapping.get(str(value), str(value))


def _unstarted_execution(failure_class: str) -> dict[str, Any]:
    return {
        "exit_code": None,
        "child_process_started": False,
        "model_execution_observed": False,
        "model_execution_completed": False,
        "host_policy_failure_count": 0,
        "rate_limit_event_count": 0,
        "model_unavailable_event_count": 0,
        "authentication_event_count": 0,
        "output_schema_error_count": 0,
        "infrastructure_failure_class": failure_class,
        "input_tokens": None,
        "cached_input_tokens": None,
        "output_tokens": None,
        "reasoning_output_tokens": None,
    }


def classify_external_attempt(
    execution: dict[str, Any], claim: dict[str, Any], *, output_valid: bool,
    schema_unchanged: bool, changed: list[str], changed_paths_allowed: bool,
    automated_acceptance: bool, forbidden_action: bool,
    confidentiality_ok: bool = True,
    malformed_bounded_writer_invocation: bool = False,
) -> str:
    claim_failure = (
        classify_model_reported_blocker(claim) if output_valid else None
    )
    infrastructure = _normalize_infrastructure(execution.get("infrastructure_failure_class"))
    if int(execution.get("host_policy_failure_count") or 0) > 0:
        if infrastructure == "HOST_POLICY_REJECTED_EXTERNAL_CODE_TRANSFER":
            return infrastructure
        return "HOST_POLICY_REJECTED_CHILD_FILESYSTEM_ACCESS"
    if infrastructure:
        return infrastructure
    if not output_valid or not schema_unchanged:
        return "SCHEMA_REJECTION"
    if forbidden_action:
        return "UNAUTHORIZED_ACTION"
    if malformed_bounded_writer_invocation:
        return "MALFORMED_BOUNDED_WRITER_INVOCATION"
    if changed and not changed_paths_allowed:
        return "UNAUTHORIZED_ACTION"
    if not confidentiality_ok:
        return "CONFIDENTIALITY_BOUNDARY"
    if not execution.get("model_execution_observed"):
        return "ENVIRONMENT_FAILURE"
    if claim_failure:
        return claim_failure
    if not execution.get("model_execution_completed"):
        return "CONTEXT_OR_REASONING_INSUFFICIENT"
    if not changed:
        return "IMPLEMENTATION_INCOMPLETE"
    if not changed_paths_allowed or not automated_acceptance:
        return "VALIDATOR_FAILURE_AFTER_ALLOWED_CHANGE"
    return ""


def _confidentiality_scan(
    worktree: Path, repository_id: str, paths: list[str]
) -> bool:
    if repository_id != "qwen-redaction-standalone":
        return True
    for relative in paths:
        path = worktree / relative
        if path.suffix.casefold() not in {".py", ".txt", ".md", ".json"}:
            return False
        data = path.read_bytes()
        if len(data) > 2_000_000 or b"\x00" in data:
            return False
        if CONFIDENTIAL_CONTENT_RE.search(data):
            return False
    return True


def _strip_matching_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _split_child_command(command: str) -> tuple[str, list[str], str, bool]:
    """Separate executable identity from the text it was asked to execute."""
    try:
        tokens = shlex.split(command, posix=False)
    except ValueError:
        return "", [], command, False
    if not tokens:
        return "", [], command, False
    values = [_strip_matching_quotes(token) for token in tokens]
    stripped = command.lstrip()
    if stripped.startswith(('"', "'")):
        quote = stripped[0]
        end = stripped.find(quote, 1)
        if end < 0:
            return values[0], values[1:], command, False
        operands = stripped[end + 1 :].lstrip()
    else:
        parts = stripped.split(maxsplit=1)
        operands = parts[1] if len(parts) == 2 else ""
    return values[0], values[1:], operands, True


def _extract_windows_paths(text: str) -> list[tuple[str, int]]:
    paths: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    for match in WINDOWS_PATH_RE.finditer(text):
        raw = next(value for value in match.groups() if value is not None)
        candidate = _strip_matching_quotes(raw).rstrip(".,;:)]}")
        key = (candidate.casefold(), match.start())
        if key not in seen:
            paths.append((candidate, match.start()))
            seen.add(key)
    return paths


def _extract_powershell_path_operands(text: str) -> list[tuple[str, int]]:
    """Extract only explicit PowerShell -Path/-LiteralPath argument values."""
    paths: list[tuple[str, int]] = []
    for match in POWERSHELL_PATH_ARGUMENT_RE.finditer(text):
        raw = match.group("value")
        candidate = _strip_matching_quotes(raw)
        paths.append((candidate, match.start("value")))
    return paths


def _normalized_windows_path(path: str) -> str:
    return ntpath.normpath(path.replace("/", "\\"))


def _exact_bounded_write_paths(patterns: list[str]) -> list[str]:
    paths: list[str] = []
    for pattern in patterns:
        normalized = pattern.replace("\\", "/")
        if (
            not pattern
            or normalized != pattern
            or any(character in pattern for character in "*?[]")
            or _windows_path_kind(pattern) != "relative"
            or any(part in {"", ".", ".."} for part in PureWindowsPath(pattern).parts)
        ):
            raise ContractError("bounded write scope must enumerate canonical paths")
        paths.append(normalized)
    if not paths or len(set(paths)) != len(paths):
        raise ContractError("bounded write scope must be non-empty and unique")
    return paths


TARGET_ALIAS_BY_PATH = {
    "smoke/result.txt": "smoke_result",
    "docs.txt": "fixture_docs",
    "docs/dogfood-automation.md": "router_documentation",
    "tests/integrations/test_dogfood_automation.py": "router_integration_test",
    "tests/redaction/test_docx_package.py": "qwen_docx_hidden_elements_test",
}


def _target_aliases(paths: list[str]) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for path in _exact_bounded_write_paths(paths):
        alias = TARGET_ALIAS_BY_PATH.get(path)
        if alias is None or alias in aliases:
            raise ContractError("bounded write path has no unique immutable alias")
        aliases[alias] = path
    return aliases


def _inspect_bounded_write(
    payload: str,
    target_aliases: dict[str, str] | None,
    verified_receipts: list[dict[str, Any]] | None = None,
    command_output: str = "",
    command_completed: bool = True,
    child_exit_code: int | None = 0,
) -> dict[str, Any]:
    stripped = payload.strip()
    match = BOUNDED_WRITE_COMMAND_RE.fullmatch(stripped)
    mentioned = bool(BOUNDED_WRITER_MENTION_RE.search(stripped))
    if match is None:
        return {
            "recognized": mentioned,
            "authorized": False,
            "target_alias": None,
            "relative_path": None,
            "content_bytes": None,
            "content_sha256": None,
            "reason": "malformed_bounded_writer_command" if mentioned else None,
        }
    alias = match.group("alias")
    encoded = match.group("content")
    try:
        content = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error):
        content = b""
        canonical = False
    else:
        canonical = base64.b64encode(content).decode("ascii") == encoded
    aliases = target_aliases or {}
    path = aliases.get(alias)
    syntax_valid = bool(
        canonical
        and len(content) <= 1_000_000
        and path is not None
    )
    reason = None
    if not syntax_valid:
        if not canonical:
            reason = "invalid_content_base64"
        elif len(content) > 1_000_000:
            reason = "content_size_limit_exceeded"
        elif path is None:
            reason = "unknown_target_alias"
        else:
            reason = "malformed_bounded_writer_command"
    digest = hashlib.sha256(content).hexdigest() if canonical else None
    matching = [
        receipt for receipt in (verified_receipts or [])
        if receipt.get("target_alias") == alias
        and receipt.get("relative_path") == path
        and receipt.get("content_sha256") == digest
        and receipt.get("content_byte_count") == len(content)
    ]
    output_matches = False
    if len(matching) == 1:
        try:
            output_matches = json.loads(command_output.strip()) == matching[0]
        except (json.JSONDecodeError, TypeError):
            output_matches = False
    authorized = bool(
        syntax_valid
        and command_completed
        and child_exit_code == 0
        and len(matching) == 1
        and output_matches
    )
    if syntax_valid and not authorized:
        if not command_completed or child_exit_code != 0:
            reason = "writer_process_failed"
        elif len(matching) == 0:
            reason = "missing_or_unverified_writer_receipt"
        elif len(matching) > 1:
            reason = "duplicate_writer_receipt"
        else:
            reason = "writer_output_receipt_mismatch"
    return {
        "recognized": True,
        "authorized": authorized,
        "target_alias": alias,
        "relative_path": path,
        "content_bytes": len(content) if canonical else None,
        "content_sha256": digest,
        "receipt_verified": len(matching) == 1 and output_matches,
        "reason": reason,
    }


def _windows_path_kind(path: str) -> str:
    """Classify Windows syntax before choosing a base for resolution."""
    value = _strip_matching_quotes(path)
    if value.startswith("/") and not value.startswith("//"):
        return "posix_absolute"
    windows = value.replace("/", "\\")
    folded = windows.casefold()
    if folded.startswith("\\\\?\\unc\\"):
        return "extended_unc"
    if folded.startswith("\\\\?\\"):
        return "extended_absolute"
    if windows.startswith("\\\\"):
        return "unc"
    drive, tail = ntpath.splitdrive(windows)
    if drive:
        return "drive_absolute" if tail.startswith("\\") else "drive_relative"
    if windows.startswith("\\"):
        return "current_drive_rooted"
    normalized = _normalized_windows_path(windows)
    if normalized == ".." or normalized.startswith("..\\"):
        return "parent_relative"
    return "relative"


def _canonical_path(path: str | Path) -> str:
    return str(Path(path).resolve(strict=False))


def _resolve_windows_path_candidate(
    candidate: str, worktree: Path | None
) -> tuple[str, str, str | None, Path | None]:
    """Return kind, normalized form, cwd-resolved form, and safe local Path."""
    kind = _windows_path_kind(candidate)
    normalized = _normalized_windows_path(candidate)
    if kind in {"relative", "parent_relative"}:
        if worktree is None:
            return kind, normalized, None, None
        resolved = worktree.joinpath(*PureWindowsPath(normalized).parts).resolve(
            strict=False
        )
        return kind, normalized, str(resolved), resolved
    if kind == "drive_absolute":
        resolved = Path(normalized).resolve(strict=False)
        return kind, normalized, str(resolved), resolved
    # Rooted, drive-relative, UNC, extended, and POSIX-absolute syntax is
    # deliberately not rebound to the workspace cwd.
    return kind, normalized, None, None


def _path_access_mode(text: str, offset: int) -> str:
    context = text[max(0, offset - 160) : offset].casefold()
    markers = (
        ("delete", ("remove-item", " del ", " erase ", " rm ", "delete(")),
        ("write", ("set-content", "add-content", "out-file", "writeall", "writebytes")),
        ("create", ("new-item", "mkdir", " md ")),
        ("enumerate", ("get-childitem", "get-child-item", " dir ", " ls ")),
        ("read", ("get-content", "readall", "readbytes", "get-filehash")),
        ("metadata-only", ("test-path", "get-item", "resolve-path")),
    )
    for mode, tokens in markers:
        if any(token in context for token in tokens):
            return mode
    return "unknown"


def _shell_string(executable: str, operand_text: str) -> str | None:
    name = ntpath.basename(executable).casefold()
    if name not in {
        "pwsh", "pwsh.exe", "powershell", "powershell.exe",
        "cmd", "cmd.exe", "sh", "sh.exe", "bash", "bash.exe",
    }:
        return None
    match = re.match(r"(?is)^(?:-command|-c|/c)\s+(.+)$", operand_text)
    return _strip_matching_quotes(match.group(1)) if match else None


def _structured_shell_string(executable: str, argv: list[str]) -> str | None:
    name = ntpath.basename(executable).casefold()
    if name not in {
        "pwsh", "pwsh.exe", "powershell", "powershell.exe",
        "cmd", "cmd.exe", "sh", "sh.exe", "bash", "bash.exe",
    }:
        return None
    for index, argument in enumerate(argv):
        if argument.casefold() in {"-command", "-c", "/c"}:
            payload = argv[index + 1 :]
            return " ".join(payload) if payload else None
    return None


def _scan_child_commands(
    events_path: Path,
    forbidden_paths: list[str | Path],
    worktree: Path | None = None,
    target_aliases: dict[str, str] | None = None,
    verified_writer_receipts: list[dict[str, Any]] | None = None,
    model_read_only: bool = False,
) -> dict[str, Any]:
    result = {
        "forbidden_action_detected": False,
        "external_path_access_detected": False,
        "credential_access_detected": False,
        "remote_operation_attempted": False,
        "unparseable_command_detected": False,
        "bounded_write_violation_detected": False,
        "bounded_write_security_violation_detected": False,
        "malformed_bounded_writer_invocation_detected": False,
        "bounded_write_count": 0,
        "bounded_write_targets": [],
        "bounded_write_aliases": [],
        "model_direct_write_attempt_detected": False,
        "model_file_change_attempt_detected": False,
        "command_records": [],
    }
    if not events_path.exists():
        return result
    protected = [Path(path).resolve(strict=False) for path in forbidden_paths]
    for event_index, line in enumerate(
        events_path.read_text(encoding="utf-8", errors="replace").splitlines()
    ):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        item = event.get("item")
        if not isinstance(item, dict):
            continue
        item_type = str(item.get("type", "")).casefold()
        if item_type in {"file_change", "apply_patch"}:
            result["model_file_change_attempt_detected"] = True
            result["bounded_write_violation_detected"] = True
            result["bounded_write_security_violation_detected"] = True
        display_command = item.get("command")
        structured_executable = item.get("executable")
        structured_argv = item.get("argv")
        structured = bool(
            isinstance(structured_executable, str)
            and isinstance(structured_argv, list)
            and all(isinstance(argument, str) for argument in structured_argv)
        )
        if structured:
            executable = structured_executable
            argv = list(structured_argv)
            operand_text = subprocess.list2cmdline(argv)
            parsed = True
            command_source = "structured_event"
            inspection_text = subprocess.list2cmdline([executable, *argv])
            command = (
                display_command
                if isinstance(display_command, str)
                else inspection_text
            )
            shell = _structured_shell_string(executable, argv)
        elif isinstance(display_command, str):
            command = display_command
            executable, argv, operand_text, parsed = _split_child_command(command)
            command_source = "display_command_fallback"
            inspection_text = command
            shell = _shell_string(executable, operand_text)
        else:
            continue
        executable_name = ntpath.basename(executable).casefold()
        inspection_payload = shell if shell is not None else operand_text
        git_action = (
            argv[0].casefold()
            if executable_name in {"git", "git.exe"} and argv
            else ""
        )
        if FORBIDDEN_ACTION_RE.search(inspection_text) or git_action in {
            "commit", "merge", "rebase", "reset", "clean", "push", "remote",
            "tag", "stash",
        }:
            result["forbidden_action_detected"] = True
        if REMOTE_OPERATION_RE.search(inspection_text) or git_action in {
            "push", "fetch", "pull", "remote",
        }:
            result["remote_operation_attempted"] = True
        if CREDENTIAL_ACCESS_RE.search(inspection_payload):
            result["credential_access_detected"] = True
        if not parsed:
            result["unparseable_command_detected"] = True
            result["external_path_access_detected"] = True
        if re.search(r"(?<![\w.])\.\.([\\/]|$)", inspection_payload):
            result["external_path_access_detected"] = True
        event_cwd = item.get("cwd")
        event_cwd_verified = None
        if isinstance(event_cwd, str):
            event_cwd_verified = bool(
                worktree is not None and same_path(event_cwd, worktree)
            )
            if not event_cwd_verified:
                result["unparseable_command_detected"] = True
                result["external_path_access_detected"] = True

        executable_paths = []
        if re.match(r"(?i)^(?:[a-z]:[\\/]|\\\\)", executable):
            executable_paths.append({
                "raw": executable,
                "normalized": _normalized_windows_path(executable),
                "canonical": _canonical_path(executable),
                "access_mode": "execute",
            })
        path_input = shell if shell is not None else operand_text
        extracted = [
            (candidate, offset, "powershell_path_argument")
            for candidate, offset in _extract_powershell_path_operands(path_input)
        ]
        extracted.extend(
            (candidate, offset, "absolute_path_fallback")
            for candidate, offset in _extract_windows_paths(path_input)
        )
        candidates = []
        seen_candidates: set[tuple[str, int]] = set()
        for candidate, offset, source in extracted:
            key = (candidate.casefold(), offset)
            if key in seen_candidates:
                continue
            seen_candidates.add(key)
            path_kind, normalized, cwd_resolved, canonical_path = (
                _resolve_windows_path_candidate(candidate, worktree)
            )
            inside_worktree = bool(
                worktree is not None
                and canonical_path is not None
                and is_contained(worktree, canonical_path)
            )
            protected_root = next(
                (
                    str(path)
                    for path in protected
                    if canonical_path is not None
                    and is_contained(path, canonical_path)
                ),
                None,
            )
            candidates.append({
                "raw": candidate,
                "normalized": normalized,
                "path_kind": path_kind,
                "cwd_resolved": cwd_resolved,
                "canonical": cwd_resolved if cwd_resolved is not None else normalized,
                "access_mode": _path_access_mode(path_input, offset),
                "extraction_source": source,
                "inside_worktree": inside_worktree,
                "protected_root": protected_root,
            })
            if worktree is None or not inside_worktree:
                result["external_path_access_detected"] = True

        shell_name = executable_name in {
            "pwsh", "pwsh.exe", "powershell", "powershell.exe",
            "cmd", "cmd.exe", "sh", "sh.exe", "bash", "bash.exe",
        }
        if shell_name and shell is None:
            result["unparseable_command_detected"] = True
            result["external_path_access_detected"] = True
        command_completed = event.get("type") == "item.completed"
        child_exit_code = item.get("exit_code")
        command_output = item.get("aggregated_output", "")
        writer_inspection_input = path_input
        if (
            shell is None
            and executable_name in {"python", "python.exe"}
        ):
            writer_inspection_input = f"python {operand_text}"
        write_transport = _inspect_bounded_write(
            writer_inspection_input,
            target_aliases,
            verified_writer_receipts,
            command_output if isinstance(command_output, str) else "",
            command_completed,
            child_exit_code if isinstance(child_exit_code, int) else None,
        )
        direct_write = bool(
            SHELL_WRITE_OPERATION_RE.search(inspection_text)
            and not write_transport["recognized"]
        )
        write_capable = bool(write_transport["recognized"] or direct_write)
        if model_read_only and command_completed and write_capable:
            result["model_direct_write_attempt_detected"] = True
            result["bounded_write_violation_detected"] = True
            result["bounded_write_security_violation_detected"] = True
        elif command_completed and write_capable and not write_transport["authorized"]:
            result["bounded_write_violation_detected"] = True
            reason = write_transport.get("reason")
            if direct_write or reason in {
                "unknown_target_alias",
                "duplicate_writer_receipt",
                "writer_output_receipt_mismatch",
            }:
                result["bounded_write_security_violation_detected"] = True
            else:
                result["malformed_bounded_writer_invocation_detected"] = True
        if not model_read_only and command_completed and write_transport["authorized"]:
            result["bounded_write_count"] += 1
            result["bounded_write_aliases"].append(write_transport["target_alias"])
            result["bounded_write_targets"].append(write_transport["relative_path"])
        result["command_records"].append({
            "event_index": event_index,
            "event_type": event.get("type"),
            "item_type": item.get("type"),
            "raw_command": command,
            "command_source": command_source,
            "executable": executable,
            "argv": argv,
            "shell_string": shell,
            "event_cwd": event_cwd if isinstance(event_cwd, str) else None,
            "event_cwd_verified": event_cwd_verified,
            "cwd": (
                str(worktree.resolve(strict=False))
                if worktree is not None
                else None
            ),
            "parse_succeeded": parsed and not (shell_name and shell is None),
            "executable_paths": executable_paths,
            "path_candidates": candidates,
            "write_capable": write_capable,
            "bounded_write_transport": write_transport,
        })
    if not model_read_only and len(verified_writer_receipts or []) != result["bounded_write_count"]:
        result["bounded_write_violation_detected"] = True
        result["bounded_write_security_violation_detected"] = True
    return result


def _file_hashes(directory: Path) -> dict[str, str]:
    return {
        path.relative_to(directory).as_posix(): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


def _sanitized_claim_summary(claim: dict[str, Any]) -> dict[str, Any]:
    summary = str(claim.get("summary", ""))
    tests = claim.get("tests_run", [])
    return {
        "status": claim.get("status"),
        "changed_paths": claim.get("changed_paths", []),
        "prohibited_action_attempted": claim.get("prohibited_action_attempted"),
        "summary_sha256": hashlib.sha256(summary.encode("utf-8")).hexdigest(),
        "test_statuses": [
            item.get("status")
            for item in tests
            if isinstance(item, dict)
        ],
        "notes_count": len(claim.get("notes", [])),
        "proposed_aliases": [
            item.get("target_alias")
            for item in claim.get("proposed_files", [])
            if isinstance(item, dict)
        ],
        "validation_expectation_count": len(claim.get("validation_expectations", [])),
    }


def _render_plan(plan: dict[str, Any], worktree: Path, run_temp: Path) -> dict[str, Any]:
    encoded = json.dumps(plan).replace("{worktree}", str(worktree))
    return json.loads(encoded.replace("{run_temp}", str(run_temp)))


def _task_payload(case: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "schema_version", "case_id", "repository", "baseline_head", "title",
        "task_text", "changed_path_patterns", "risk", "validator_plan_digest",
    )
    return {key: case[key] for key in keys}


def _child_prompt(case: dict[str, Any], worktree: Path) -> str:
    validators = case["validator_plan"]
    allowed_write_paths = _exact_bounded_write_paths(
        case["changed_path_patterns"]
    )
    target_aliases = _target_aliases(allowed_write_paths)
    return f"""Propose one bounded task result from this read-only assigned worktree:
{worktree}

Task: {case['title']}
{case['task_text']}

Parent-controlled target aliases: {json.dumps(sorted(target_aliases))}
Frozen parent-run validator instructions: {json.dumps(validators)}

The model phase is read-only. Do not invoke file_change, apply_patch, the bounded
writer, PowerShell or Python writes, shell redirection, directory creation,
deletion, moves, or any Git mutation. Return proposed UTF-8 file contents only
through the structured final result. Refer to targets only by the exact aliases
above. Do not put a filesystem path or changed_paths field in the final result.
For every proposed file, declare its exact UTF-8 byte count, SHA-256, media type,
encoding, representation, and line endings. Declare the parent validations that
must pass. Incomplete, malformed, truncated, missing, extra, or oversized output
will fail closed and will materialize no file. The parent alone validates all
payloads and then invokes the trusted writer transactionally.

Read only inside the assigned worktree. Use only repository files and
synthetic fixtures already present there. Do not access credentials, user
memory, another repository, or any path outside the worktree. Do not use
network tools, web search, browser tools, apps, plugins, or subagents. Do not
run git commit, merge, rebase, reset, clean, push, remote, tag, or stash. Do not
deploy, publish, release, deliver, or modify persistent Git configuration.
Propose the smallest useful change and return only the structured final result.
"""


def _load_frozen_case(
    contract: dict[str, Any], descriptor: dict[str, Any], root: Path
) -> tuple[dict[str, Any], bytes]:
    source = (root / descriptor["source_task_receipt"]).resolve()
    if not is_contained(root, source):
        raise ContractError("frozen task source escapes harness")
    source_bytes = source.read_bytes()
    if hashlib.sha256(source_bytes).hexdigest() != descriptor["source_task_sha256"]:
        raise ContractError("frozen task receipt hash mismatch")
    case = load_json(source)
    if case.get("case_id") != descriptor["case_id"]:
        raise ContractError("frozen task case id mismatch")
    if freeze_validator_plan(case["validator_plan"]) != case["validator_plan_digest"]:
        raise ContractError("frozen validator plan digest mismatch")
    request_source = (root / contract["paths"]["source_router_request_config"]).resolve()
    request_bytes = request_source.read_bytes()
    if hashlib.sha256(request_bytes).hexdigest() != contract["paths"]["source_router_request_config_sha256"]:
        raise ContractError("frozen Router request config hash mismatch")
    request_config = load_json(request_source)
    request_case = next((item for item in request_config.get("cases", []) if item.get("case_id") == case["case_id"]), None)
    if request_case is None:
        raise ContractError("frozen Router request is missing")
    for field in ("repository", "baseline_head", "task_text"):
        if request_case.get(field) != case.get(field):
            raise ContractError(f"frozen Router request binding mismatch: {field}")
    if freeze_validator_plan(request_case["validator_plan"]) != case["validator_plan_digest"]:
        raise ContractError("frozen Router validator binding mismatch")
    case["router_request"] = request_case["router_request"]
    return case, source_bytes


def _verify_control(contract: dict[str, Any]) -> dict[str, Any]:
    control = contract["existing_fixed_premium_control"]
    assert_control_action_allowed("read")
    repository = contract["repositories"][control["repository"]]["path"]
    branch_commit = _git(repository, "rev-parse", f"refs/heads/{control['branch']}")
    parent = _git(repository, "rev-parse", f"{control['commit']}^")
    if branch_commit != control["commit"] or parent != control["baseline"]:
        raise RuntimeError("EXISTING_CONTROL_MISSING_OR_MUTATED")
    if not control["read_only"] or control["rerun"] or control["merge"]:
        raise RuntimeError("UNAUTHORIZED_CONTROL_RERUN_OR_MERGE")
    return {
        "branch": control["branch"], "commit": control["commit"],
        "parent": parent, "unchanged": True, "rerun": False, "merge": False,
    }


def _pool_state(
    pool: str | Path,
    repositories: list[str | Path] | None = None,
) -> dict[str, Any]:
    root = Path(pool).resolve()
    root.mkdir(parents=True, exist_ok=True)
    entries = sorted(path.name for path in root.iterdir())
    registered: set[str] = set()
    for repository in repositories or []:
        for line in _git(
            repository, "worktree", "list", "--porcelain"
        ).splitlines():
            if not line.startswith("worktree "):
                continue
            candidate = Path(line.removeprefix("worktree ")).resolve()
            if is_contained(root, candidate) and not same_path(root, candidate):
                registered.add(str(candidate))
    return {
        "path": str(root),
        "entry_count": len(entries),
        "entries": entries,
        "registered_worktree_count": len(registered),
        "registered_worktrees": sorted(registered),
    }


def _preflight(contract: dict[str, Any], root: Path) -> dict[str, Any]:
    validate_contract_paths(contract, root)
    live_model_map = load_json(root / "config" / "model-map.json")
    profiles = live_model_map.get("logical_profiles", {})
    for profile, expected in contract["model_mapping"].items():
        actual = profiles.get(profile, {})
        if (
            actual.get("codex_model") != expected["model"]
            or actual.get("model_reasoning_effort") != expected["reasoning_effort"]
            or actual.get("next_escalation_profile") != expected["next"]
        ):
            raise RuntimeError("UNKNOWN_PROFILE")
    if set(profiles) != set(contract["model_mapping"]):
        raise RuntimeError("UNKNOWN_PROFILE")
    harness_state = repository_state(root)
    if not same_path(harness_state["root"], root):
        raise RuntimeError("HARNESS_STATE_MISMATCH")
    if (
        not harness_state["clean"] or harness_state["remotes"]
        or harness_state["locks"] or harness_state["active_operations"]
    ):
        raise RuntimeError("HARNESS_STATE_MISMATCH")
    parent = _git(root, "rev-parse", "HEAD^")
    subject = _git(root, "show", "-s", "--format=%s", "HEAD")
    if parent != contract["prepared_from_harness_head"] or subject != contract["preparation_commit_subject"]:
        raise RuntimeError("HARNESS_STATE_MISMATCH")
    targets = []
    for repository_id, entry in contract["repositories"].items():
        state = require_clean_baseline(entry["path"], entry["path"], entry["baseline_head"])
        if state["branch"] != entry["branch"]:
            raise RuntimeError("TARGET_STATE_MISMATCH")
        targets.append({
            "repository": repository_id, "branch": state["branch"],
            "head": state["head"], "clean": state["clean"],
        })
    pool = _pool_state(
        contract["paths"]["worktree_pool"],
        [entry["path"] for entry in contract["repositories"].values()],
    )
    if pool["entry_count"] != 0 or pool["registered_worktree_count"] != 0:
        raise RuntimeError("WORKTREE_POOL_NOT_EMPTY")
    return {
        "harness": {"head": harness_state["head"], "clean": True, "remote_count": 0},
        "targets": targets, "control": _verify_control(contract),
        "worktree_pool": pool,
    }


def _task_still_useful(case: dict[str, Any], repository: Path) -> None:
    if case["case_id"] == "mtr-docs-private-executor-r1":
        for relative in (
            "docs/dogfood-automation.md",
            "tests/integrations/test_dogfood_automation.py",
        ):
            if (repository / relative).exists():
                raise RuntimeError("FROZEN_TASK_OR_VALIDATOR_MISSING")
    elif case["case_id"] == "qwen-docx-hidden-elements-r1":
        text = (repository / "tests" / "redaction" / "test_docx_package.py").read_text(encoding="utf-8")
        if "vanish" in text or "webHidden" in text:
            raise RuntimeError("FROZEN_TASK_OR_VALIDATOR_MISSING")


def _substantive_lane_content(case: dict[str, Any], worktree: Path) -> bool:
    paths = case.get("changed_path_patterns", [])
    if case.get("case_id") == "writable_smoke":
        try:
            return (worktree / "smoke/result.txt").read_bytes() == b"WORKSPACE_WRITE_OK\n"
        except OSError:
            return False
    try:
        required = [worktree / path for path in _exact_bounded_write_paths(paths)]
        if not required or not all(
            path.is_file() and len(path.read_bytes()) > 0 for path in required
        ):
            return False
    except (OSError, ContractError):
        return False
    if case["case_id"] != "mtr-docs-private-executor-r1":
        return True
    try:
        documentation = (worktree / "docs/dogfood-automation.md").read_text(
            encoding="utf-8"
        )
        integration = (
            worktree / "tests/integrations/test_dogfood_automation.py"
        ).read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return False
    documentation_folded = documentation.casefold()
    integration_folded = integration.casefold()
    return bool(
        len(documentation.strip()) >= 80
        and len(integration.strip()) >= 80
        and all(
            token in documentation_folded
            for token in (
                "execution_authorized", "authorized_write_scope",
                "recommended", "separate", "authority",
            )
        )
        and all(
            token in integration_folded
            for token in (
                "unittest", "assess", "execution_authorized",
                "authorized_write_scope", "recommended",
            )
        )
    )


def _run_attempt(
    contract: dict[str, Any], case: dict[str, Any], descriptor: dict[str, Any],
    source_task_bytes: bytes, decision: dict[str, Any], profile: str,
    attempt: int, escalation_count: int, budget: ProcessAccounting,
    launcher: Launcher, ancestry_guard: Callable[[], dict[str, Any]],
    executable_resolver: Callable[[], str], root: Path,
) -> dict[str, Any]:
    repository_entry = contract["repositories"][case["repository"]]
    repository = Path(repository_entry["path"])
    baseline = case["baseline_head"]
    require_clean_baseline(repository, repository, baseline)
    receipt_dir = root / contract["reporting"]["receipt_root"] / case["case_id"] / f"attempt-{attempt}"
    raw_dir = root / contract["reporting"]["raw_root"] / case["case_id"] / f"attempt-{attempt}"
    run_temp = raw_dir / "validator-temp"
    (run_temp / "validation" / "atomic").mkdir(parents=True, exist_ok=True)
    worktree = (
        Path(contract["paths"]["worktree_pool"]) / case["repository"]
        / f"{case['case_id']}-r3" / f"router_auto-{attempt}"
    )
    branch = f"{descriptor['branch_prefix']}-{attempt}"
    create_worktree(repository, contract["paths"]["worktree_pool"], worktree, branch, baseline)
    committed = False
    result: dict[str, Any] = {}
    output_valid = False
    filesystem_mutation = False
    validator_completed = False
    try:
        metadata = worktree / Path(BOUNDED_WRITER_RELATIVE).parent
        metadata.mkdir(parents=True, exist_ok=False)
        local_schema = metadata / "proposed-files-result.schema.json"
        local_lane_policy = metadata / "host-materialization-lanes.json"
        final_output = metadata / "final-result.json"
        shutil.copyfile(root / "schemas" / "proposed-files-result.schema.json", local_schema)
        shutil.copyfile(root / "config" / "host-materialization-lanes.json", local_lane_policy)
        lane_policy = load_lane_policy(local_lane_policy)
        lane = host_lane_contract(lane_policy, case["case_id"])
        allowed_write_paths = _exact_bounded_write_paths(
            case["changed_path_patterns"]
        )
        target_aliases = _target_aliases(allowed_write_paths)
        if target_aliases != host_alias_map(lane):
            raise RuntimeError("HOST_MATERIALIZATION_LANE_POLICY_MISMATCH")
        local_writer = metadata / Path(BOUNDED_WRITER_RELATIVE).name
        local_write_policy = metadata / BOUNDED_WRITE_POLICY_FILENAME
        shutil.copyfile(Path(__file__).with_name("bounded_writer.py"), local_writer)
        write_json(local_write_policy, {
            "schema_version": "2.0.0",
            "workspace": str(worktree.resolve(strict=True)),
            "target_aliases": target_aliases,
            "max_content_bytes": max(item["maximum_content_bytes"] for item in lane["aliases"]),
        })
        output_schema = load_json(local_schema)
        schema_digest = hashlib.sha256(local_schema.read_bytes()).hexdigest()
        lane_policy_digest = hashlib.sha256(local_lane_policy.read_bytes()).hexdigest()
        writer_digest = hashlib.sha256(local_writer.read_bytes()).hexdigest()
        write_policy_digest = hashlib.sha256(
            local_write_policy.read_bytes()
        ).hexdigest()
        receipt_schema_path = root / "schemas" / "bounded-writer-receipt.schema.json"
        receipt_schema_digest = hashlib.sha256(receipt_schema_path.read_bytes()).hexdigest()
        immutable_model_files = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (local_schema, local_lane_policy, local_writer, local_write_policy)
        }
        receipt_dir.mkdir(parents=True, exist_ok=True)
        (receipt_dir / "task.json").write_bytes(source_task_bytes)
        authority = {
            "schema_version": "1.0.0", "contract_id": RUNTIME_ROUTE_ID,
            "case_id": case["case_id"], "target_repository": str(repository),
            "baseline_head": baseline, "allowed_worktree": str(worktree),
            "allowed_task": case["task_text"],
            "allowed_validation": [item["name"] for item in case["validator_plan"]["commands"]],
            "allowed_commit_behavior": "validated local commit; risk-gated merge",
            "external_push_authorized": False,
            "known_external_sessions_declared_active": True,
            "execution_authority_source": "explicit external R3 runtime contract",
            "router_execution_authorized": False, "router_authorized_write_scope": [],
            "worktree_local_schema_path": str(local_schema),
            "child_writable_roots": [],
        }
        write_json(receipt_dir / "authority-receipt.json", authority)
        write_json(receipt_dir / "decision.json", decision)
        mapping = contract["model_mapping"][profile]
        command = build_external_codex_command(
            "codex.exe", worktree, mapping["model"],
            mapping["reasoning_effort"], local_schema, final_output,
        )
        prompt = _child_prompt(case, worktree)
        forbidden_paths = [
            root, *[entry["path"] for entry in contract["repositories"].values()],
            *contract["denylist"],
        ]
        budget.record_prelaunch()
        try:
            validate_launch_payloads(
                _task_payload(case),
                load_json(root / "schemas" / "task.schema.json"),
                authority,
                load_json(root / "schemas" / "authority-receipt.schema.json"),
                decision,
                output_schema,
                set(contract["model_mapping"]),
            )
            validate_external_command_shape(command, worktree)
            validate_child_transport(worktree, command, prompt, forbidden_paths)
        except PayloadValidationError:
            result = _unstarted_execution("SCHEMA_REJECTION")
        else:
            ancestry_guard()
            try:
                command[0] = executable_resolver()
            except FileNotFoundError:
                result = _unstarted_execution("MISSING_COMMAND")
            else:
                prestart_transport_verified = bool(
                    local_writer.exists()
                    and local_write_policy.exists()
                    and hashlib.sha256(local_writer.read_bytes()).hexdigest()
                    == writer_digest
                    and hashlib.sha256(local_write_policy.read_bytes()).hexdigest()
                    == write_policy_digest
                    and not (metadata / BOUNDED_WRITE_RECEIPT_DIRECTORY).exists()
                )
                if not prestart_transport_verified:
                    raise RuntimeError("BOUNDED_WRITE_TRANSPORT_PRESTART_MISMATCH")
                budget.require_start_available()
                starts_before = budget.os_child_process_started
                result = launcher(
                    command=command, prompt=prompt, raw_directory=raw_dir,
                    worktree=worktree,
                    timeout_seconds=int(case.get("model_timeout_seconds", 1200)),
                    on_process_started=budget.record_process_start,
                )
                started_delta = budget.os_child_process_started - starts_before
                if started_delta != int(bool(result.get("child_process_started"))):
                    raise RuntimeError("ENVIRONMENT_FAILURE")
        if final_output.exists():
            shutil.copyfile(final_output, raw_dir / "final-result.json")
        schema_unchanged = (
            local_schema.exists()
            and hashlib.sha256(local_schema.read_bytes()).hexdigest() == schema_digest
            and local_lane_policy.exists()
            and hashlib.sha256(local_lane_policy.read_bytes()).hexdigest()
            == lane_policy_digest
        )
        bounded_write_transport_unchanged = bool(
            local_writer.exists()
            and local_write_policy.exists()
            and hashlib.sha256(local_writer.read_bytes()).hexdigest() == writer_digest
            and hashlib.sha256(local_write_policy.read_bytes()).hexdigest()
            == write_policy_digest
        )
        immutable_hashes_match = bool(
            schema_unchanged
            and bounded_write_transport_unchanged
            and all(
                path.is_file()
                and hashlib.sha256(path.read_bytes()).hexdigest()
                == immutable_model_files[path.name]
                for path in (local_schema, local_lane_policy, local_writer, local_write_policy)
            )
        )
        model_paths = [
            path for path in changed_paths(worktree)
            if not path.replace("\\", "/").startswith(".mtr-dogfood-r4/")
        ]
        allowed_metadata = set(immutable_model_files) | {final_output.name}
        unexpected_metadata = {
            path.relative_to(metadata).as_posix()
            for path in metadata.rglob("*")
            if path.is_file() and path.relative_to(metadata).as_posix() not in allowed_metadata
        }
        model_workspace_mutated = bool(model_paths or unexpected_metadata)
        scan = _scan_child_commands(
            raw_dir / "codex-events.jsonl",
            forbidden_paths,
            worktree,
            target_aliases,
            [],
            model_read_only=True,
        )
        protocol_failure: str | None = None
        transaction_receipt: dict[str, Any] | None = None
        proposal = None
        output_valid = False
        claim: dict[str, Any] = {}
        writer_receipt_validation: dict[str, Any] = {
            "valid": False,
            "receipt_count": 0,
            "receipts": [],
            "errors": ["host materialization did not complete"],
        }
        source_repositories_unchanged = all(
            not Path(entry["path"]).exists()
            or (
                _git(entry["path"], "rev-parse", "HEAD", check=False)
                == entry["baseline_head"]
                and not _git(
                    entry["path"], "status", "--porcelain=v2", check=False
                )
            )
            for entry in contract["repositories"].values()
        )
        try:
            infrastructure = _normalize_infrastructure(
                result.get("infrastructure_failure_class")
            )
            if infrastructure or int(result.get("host_policy_failure_count") or 0):
                raise HostMaterializationError(
                    infrastructure or "HOST_POLICY_REJECTED_CHILD_FILESYSTEM_ACCESS",
                    "model process infrastructure gate failed",
                )
            if any(scan.get(name) for name in (
                "external_path_access_detected",
                "credential_access_detected",
                "remote_operation_attempted",
                "forbidden_action_detected",
            )):
                raise HostMaterializationError(
                    "UNAUTHORIZED_ACTION", "higher-precedence child safety boundary failed"
                )
            if not source_repositories_unchanged:
                raise HostMaterializationError(
                    "UNAUTHORIZED_ACTION", "source repository changed before materialization"
                )
            proposal = validate_model_phase(
                process_result=result,
                output_path=final_output,
                lane=lane,
                schema=output_schema,
                command_scan=scan,
                workspace_mutated=model_workspace_mutated,
                immutable_hashes_match=immutable_hashes_match,
            )
            output_valid = True
            claim = proposal.result
            transaction_receipt = materialize_transaction(
                workspace=worktree,
                metadata=metadata,
                proposal=proposal,
                lane=lane,
                helper_sha256=writer_digest,
                policy_sha256=write_policy_digest,
                receipt_schema_path=receipt_schema_path,
                receipt_schema_sha256=receipt_schema_digest,
                protected_roots=tuple(
                    Path(entry["path"]) for entry in contract["repositories"].values()
                ),
            )
            writer_receipt_validation = validate_writer_receipts(
                workspace=worktree,
                helper_sha256=writer_digest,
                policy_sha256=write_policy_digest,
                target_aliases=target_aliases,
            )
        except HostMaterializationError as exc:
            protocol_failure = exc.classification
            if exc.transaction_receipt is not None:
                transaction_receipt = exc.transaction_receipt
        transaction_path = metadata / "host-materialization-transaction.json"
        if transaction_path.is_file():
            shutil.copyfile(transaction_path, raw_dir / transaction_path.name)
        shutil.rmtree(metadata, ignore_errors=True)
        shutil.rmtree(worktree / ".mtr-dogfood-r2", ignore_errors=True)

        paths = changed_paths(worktree)
        filesystem_mutation = bool(paths)
        patch = diff_bytes(worktree)
        (raw_dir / "target-diff.patch").write_bytes(patch)
        path_scope_ok = paths_allowed(paths, case["changed_path_patterns"])
        confidentiality_ok = _confidentiality_scan(
            worktree, case["repository"], paths
        )
        substantive_content_ok = _substantive_lane_content(case, worktree)
        receipt_path_consistency = bool(
            transaction_receipt is not None
            and transaction_receipt.get("final_status") == "committed"
            and writer_receipt_validation["valid"]
            and writer_receipt_validation["receipt_count"] == len(paths)
            and sorted(
                item["target_alias"]
                for item in writer_receipt_validation["receipts"]
            ) == sorted(target_aliases)
        )
        exact_diff_ok = sorted(paths) == sorted(allowed_write_paths)
        forbidden_action = bool(
            scan["forbidden_action_detected"]
            or scan["external_path_access_detected"]
            or scan["credential_access_detected"]
            or scan["remote_operation_attempted"]
        )
        infrastructure = _normalize_infrastructure(
            result.get("infrastructure_failure_class")
        )
        validation_results: list[dict[str, Any]] = []
        may_validate = bool(
            result.get("child_process_started")
            and result.get("model_execution_completed")
            and result.get("exit_code") == 0
            and output_valid
            and schema_unchanged
            and bounded_write_transport_unchanged
            and infrastructure is None
            and protocol_failure is None
            and paths
            and path_scope_ok
            and exact_diff_ok
            and confidentiality_ok
            and substantive_content_ok
            and not forbidden_action
            and receipt_path_consistency
        )
        validator_side_effect_free = True
        if may_validate:
            validation_results = run_plan(
                worktree,
                _render_plan(case["validator_plan"], worktree, run_temp),
                raw_dir,
            )
            validator_completed = True
            post_validator_paths = changed_paths(worktree)
            if post_validator_paths != paths:
                validator_side_effect_free = False
                if result.get("infrastructure_failure_class") is None:
                    result["infrastructure_failure_class"] = "ENVIRONMENT_FAILURE"
                paths = post_validator_paths
                filesystem_mutation = bool(paths)
                patch = diff_bytes(worktree)
                (raw_dir / "target-diff.patch").write_bytes(patch)
                path_scope_ok = paths_allowed(paths, case["changed_path_patterns"])
                confidentiality_ok = _confidentiality_scan(
                    worktree, case["repository"], paths
                )
        validation = summarize_validation(
            bool(
                result.get("model_execution_completed")
                and result.get("exit_code") == 0
            ),
            path_scope_ok,
            validation_results,
            forbidden_action or not validator_side_effect_free,
        )
        validation["confidentiality_scan_passed"] = confidentiality_ok
        validation["substantive_content_passed"] = substantive_content_ok
        validation["validator_side_effect_free"] = validator_side_effect_free
        required_validator_count = len(case["validator_plan"]["commands"])
        validation["required_validator_count"] = required_validator_count
        validation["validation_ran"] = bool(validation_results)
        validation["validator_stage_passed"] = bool(
            (
                required_validator_count == 0
                or len(validation_results) == required_validator_count
            )
            and all(item.get("passed") for item in validation_results)
        )
        if required_validator_count and not validation_results:
            validation["automated_acceptance"] = False
        if forbidden_action:
            failure_class = "UNAUTHORIZED_ACTION"
        elif protocol_failure:
            failure_class = protocol_failure
        elif not receipt_path_consistency:
            failure_class = "HOST_MATERIALIZATION_RECEIPT_INVALID"
        elif not exact_diff_ok or not path_scope_ok:
            failure_class = "HOST_MATERIALIZATION_DIFF_MISMATCH"
        elif not confidentiality_ok:
            failure_class = "CONFIDENTIALITY_BOUNDARY"
        elif not substantive_content_ok:
            failure_class = "LANE_VALIDATION_FAILED"
        elif not validation["automated_acceptance"] or not validator_side_effect_free:
            failure_class = "LANE_VALIDATION_FAILED"
        else:
            failure_class = ""
        accepted = failure_class == ""
        execution_receipt = {
            "schema_version": "1.0.0",
            "route_id": RUNTIME_ROUTE_ID,
            "case_id": case["case_id"],
            "attempt": attempt,
            "profile": profile,
            "model": mapping["model"],
            "reasoning_effort": mapping["reasoning_effort"],
            "escalation_count": escalation_count,
            "child_process_started": bool(result.get("child_process_started")),
            "model_execution_observed": bool(result.get("model_execution_observed")),
            "model_execution_completed": bool(result.get("model_execution_completed")),
            "exit_code": result.get("exit_code"),
            "timed_out": bool(result.get("timed_out")),
            "wall_time_seconds": result.get("wall_time_seconds"),
            "final_output_valid": output_valid,
            "schema_unchanged": schema_unchanged,
            "model_workspace_read_only": True,
            "model_workspace_mutation_detected": model_workspace_mutated,
            "source_repositories_unchanged_before_materialization": source_repositories_unchanged,
            "host_materialization_transaction": transaction_receipt,
            "bounded_write_transport_unchanged": bounded_write_transport_unchanged,
            "bounded_writer_receipt_validation": writer_receipt_validation,
            "bounded_writer_receipts_match_diff": receipt_path_consistency,
            "filesystem_mutation_observed": filesystem_mutation,
            "validator_completed": validator_completed,
            "changed_paths": paths,
            "confidentiality_scan_passed": confidentiality_ok,
            "diff_sha256": hashlib.sha256(patch).hexdigest(),
            "failure_class": failure_class,
            "accepted": accepted,
            "usage": {
                key: result.get(key)
                for key in (
                    "input_tokens", "cached_input_tokens", "output_tokens",
                    "reasoning_output_tokens",
                )
            },
            "infrastructure": {
                key: result.get(key)
                for key in (
                    "infrastructure_failure_class", "host_policy_failure_count",
                    "rate_limit_event_count", "model_unavailable_event_count",
                    "authentication_event_count", "output_schema_error_count",
                )
            },
            "child_command_scan": scan,
            "raw_log_sha256": _file_hashes(raw_dir),
        }
        write_json(receipt_dir / "execution.json", execution_receipt)
        write_json(receipt_dir / "validation.json", validation)

        target_commit = ""
        merged = False
        merge_blocked = ""
        if accepted:
            primary = require_clean_baseline(repository, repository, baseline)
            if primary["branch"] != repository_entry["branch"]:
                raise RuntimeError("CONCURRENT_TARGET_CHANGE")
            identity = contract["commit_identity"]
            target_commit = commit_exact_paths(
                worktree,
                paths,
                f"Complete {case['case_id']} via Router",
                identity["name"],
                identity["email"],
            )
            committed = True
            if descriptor["automatic_fast_forward_merge"]:
                merge_allowed = risk_allows_auto_merge(
                    case["risk"], case["change_class"], "ROUTER_AUTO"
                )
                if not merge_allowed:
                    raise RuntimeError("UNAUTHORIZED_ACTION")
                try:
                    fast_forward(repository, baseline, target_commit)
                except GitContractError:
                    merge_blocked = "CONCURRENT_TARGET_CHANGE"
                else:
                    merged = True
        outcome = {
            **execution_receipt,
            "branch": branch if committed else "",
            "target_commit": target_commit,
            "automatic_merge": merged,
            "merge_blocked": merge_blocked,
            "validation": validation,
            "model_claim": _sanitized_claim_summary(claim),
        }
        write_json(receipt_dir / "outcome.json", outcome)
        return outcome
    finally:
        budget.record_result(
            result,
            final_output_valid=output_valid,
            filesystem_mutation=filesystem_mutation,
            validator_completed=validator_completed,
        )
        if worktree.exists():
            remove_worktree(repository, contract["paths"]["worktree_pool"], worktree)
        if not committed:
            delete_unadvanced_branch(repository, branch, baseline)


Assessment = Callable[[str | Path, dict[str, Any], set[str]], dict[str, Any]]


def execute_lane(
    contract: dict[str, Any],
    descriptor: dict[str, Any],
    budget: ProcessAccounting,
    launcher: Launcher,
    ancestry_guard: Callable[[], dict[str, Any]],
    executable_resolver: Callable[[], str],
    root: Path,
    *,
    assessor: Assessment = assess_live,
    attempt_runner: Callable[..., dict[str, Any]] = _run_attempt,
) -> dict[str, Any]:
    case, source_task_bytes = _load_frozen_case(contract, descriptor, root)
    repository = Path(contract["repositories"][case["repository"]]["path"])
    if case["baseline_head"] != contract["repositories"][case["repository"]]["baseline_head"]:
        raise RuntimeError("BASELINE_FAILURE")
    if any(
        case.get(key)
        for key in ("requires_confidential_payload", "requires_network", "requires_other_repository")
    ):
        raise RuntimeError("CONFIDENTIALITY_BOUNDARY")
    _task_still_useful(case, repository)
    decision = assessor(
        contract["repositories"]["model-tier-router"]["path"],
        case["router_request"],
        set(contract["model_mapping"]),
    )
    if (
        decision.get("execution_authorized") is not False
        or decision.get("authorized_write_scope", []) != []
        or decision.get("status") != "recommended"
    ):
        raise RuntimeError("ROUTER_DECISION_INVALID")
    profile = decision.get("selected_profile")
    if profile not in contract["model_mapping"]:
        raise RuntimeError("UNKNOWN_PROFILE")

    attempts = [
        attempt_runner(
            contract, case, descriptor, source_task_bytes, decision, profile,
            1, 0, budget, launcher, ancestry_guard, executable_resolver, root,
        )
    ]
    next_profile = None
    if not attempts[0]["accepted"]:
        next_profile = next_escalation_profile(
            contract, profile, attempts[0]["failure_class"], 0
        )
    if next_profile is not None and budget.remaining > 0:
        attempts.append(
            attempt_runner(
                contract, case, descriptor, source_task_bytes, decision,
                next_profile, 2, 1, budget, launcher, ancestry_guard,
                executable_resolver, root,
            )
        )
    final = attempts[-1]
    return {
        "case_id": case["case_id"],
        "repository": case["repository"],
        "decision": decision,
        "initial_profile": profile,
        "attempts": attempts,
        "escalation_eligible": next_profile is not None,
        "escalation_count": len(attempts) - 1,
        "final_profile": attempts[-1]["profile"],
        "accepted": bool(final["accepted"]),
        "final_status": "accepted" if final["accepted"] else final["failure_class"],
        "target_commit": final["target_commit"],
        "branch_retained": final["branch"],
        "automatic_merge": bool(final["automatic_merge"]),
        "merge_blocked": final.get("merge_blocked", ""),
    }


def product_tasks_allowed(smoke: dict[str, Any]) -> bool:
    return bool(smoke.get("accepted"))


def next_product_lane_allowed(lanes: list[dict[str, Any]]) -> bool:
    return not lanes or bool(lanes[-1].get("accepted"))


def _usage_totals(lanes: list[dict[str, Any]], smoke: dict[str, Any]) -> dict[str, int | None]:
    keys = (
        "input_tokens", "cached_input_tokens", "output_tokens",
        "reasoning_output_tokens",
    )
    usage_rows = [smoke.get("usage", {})]
    usage_rows.extend(
        attempt.get("usage", {})
        for lane in lanes
        for attempt in lane.get("attempts", [])
    )
    totals: dict[str, int | None] = {}
    for key in keys:
        values = [row.get(key) for row in usage_rows]
        totals[key] = (
            sum(int(value) for value in values if isinstance(value, int))
            if any(isinstance(value, int) for value in values)
            else None
        )
    return totals


def _control_comparison(root: Path, lanes: list[dict[str, Any]]) -> dict[str, Any]:
    receipt = root / "runs" / "receipts" / (
        "mtr-docs-private-executor-r1--fixed_premium_control"
    )
    execution = load_json(receipt / "execution.json")
    validation = load_json(receipt / "validation.json")
    outcome = load_json(receipt / "outcome.json")
    mtr = next(
        (lane for lane in lanes if lane["case_id"] == "mtr-docs-private-executor-r1"),
        None,
    )
    return {
        "control_commit": outcome.get("commit_oid"),
        "control_validated": bool(validation.get("automated_acceptance")),
        "control_changed_paths": execution.get("changed_paths", []),
        "control_diff_sha256": execution.get("diff_sha256"),
        "control_validation": validation,
        "control_usage": {
            key: execution.get(key)
            for key in (
                "input_tokens", "cached_input_tokens", "output_tokens",
                "reasoning_output_tokens",
            )
        },
        "router_attempts": [] if mtr is None else [
            {
                "profile": item["profile"],
                "accepted": item["accepted"],
                "changed_paths": item["changed_paths"],
                "diff_sha256": item["diff_sha256"],
                "usage": item["usage"],
            }
            for item in mtr["attempts"]
        ],
        "causal_wall_time_claim": False,
    }


def _report_payload(
    contract: dict[str, Any],
    ancestry: dict[str, Any],
    smoke: dict[str, Any],
    lanes: list[dict[str, Any]],
    budget: ProcessAccounting,
    root: Path,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "route_id": RUNTIME_ROUTE_ID,
        "ordinary_powershell_ancestor_verified": bool(
            ancestry.get("ordinary_powershell_ancestor_verified")
        ),
        "fixture_smoke": smoke,
        "process_accounting": budget.as_dict(),
        "maximum_child_process_starts": budget.maximum,
        "child_process_starts_used": budget.os_child_process_started,
        "model_execution_count": budget.model_execution_observed,
        "lanes": lanes,
        "router_decisions": [lane["decision"] for lane in lanes],
        "usage_totals": _usage_totals(lanes, smoke),
        "existing_control_comparison": _control_comparison(root, lanes),
        "existing_fixed_premium_control_unchanged": True,
        "target_commits_created": [
            lane["target_commit"] for lane in lanes if lane["target_commit"]
        ],
        "target_branches_retained": [
            lane["branch_retained"] for lane in lanes if lane["branch_retained"]
        ],
        "automatic_merges": [
            lane["target_commit"] for lane in lanes if lane["automatic_merge"]
        ],
        "wall_time_measurement_quality": (
            "OBSERVED_ONLY_CONCURRENCY_NOT_USED_FOR_CAUSAL_CLAIMS"
        ),
        "zero_action_counts": {
            "confidential_payload_sent_count": 0,
            "customer_delivery_count": 0,
            "deployment_count": 0,
            "external_push_count": 0,
            "remote_mutation_count": 0,
            "release_or_publication_count": 0,
            "other_repository_access_count": 0,
            "other_repository_mutation_count": 0,
        },
    }


def _write_reports(
    contract: dict[str, Any],
    ancestry: dict[str, Any],
    smoke: dict[str, Any],
    lanes: list[dict[str, Any]],
    budget: ProcessAccounting,
    root: Path,
) -> list[str]:
    payload = _report_payload(contract, ancestry, smoke, lanes, budget, root)
    report_paths = [root / item for item in contract["reporting"]["reports"]]
    for path in report_paths:
        if path.exists():
            raise RuntimeError("REPORT_PATH_ALREADY_EXISTS")
        path.parent.mkdir(parents=True, exist_ok=True)
    write_json(report_paths[0], payload)
    lines = [
        "# External automated dogfood pilot R3",
        "",
        f"- Fixture smoke: {smoke.get('status', 'not-run')}",
        f"- Child process starts: {budget.os_child_process_started}/{budget.maximum}",
        f"- Observable model executions: {budget.model_execution_observed}",
        f"- Existing fixed-premium control unchanged: true",
        "",
        "Wall time is observational only and is not used for causal claims.",
    ]
    for lane in lanes:
        lines.append(
            f"- {lane['case_id']}: {lane['final_status']} "
            f"(attempts={len(lane['attempts'])})"
        )
    report_paths[1].write_text("\n".join(lines) + "\n", encoding="utf-8")
    with report_paths[2].open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "case_id", "attempt", "profile", "accepted", "failure_class",
                "child_process_started", "model_execution_observed",
                "input_tokens", "cached_input_tokens", "output_tokens",
                "reasoning_output_tokens", "target_commit", "automatic_merge",
            ],
        )
        writer.writeheader()
        for lane in lanes:
            for attempt in lane["attempts"]:
                writer.writerow({
                    "case_id": lane["case_id"],
                    "attempt": attempt["attempt"],
                    "profile": attempt["profile"],
                    "accepted": attempt["accepted"],
                    "failure_class": attempt["failure_class"],
                    "child_process_started": attempt["child_process_started"],
                    "model_execution_observed": attempt["model_execution_observed"],
                    **attempt["usage"],
                    "target_commit": attempt["target_commit"],
                    "automatic_merge": attempt["automatic_merge"],
                })
    return [path.relative_to(root).as_posix() for path in report_paths]


def _reject_unsafe_receipt_value(value: Any) -> None:
    forbidden_keys = {
        "command_line", "raw_command_line", "stdout", "stderr", "prompt",
        "credential", "credentials",
    }
    if isinstance(value, dict):
        if forbidden_keys.intersection(str(key).casefold() for key in value):
            raise RuntimeError("SANITIZED_RECEIPT_VALIDATION_FAILED")
        for child in value.values():
            _reject_unsafe_receipt_value(child)
    elif isinstance(value, list):
        for child in value:
            _reject_unsafe_receipt_value(child)


def _validate_and_commit_reports(
    contract: dict[str, Any], root: Path, report_paths: list[str]
) -> str:
    receipt_root = root / contract["reporting"]["receipt_root"]
    receipt_paths = sorted(
        path.relative_to(root).as_posix()
        for path in receipt_root.rglob("*.json")
        if path.is_file()
    )
    if not receipt_paths:
        raise RuntimeError("SANITIZED_RECEIPT_VALIDATION_FAILED")
    denied = [
        str(Path(path).resolve()).replace("/", "\\").casefold()
        for path in contract["denylist"]
    ]
    for relative in receipt_paths:
        value = load_json(root / relative)
        _reject_unsafe_receipt_value(value)
        serialized = json.dumps(value, ensure_ascii=False).replace("/", "\\").casefold()
        if any(path in serialized for path in denied):
            raise RuntimeError("SANITIZED_RECEIPT_VALIDATION_FAILED")
    expected = sorted(set(report_paths + receipt_paths))
    actual = changed_paths(root)
    if actual != expected:
        raise RuntimeError("SANITIZED_RECEIPT_VALIDATION_FAILED")
    identity = contract["commit_identity"]
    return commit_exact_paths(
        root,
        expected,
        contract["reporting"]["report_commit_subject"],
        identity["name"],
        identity["email"],
    )


def _final_repository_states(contract: dict[str, Any], root: Path) -> dict[str, Any]:
    harness = repository_state(root)
    targets: dict[str, Any] = {}
    for repository_id, entry in contract["repositories"].items():
        state = repository_state(entry["path"])
        targets[repository_id] = {
            "branch": state["branch"],
            "head": state["head"],
            "clean": state["clean"],
            "locks": state["locks"],
            "active_operations": state["active_operations"],
        }
    return {
        "harness": {
            "branch": harness["branch"], "head": harness["head"],
            "clean": harness["clean"], "remote_count": len(harness["remotes"]),
            "locks": harness["locks"],
            "active_operations": harness["active_operations"],
        },
        "targets": targets,
    }


def _empty_closeout(contract: dict[str, Any]) -> dict[str, Any]:
    return {
        "route_id": RUNTIME_ROUTE_ID,
        "status": "BLOCKED_MODEL_TIER_ROUTER_DOGFOOD_R3_EXTERNAL_BEFORE_FIXTURE_SMOKE",
        "ordinary_powershell_ancestor_verified": False,
        "nested_codex_ancestor_detected": False,
        "fixture_smoke": {},
        "maximum_child_process_starts": contract["maximum_new_codex_exec_process_starts"],
        "child_process_starts_used": 0,
        "model_execution_count": 0,
        "model_tier_router_lane": {},
        "qwen_redaction_lane": {},
        "router_decisions": [],
        "usage_totals": {
            "input_tokens": None, "cached_input_tokens": None,
            "output_tokens": None, "reasoning_output_tokens": None,
        },
        "escalation_results": {},
        "existing_control_unchanged": True,
        "target_commits_created": [],
        "target_branches_retained": [],
        "automatic_merges": [],
        "harness_report_commit": {},
        "primary_repository_final_states": {},
        "worktree_pool_final_state": {},
        "confidential_payload_sent_count": 0,
        "customer_delivery_count": 0,
        "deployment_count": 0,
        "external_push_count": 0,
        "remote_mutation_count": 0,
        "release_or_publication_count": 0,
        "other_repository_access_count": 0,
        "other_repository_mutation_count": 0,
        "remaining_review_items": [],
        "remaining_blockers": [],
        "hard_stop_code": "",
    }


class ExternalRunner:
    def __init__(
        self,
        contract_path: str | Path,
        closeout_path: str | Path,
        runner_pid: int,
        *,
        launcher: Launcher = default_launcher,
        executable_resolver: Callable[[], str] = resolve_codex_executable,
        process_provider: ProcessProvider = windows_process_provider,
        assessor: Assessment = assess_live,
        fixture_parent: str | Path | None = None,
    ) -> None:
        self.root = harness_root()
        self.contract = load_runtime_contract(contract_path, self.root)
        self.closeout_path = Path(closeout_path).resolve()
        expected_closeout = (
            self.root / self.contract["reporting"]["closeout"]
        ).resolve()
        if not same_path(self.closeout_path, expected_closeout):
            raise ContractError("external closeout path mismatch")
        self.runner_pid = int(runner_pid)
        self.launcher = launcher
        self.executable_resolver = executable_resolver
        self.process_provider = process_provider
        self.assessor = assessor
        self.fixture_parent = fixture_parent

    def _guard(self) -> dict[str, Any]:
        return verify_standalone_powershell(
            self.runner_pid, self.process_provider
        )

    def _finish(self, closeout: dict[str, Any], exit_code: int) -> tuple[dict[str, Any], int]:
        schema = load_json(self.root / self.contract["paths"]["closeout_schema"])
        validate_closeout(closeout, schema)
        write_json(self.closeout_path, closeout)
        return closeout, exit_code

    def _commit_runtime_evidence(
        self,
        ancestry: dict[str, Any],
        smoke: dict[str, Any],
        lanes: list[dict[str, Any]],
        budget: ProcessAccounting,
    ) -> str:
        report_paths = _write_reports(
            self.contract, ancestry, smoke, lanes, budget, self.root
        )
        return _validate_and_commit_reports(self.contract, self.root, report_paths)

    def run(self) -> tuple[dict[str, Any], int]:
        contract = self.contract
        closeout = _empty_closeout(contract)
        budget = ProcessAccounting(
            maximum=contract["maximum_new_codex_exec_process_starts"]
        )
        ancestry: dict[str, Any] = {}
        smoke: dict[str, Any] = {}
        lanes: list[dict[str, Any]] = []
        try:
            ancestry = self._guard()
        except NestedCodexAncestorError as exc:
            receipt = getattr(exc, "receipt", {})
            closeout["nested_codex_ancestor_detected"] = True
            closeout["ordinary_powershell_ancestor_verified"] = False
            closeout["hard_stop_code"] = "NESTED_CODEX_ANCESTOR_DETECTED"
            closeout["remaining_blockers"] = ["NESTED_CODEX_ANCESTOR_DETECTED"]
            closeout["fixture_smoke"] = {
                "created": False,
                "ancestry_receipt": receipt,
            }
            return self._finish(closeout, 2)
        except ProcessAncestryError:
            closeout["hard_stop_code"] = "PROCESS_ANCESTRY_NOT_VERIFIED"
            closeout["remaining_blockers"] = ["PROCESS_ANCESTRY_NOT_VERIFIED"]
            return self._finish(closeout, 2)

        closeout["ordinary_powershell_ancestor_verified"] = True
        try:
            preflight = _preflight(contract, self.root)
            closeout["primary_repository_final_states"] = preflight
        except (ContractError, GitContractError, RuntimeError) as exc:
            code = str(exc) if str(exc).isupper() else "EXTERNAL_PREFLIGHT_FAILED"
            closeout["hard_stop_code"] = code
            closeout["remaining_blockers"] = [code]
            return self._finish(closeout, 2)

        smoke_receipt = (
            self.root / contract["reporting"]["receipt_root"] / "writable-smoke.json"
        )
        smoke = run_writable_smoke(
            contract,
            self.root,
            budget,
            self.launcher,
            self._guard,
            self.executable_resolver,
            self.root / contract["reporting"]["raw_root"] / "writable-smoke",
            smoke_receipt,
            fixture_parent=self.fixture_parent,
        )
        closeout["fixture_smoke"] = smoke
        if not product_tasks_allowed(smoke):
            report_commit = self._commit_runtime_evidence(
                ancestry, smoke, lanes, budget
            )
            closeout.update({
                "status": (
                    "BLOCKED_MODEL_TIER_ROUTER_DOGFOOD_R3_EXTERNAL_"
                    "WRITABLE_SMOKE_FAILED"
                ),
                "harness_report_commit": {"commit": report_commit},
                "hard_stop_code": smoke.get("failure_class", "WRITABLE_SMOKE_FAILED"),
                "remaining_blockers": [
                    smoke.get("failure_class", "WRITABLE_SMOKE_FAILED")
                ],
                "child_process_starts_used": budget.os_child_process_started,
                "model_execution_count": budget.model_execution_observed,
                "usage_totals": _usage_totals(lanes, smoke),
                "worktree_pool_final_state": _pool_state(
                    contract["paths"]["worktree_pool"],
                    [
                        entry["path"]
                        for entry in contract["repositories"].values()
                    ],
                ),
                "primary_repository_final_states": _final_repository_states(
                    contract, self.root
                ),
            })
            return self._finish(closeout, 3)

        lane_error = ""
        for descriptor in contract["cases"]:
            if not next_product_lane_allowed(lanes):
                break
            try:
                lane = execute_lane(
                    contract,
                    descriptor,
                    budget,
                    self.launcher,
                    self._guard,
                    self.executable_resolver,
                    self.root,
                    assessor=self.assessor,
                )
                lanes.append(lane)
                if not lane["accepted"]:
                    lane_error = str(lane["final_status"])
            except (ContractError, GitContractError, RuntimeError) as exc:
                lane_error = str(exc) if str(exc).isupper() else "PRODUCT_LANE_FAILED"
                break

        report_commit = self._commit_runtime_evidence(
            ancestry, smoke, lanes, budget
        )
        final_states = _final_repository_states(contract, self.root)
        pool = _pool_state(
            contract["paths"]["worktree_pool"],
            [entry["path"] for entry in contract["repositories"].values()],
        )
        control = _verify_control(contract)
        by_case = {lane["case_id"]: lane for lane in lanes}
        mtr_lane = by_case.get("mtr-docs-private-executor-r1", {})
        expected_mtr_head = (
            mtr_lane.get("target_commit")
            if mtr_lane.get("automatic_merge")
            else contract["repositories"]["model-tier-router"]["baseline_head"]
        )
        target_invariants = bool(
            final_states["targets"]["model-tier-router"]["branch"]
            == contract["repositories"]["model-tier-router"]["branch"]
            and final_states["targets"]["model-tier-router"]["head"]
            == expected_mtr_head
            and final_states["targets"]["qwen-redaction-standalone"]["branch"]
            == contract["repositories"]["qwen-redaction-standalone"]["branch"]
            and final_states["targets"]["qwen-redaction-standalone"]["head"]
            == contract["repositories"]["qwen-redaction-standalone"]["baseline_head"]
            and not any(
                item["locks"] or item["active_operations"]
                for item in final_states["targets"].values()
            )
        )
        merge_blocker = next(
            (
                lane["merge_blocked"]
                for lane in lanes
                if lane.get("merge_blocked")
            ),
            "",
        )
        runtime_blocker = lane_error or merge_blocker
        if (
            not final_states["harness"]["clean"]
            or final_states["harness"]["branch"] != "main"
            or final_states["harness"]["remote_count"] != 0
            or final_states["harness"]["locks"]
            or final_states["harness"]["active_operations"]
            or pool["entry_count"] != 0
            or pool["registered_worktree_count"] != 0
            or not all(item["clean"] for item in final_states["targets"].values())
            or not target_invariants
            or not control["unchanged"]
        ):
            closeout["status"] = (
                "BLOCKED_MODEL_TIER_ROUTER_DOGFOOD_R3_EXTERNAL_"
                "CONTRACT_OR_FINAL_INVARIANT"
            )
            closeout["hard_stop_code"] = "FINAL_INVARIANT_VIOLATION"
            exit_code = 6
        elif runtime_blocker:
            closeout["status"] = (
                "BLOCKED_MODEL_TIER_ROUTER_DOGFOOD_R3_EXTERNAL_AFTER_FIXTURE_SMOKE"
                if not lanes else
                "PARTIAL_MODEL_TIER_ROUTER_DOGFOOD_R3_EXTERNAL_"
                "WRITABLE_SMOKE_PASSED_REAL_LANES_INCOMPLETE"
            )
            closeout["hard_stop_code"] = runtime_blocker
            exit_code = 4 if not lanes else 5
        elif len(lanes) == 2 and all(lane["accepted"] for lane in lanes):
            closeout["status"] = (
                "PASS_MODEL_TIER_ROUTER_DOGFOOD_R3_EXTERNAL_"
                "WRITABLE_SMOKE_AND_TWO_REAL_LANES_VERIFIED"
            )
            closeout["hard_stop_code"] = ""
            exit_code = 0
        else:
            closeout["status"] = (
                "PARTIAL_MODEL_TIER_ROUTER_DOGFOOD_R3_EXTERNAL_"
                "WRITABLE_SMOKE_PASSED_REAL_LANES_INCOMPLETE"
            )
            closeout["hard_stop_code"] = ""
            exit_code = 5

        closeout.update({
            "fixture_smoke": smoke,
            "child_process_starts_used": budget.os_child_process_started,
            "model_execution_count": budget.model_execution_observed,
            "model_tier_router_lane": by_case.get(
                "mtr-docs-private-executor-r1", {}
            ),
            "qwen_redaction_lane": by_case.get(
                "qwen-docx-hidden-elements-r1", {}
            ),
            "router_decisions": [lane["decision"] for lane in lanes],
            "usage_totals": _usage_totals(lanes, smoke),
            "escalation_results": {
                lane["case_id"]: {
                    "eligible": lane["escalation_eligible"],
                    "count": lane["escalation_count"],
                }
                for lane in lanes
            },
            "existing_control_unchanged": control["unchanged"],
            "target_commits_created": [
                lane["target_commit"] for lane in lanes if lane["target_commit"]
            ],
            "target_branches_retained": [
                lane["branch_retained"] for lane in lanes if lane["branch_retained"]
            ],
            "automatic_merges": [
                lane["target_commit"] for lane in lanes if lane["automatic_merge"]
            ],
            "harness_report_commit": {"commit": report_commit},
            "primary_repository_final_states": final_states,
            "worktree_pool_final_state": pool,
            "remaining_review_items": [
                lane["branch_retained"]
                for lane in lanes
                if lane["repository"] == "qwen-redaction-standalone"
                and lane["branch_retained"]
            ],
            "remaining_blockers": [runtime_blocker] if runtime_blocker else [],
        })
        return self._finish(closeout, exit_code)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", required=True)
    parser.add_argument("--closeout", required=True)
    parser.add_argument("--runner-pid", required=True, type=int)
    arguments = parser.parse_args(argv)
    try:
        runner = ExternalRunner(
            arguments.contract, arguments.closeout, arguments.runner_pid
        )
        closeout, exit_code = runner.run()
    except (ContractError, GitContractError, RuntimeError, OSError) as exc:
        closeout = _empty_closeout({
            "maximum_new_codex_exec_process_starts": 5
        })
        closeout.update({
            "status": (
                "BLOCKED_MODEL_TIER_ROUTER_DOGFOOD_R3_EXTERNAL_"
                "CONTRACT_OR_FINAL_INVARIANT"
            ),
            "hard_stop_code": (
                str(exc) if str(exc).isupper() else "RUNTIME_CONTRACT_VIOLATION"
            ),
            "remaining_blockers": [
                str(exc) if str(exc).isupper() else "RUNTIME_CONTRACT_VIOLATION"
            ],
        })
        exit_code = 6
        expected = (
            harness_root() / "reports" / "pilot-r3-closeout.json"
        ).resolve()
        candidate = Path(arguments.closeout).resolve()
        if same_path(candidate, expected):
            write_json(candidate, closeout)
    sys.stdout.write(canonical_json_bytes(closeout).decode("utf-8") + "\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
