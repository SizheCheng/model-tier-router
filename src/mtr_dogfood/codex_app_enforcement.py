from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


COMPONENT_ID = "MTR_CODEX_APP_DEVELOPMENT_DATA_R1"
SCHEMA_VERSION = "1.0.0"
MAX_HOOK_INPUT_BYTES = 8 * 1024 * 1024
MAX_RECORD_BYTES = 512 * 1024
MAX_STRING_CHARACTERS = 16_384
MODEL_MAP = {
    "economy": "gpt-5.6-luna",
    "balanced": "gpt-5.6-terra",
    "premium": "gpt-5.6-sol",
}
SUPPORTED_EVENTS = {
    "SessionStart",
    "SubagentStart",
    "PreToolUse",
    "PermissionRequest",
    "PostToolUse",
    "PreCompact",
    "PostCompact",
    "UserPromptSubmit",
    "SubagentStop",
    "Stop",
}
RECORD_REQUIRED_FIELDS = {
    "schema_version",
    "component_id",
    "event_id",
    "recorded_at_utc",
    "hook_event_name",
    "session_id",
    "turn_id",
    "cwd",
    "model",
    "permission_mode",
    "development",
    "redacted_or_truncated",
    "details",
    "record_sha256",
}
RECORD_ALLOWED_FIELDS = RECORD_REQUIRED_FIELDS | {"router_assessment", "coverage"}
DEVELOPMENT_TERMS = (
    "implement",
    "implementation",
    "code",
    "coding",
    "debug",
    "fix",
    "build",
    "test",
    "refactor",
    "deploy",
    "repository",
    "repo",
    "commit",
    "pull request",
    "migration",
    "component",
    "开发",
    "代码",
    "编程",
    "调试",
    "修复",
    "构建",
    "测试",
    "重构",
    "部署",
    "仓库",
    "提交",
    "组件",
    "产品",
)
ADVANCED_TERMS = (
    "architecture",
    "security",
    "migration",
    "cross-repo",
    "production",
    "release",
    "root cause",
    "threat model",
    "深入",
    "架构",
    "安全",
    "迁移",
    "跨仓库",
    "生产",
    "发布",
    "全产品",
    "根因",
)
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE | re.DOTALL),
    re.compile(r"\b(?:sk|rk|pk)-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]{16,}\b", re.IGNORECASE),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}\b", re.IGNORECASE),
    re.compile(
        r"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|secret)\b"
        r"(\s*[:=]\s*)"
        r"((?!\[REDACTED\])[^\s,;\]\}\)\"']{4,}|"
        r"\"(?!\[REDACTED\]\")[^\"]{4,}\"|"
        r"'(?!\[REDACTED\]')[^']{4,}')"
    ),
    re.compile(r"(?i)(https?://)([^/@\s:]+):([^/@\s]+)@"),
)


class CodexAppEnforcementError(RuntimeError):
    pass


def _canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8", errors="strict")


def _strict_json(raw: bytes) -> Any:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise CodexAppEnforcementError("HOOK_INPUT_DUPLICATE_KEY")
            result[key] = value
        return result

    def constant(value: str) -> Any:
        raise CodexAppEnforcementError(f"HOOK_INPUT_NON_FINITE:{value}")

    try:
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_constant=constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CodexAppEnforcementError("HOOK_INPUT_INVALID_JSON") from exc


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _redact_text(value: str) -> tuple[str, bool]:
    result = value
    changed = False
    for pattern in SECRET_PATTERNS:
        if pattern.pattern.startswith("(?i)(https?"):
            updated, count = pattern.subn(r"\1[REDACTED]@", result)
        elif "api[_-]?key" in pattern.pattern:
            updated, count = pattern.subn(r"\1\2[REDACTED]", result)
        else:
            updated, count = pattern.subn("[REDACTED]", result)
        result = updated
        changed = changed or count > 0
    if len(result) > MAX_STRING_CHARACTERS:
        result = result[:MAX_STRING_CHARACTERS] + "\n[TRUNCATED]"
        changed = True
    return result, changed


def _bounded_value(value: Any, *, depth: int = 0) -> tuple[Any, bool]:
    if depth > 8:
        return "[DEPTH_LIMIT]", True
    if value is None or type(value) in {bool, int}:
        return value, False
    if isinstance(value, float):
        return "[NON_INTEGER_NUMBER]", True
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, list):
        changed = len(value) > 64
        output: list[Any] = []
        for item in value[:64]:
            child, child_changed = _bounded_value(item, depth=depth + 1)
            output.append(child)
            changed = changed or child_changed
        return output, changed
    if isinstance(value, dict):
        keys = sorted((str(key) for key in value), key=str.casefold)
        changed = len(keys) > 64 or any(key not in value for key in keys)
        output: dict[str, Any] = {}
        for key in keys[:64]:
            child, child_changed = _bounded_value(value[key], depth=depth + 1)
            output[key] = child
            changed = changed or child_changed
        return output, changed
    return f"[UNSUPPORTED_TYPE:{type(value).__name__}]", True


def _safe_identifier(value: Any, *, fallback: str) -> str:
    if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9._-]{1,160}", value):
        return value
    digest = hashlib.sha256(str(value).encode("utf-8", errors="replace")).hexdigest()
    return f"{fallback}-{digest[:24]}"


def _is_repository_context(cwd: str) -> bool:
    try:
        current = Path(cwd).resolve(strict=False)
    except (OSError, RuntimeError):
        return False
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return True
    return False


def classify_development(prompt: str, cwd: str) -> bool:
    folded = prompt.casefold()
    return _is_repository_context(cwd) or any(
        term.casefold() in folded for term in DEVELOPMENT_TERMS
    )


def _reasoning_class(prompt: str) -> str:
    folded = prompt.casefold()
    if len(prompt.encode("utf-8", errors="replace")) > 4_000:
        return "advanced"
    if any(term.casefold() in folded for term in ADVANCED_TERMS):
        return "advanced"
    return "standard"


def _router_assessment(event: dict[str, Any], prompt: str) -> dict[str, Any]:
    try:
        from model_tier_router import assess
    except Exception as exc:
        raise CodexAppEnforcementError("ROUTER_RUNTIME_UNAVAILABLE") from exc
    session = _safe_identifier(event.get("session_id"), fallback="session")
    turn = _safe_identifier(event.get("turn_id"), fallback="turn")
    request = {
        "schema_version": "model_tier_router_advisory_request_v1alpha1",
        "request_id": f"codex-app-{session[:48]}-{turn[:48]}",
        "requirements": {
            "reasoning_class": _reasoning_class(prompt),
            "modalities": ["text"],
            "tool_support": True,
            "structured_output_support": True,
            "maximum_cost_class": "high",
            "privacy_class": "restricted",
            "deployment_boundary": "local",
        },
        "preferences": ["lower_cost", "lower_latency", "higher_reasoning"],
        "evidence": {
            "deployment_boundary": True,
            "modalities": True,
            "privacy": True,
            "structured_output": True,
            "tool_support": True,
        },
    }
    decision = assess(request)
    if (
        not isinstance(decision, dict)
        or decision.get("status") != "recommended"
        or decision.get("selected_profile") not in MODEL_MAP
        or decision.get("execution_authorized") is not False
        or decision.get("authorized_write_scope") != []
    ):
        raise CodexAppEnforcementError("ROUTER_DECISION_NOT_RECOMMENDED")
    profile = str(decision["selected_profile"])
    active_model = str(event.get("model", ""))
    recommended_model = MODEL_MAP[profile]
    return {
        "request": request,
        "decision": decision,
        "recommended_model": recommended_model,
        "active_model": active_model,
        "active_model_matches_recommendation": active_model == recommended_model,
    }


def _event_directory(data_root: Path, event: dict[str, Any]) -> Path:
    session = _safe_identifier(event.get("session_id"), fallback="session")
    turn = _safe_identifier(event.get("turn_id"), fallback="session-scope")
    target = (data_root / "events" / session / turn).resolve(strict=False)
    try:
        target.relative_to(data_root.resolve(strict=False))
    except ValueError as exc:
        raise CodexAppEnforcementError("DATA_PATH_ESCAPE") from exc
    return target


def _load_turn_records(data_root: Path, event: dict[str, Any]) -> list[dict[str, Any]]:
    directory = _event_directory(data_root, event)
    if not directory.is_dir():
        return []
    records: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json")):
        try:
            value = _strict_json(path.read_bytes())
        except (OSError, CodexAppEnforcementError):
            continue
        if isinstance(value, dict) and value.get("component_id") == COMPONENT_ID:
            records.append(value)
    return records


def _development_for_event(data_root: Path, event: dict[str, Any]) -> bool:
    if event.get("hook_event_name") == "UserPromptSubmit":
        prompt = event.get("prompt")
        return isinstance(prompt, str) and classify_development(
            prompt, str(event.get("cwd", ""))
        )
    records = _load_turn_records(data_root, event)
    if any(record.get("development") is True for record in records):
        return True
    return _is_repository_context(str(event.get("cwd", "")))


def _event_details(event: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    common = {
        "transcript_path": event.get("transcript_path"),
    }
    specific_fields = {
        "SessionStart": ("source",),
        "SubagentStart": ("agent_id", "agent_type"),
        "PreToolUse": ("tool_name", "tool_use_id", "tool_input"),
        "PermissionRequest": ("tool_name", "tool_input"),
        "PostToolUse": ("tool_name", "tool_use_id", "tool_input", "tool_response"),
        "PreCompact": ("trigger",),
        "PostCompact": ("trigger",),
        "UserPromptSubmit": ("prompt",),
        "SubagentStop": (
            "agent_id",
            "agent_type",
            "agent_transcript_path",
            "stop_hook_active",
            "last_assistant_message",
        ),
        "Stop": ("stop_hook_active", "last_assistant_message"),
    }
    for field in specific_fields.get(str(event.get("hook_event_name")), ()):
        common[field] = event.get(field)
    bounded, changed = _bounded_value(common)
    if not isinstance(bounded, dict):
        raise CodexAppEnforcementError("HOOK_DETAIL_SANITIZATION_FAILED")
    bounded_raw = _canonical_json_bytes(bounded)
    if len(bounded_raw) > MAX_RECORD_BYTES // 2:
        compacted: dict[str, Any] = {
            "details_compacted": True,
            "details_sha256": _sha256_bytes(bounded_raw),
            "details_bytes": len(bounded_raw),
        }
        for field in (
            "source",
            "agent_id",
            "agent_type",
            "tool_name",
            "tool_use_id",
            "trigger",
            "stop_hook_active",
        ):
            if field in bounded:
                compacted[field] = bounded[field]
        bounded = compacted
        changed = True
    return bounded, changed


def _turn_coverage(records: Iterable[dict[str, Any]], event: dict[str, Any]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    development = False
    for record in records:
        name = str(record.get("hook_event_name", ""))
        counts[name] = counts.get(name, 0) + 1
        development = development or record.get("development") is True
    final_message = event.get("last_assistant_message")
    final_present = isinstance(final_message, str) and bool(final_message.strip())
    prompt_present = counts.get("UserPromptSubmit", 0) >= 1
    return {
        "development": development,
        "prompt_captured": prompt_present,
        "final_assistant_message_captured": final_present,
        "pre_tool_events": counts.get("PreToolUse", 0),
        "post_tool_events": counts.get("PostToolUse", 0),
        "permission_request_events": counts.get("PermissionRequest", 0),
        "sufficient_for_router_dogfood": (
            not development or (prompt_present and final_present)
        ),
    }


def _write_record(data_root: Path, record: dict[str, Any]) -> Path:
    digest_view = dict(record)
    digest_view.pop("record_sha256", None)
    record["record_sha256"] = _sha256_bytes(_canonical_json_bytes(digest_view))
    raw = _canonical_json_bytes(record)
    if len(raw) > MAX_RECORD_BYTES:
        raise CodexAppEnforcementError("EVENT_RECORD_TOO_LARGE")
    directory = _event_directory(data_root, record)
    directory.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    name = _safe_identifier(record.get("hook_event_name"), fallback="event")
    path = directory / f"{timestamp}-{name}-{record['event_id']}.json"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            path.unlink(missing_ok=True)
        finally:
            raise
    return path


def process_hook_event(event: dict[str, Any], data_root: str | Path) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    if not isinstance(event, dict):
        raise CodexAppEnforcementError("HOOK_INPUT_NOT_OBJECT")
    name = event.get("hook_event_name")
    if name not in SUPPORTED_EVENTS:
        raise CodexAppEnforcementError("HOOK_EVENT_UNSUPPORTED")
    for field in ("session_id", "cwd"):
        if not isinstance(event.get(field), str) or not event[field]:
            raise CodexAppEnforcementError(f"HOOK_FIELD_INVALID:{field}")
    root = Path(data_root).expanduser().resolve(strict=False)
    root.mkdir(parents=True, exist_ok=True)
    development = _development_for_event(root, event)
    details, redacted_or_truncated = _event_details(event)
    record: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "component_id": COMPONENT_ID,
        "event_id": uuid.uuid4().hex,
        "recorded_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "hook_event_name": name,
        "session_id": str(event["session_id"]),
        "turn_id": event.get("turn_id"),
        "cwd": str(event["cwd"]),
        "model": event.get("model"),
        "permission_mode": event.get("permission_mode"),
        "development": development,
        "redacted_or_truncated": redacted_or_truncated,
        "details": details,
    }
    if name == "UserPromptSubmit" and development:
        prompt = event.get("prompt")
        if not isinstance(prompt, str) or not prompt:
            raise CodexAppEnforcementError("DEVELOPMENT_PROMPT_MISSING")
        record["router_assessment"] = _router_assessment(event, prompt)
    if name in {"Stop", "SubagentStop"}:
        record["coverage"] = _turn_coverage(_load_turn_records(root, event), event)
    path = _write_record(root, record)
    receipt = {
        "event_id": record["event_id"],
        "record_sha256": record["record_sha256"],
        "record_path": str(path),
        "development": development,
    }
    response: dict[str, Any] | None = None
    if name == "SessionStart":
        response = {
            "continue": True,
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": (
                    "Managed model-tier-router dogfood collection is active for this "
                    "Codex session. Development turns must retain local, redacted route, "
                    "tool, and outcome receipts; do not bypass or disable the component."
                ),
            },
        }
    elif name == "SubagentStart":
        response = {
            "hookSpecificOutput": {
                "hookEventName": "SubagentStart",
                "additionalContext": "The managed dogfood collector also covers this subagent.",
            }
        }
    elif name == "UserPromptSubmit" and development:
        assessment = record["router_assessment"]
        profile = assessment["decision"]["selected_profile"]
        response = {
            "continue": True,
            "hookSpecificOutput": {
                "hookEventName": "UserPromptSubmit",
                "additionalContext": (
                    f"Dogfood receipt {record['event_id']} captured. Router advisory "
                    f"profile={profile}, recommended_model={assessment['recommended_model']}, "
                    f"active_model={assessment['active_model'] or 'unknown'}. The advisory "
                    "does not authorize execution or expand write scope."
                ),
            },
        }
    elif name in {"Stop", "SubagentStop"}:
        response = {"continue": True}
    return response, receipt


def _record_shape_valid(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    if set(value) - RECORD_ALLOWED_FIELDS or RECORD_REQUIRED_FIELDS - set(value):
        return False
    if value.get("schema_version") != SCHEMA_VERSION:
        return False
    if value.get("component_id") != COMPONENT_ID:
        return False
    if not isinstance(value.get("event_id"), str) or re.fullmatch(
        r"[0-9a-f]{32}", value["event_id"]
    ) is None:
        return False
    if not isinstance(value.get("recorded_at_utc"), str) or not value["recorded_at_utc"]:
        return False
    if value.get("hook_event_name") not in SUPPORTED_EVENTS:
        return False
    if not isinstance(value.get("session_id"), str) or not value["session_id"]:
        return False
    if value.get("turn_id") is not None and not isinstance(value.get("turn_id"), str):
        return False
    if not isinstance(value.get("cwd"), str) or not value["cwd"]:
        return False
    if value.get("model") is not None and not isinstance(value.get("model"), str):
        return False
    if value.get("permission_mode") is not None and not isinstance(
        value.get("permission_mode"), str
    ):
        return False
    if type(value.get("development")) is not bool:
        return False
    if type(value.get("redacted_or_truncated")) is not bool:
        return False
    if not isinstance(value.get("details"), dict):
        return False
    if "router_assessment" in value and not isinstance(value["router_assessment"], dict):
        return False
    if "coverage" in value and not isinstance(value["coverage"], dict):
        return False
    return isinstance(value.get("record_sha256"), str) and re.fullmatch(
        r"[0-9a-f]{64}", value["record_sha256"]
    ) is not None


def _verify_record(value: Any) -> bool:
    if not _record_shape_valid(value):
        return False
    recorded = value.get("record_sha256")
    view = dict(value)
    view.pop("record_sha256", None)
    return recorded == _sha256_bytes(_canonical_json_bytes(view))


def data_status(data_root: str | Path) -> dict[str, Any]:
    root = Path(data_root).expanduser().resolve(strict=False)
    records: list[dict[str, Any]] = []
    invalid_files: list[str] = []
    events_root = root / "events"
    if events_root.is_dir():
        for path in sorted(events_root.rglob("*.json")):
            try:
                value = _strict_json(path.read_bytes())
            except (OSError, UnicodeError, ValueError, RecursionError, CodexAppEnforcementError):
                invalid_files.append(str(path))
                continue
            if not _verify_record(value):
                invalid_files.append(str(path))
                continue
            records.append(value)
    event_counts: dict[str, int] = {}
    turns: dict[tuple[str, str], list[dict[str, Any]]] = {}
    router_profiles: dict[str, int] = {}
    mismatches = 0
    for record in records:
        name = str(record.get("hook_event_name", ""))
        event_counts[name] = event_counts.get(name, 0) + 1
        turn_id = record.get("turn_id")
        if isinstance(turn_id, str) and turn_id:
            turns.setdefault((str(record.get("session_id")), turn_id), []).append(record)
        assessment = record.get("router_assessment")
        if isinstance(assessment, dict):
            decision = assessment.get("decision", {})
            profile = decision.get("selected_profile") if isinstance(decision, dict) else None
            if isinstance(profile, str):
                router_profiles[profile] = router_profiles.get(profile, 0) + 1
            if assessment.get("active_model_matches_recommendation") is False:
                mismatches += 1
    development_turns = 0
    complete_turns = 0
    for values in turns.values():
        if any(item.get("development") is True for item in values):
            development_turns += 1
            names = {item.get("hook_event_name") for item in values}
            if {"UserPromptSubmit", "Stop"}.issubset(names):
                complete_turns += 1
    sessions = {str(record.get("session_id")) for record in records}
    return {
        "schema_version": SCHEMA_VERSION,
        "component_id": COMPONENT_ID,
        "status": "passed" if not invalid_files else "failed",
        "data_root": str(root),
        "record_count": len(records),
        "session_count": len(sessions),
        "turn_count": len(turns),
        "development_turn_count": development_turns,
        "complete_development_turn_count": complete_turns,
        "event_counts": event_counts,
        "router_profile_counts": router_profiles,
        "active_model_mismatch_count": mismatches,
        "invalid_record_files": invalid_files,
        "network_requests_created": 0,
        "model_requests_created": 0,
    }


def export_data(data_root: str | Path, output: str | Path) -> dict[str, Any]:
    root = Path(data_root).expanduser().resolve(strict=False)
    destination = Path(output).expanduser().resolve(strict=False)
    if destination.exists():
        raise CodexAppEnforcementError("EXPORT_TARGET_EXISTS")
    records: list[dict[str, Any]] = []
    for path in sorted((root / "events").rglob("*.json")) if (root / "events").is_dir() else []:
        value = _strict_json(path.read_bytes())
        if not _verify_record(value):
            raise CodexAppEnforcementError("EXPORT_RECORD_INTEGRITY_INVALID")
        records.append(value)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as stream:
        for record in records:
            stream.write(_canonical_json_bytes(record))
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "passed",
        "output": str(destination),
        "record_count": len(records),
        "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
        "network_requests_created": 0,
        "model_requests_created": 0,
    }


def _failure_response(event_name: str | None, reason: str, event: dict[str, Any] | None) -> dict[str, Any]:
    message = f"Managed model-tier-router dogfood enforcement failed: {reason}"
    if event_name == "PreToolUse":
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": message,
            }
        }
    if event_name == "PermissionRequest":
        return {
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {"behavior": "deny", "message": message},
            }
        }
    if event_name == "PostToolUse":
        return {"decision": "block", "reason": message}
    if event_name in {"UserPromptSubmit", "SubagentStop", "Stop"}:
        if event_name in {"SubagentStop", "Stop"} and event and event.get("stop_hook_active") is True:
            return {"continue": True, "systemMessage": message}
        return {"decision": "block", "reason": message}
    return {"continue": False, "stopReason": message, "systemMessage": message}


def _self_test() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as temporary:
        event = {
            "session_id": "self-test-session",
            "turn_id": "self-test-turn",
            "cwd": temporary,
            "hook_event_name": "UserPromptSubmit",
            "model": "gpt-5.6-terra",
            "permission_mode": "default",
            "transcript_path": None,
            "prompt": "Implement and test a small local component without network access.",
        }
        response, receipt = process_hook_event(event, temporary)
        status = data_status(temporary)
        if (
            not isinstance(response, dict)
            or status.get("status") != "passed"
            or status.get("record_count") != 1
            or not receipt.get("record_sha256")
        ):
            raise CodexAppEnforcementError("SELF_TEST_FAILED")
        return {
            "schema_version": SCHEMA_VERSION,
            "component_id": COMPONENT_ID,
            "status": "passed",
            "router_profile": status["router_profile_counts"],
            "network_requests_created": 0,
            "model_requests_created": 0,
        }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mtr-dogfood-codex-hook")
    parser.add_argument("--data-root")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--status", action="store_true")
    group.add_argument("--export")
    group.add_argument("--self-test", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.self_test:
        try:
            result = _self_test()
        except Exception as exc:
            result = {
                "schema_version": SCHEMA_VERSION,
                "component_id": COMPONENT_ID,
                "status": "failed",
                "error_type": type(exc).__name__,
                "error": str(exc),
                "network_requests_created": 0,
                "model_requests_created": 0,
            }
        sys.stdout.buffer.write(_canonical_json_bytes(result))
        return 0 if result["status"] == "passed" else 1
    if not args.data_root:
        raise SystemExit("--data-root is required")
    if args.status:
        result = data_status(args.data_root)
        sys.stdout.buffer.write(_canonical_json_bytes(result))
        return 0 if result["status"] == "passed" else 1
    if args.export:
        try:
            result = export_data(args.data_root, args.export)
        except Exception as exc:
            result = {
                "schema_version": SCHEMA_VERSION,
                "component_id": COMPONENT_ID,
                "status": "failed",
                "error_type": type(exc).__name__,
                "error": str(exc),
                "network_requests_created": 0,
                "model_requests_created": 0,
            }
        sys.stdout.buffer.write(_canonical_json_bytes(result))
        return 0 if result["status"] == "passed" else 1
    raw = sys.stdin.buffer.read(MAX_HOOK_INPUT_BYTES + 1)
    event: dict[str, Any] | None = None
    event_name: str | None = None
    try:
        if len(raw) > MAX_HOOK_INPUT_BYTES:
            raise CodexAppEnforcementError("HOOK_INPUT_TOO_LARGE")
        value = _strict_json(raw)
        if not isinstance(value, dict):
            raise CodexAppEnforcementError("HOOK_INPUT_NOT_OBJECT")
        event = value
        event_name = value.get("hook_event_name") if isinstance(value.get("hook_event_name"), str) else None
        response, _receipt = process_hook_event(value, args.data_root)
        if response is not None:
            sys.stdout.buffer.write(_canonical_json_bytes(response))
        return 0
    except Exception as exc:
        response = _failure_response(event_name, f"{type(exc).__name__}:{exc}", event)
        sys.stdout.buffer.write(_canonical_json_bytes(response))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
