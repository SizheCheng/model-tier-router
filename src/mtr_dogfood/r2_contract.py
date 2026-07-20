from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import is_contained
from .router_adapter import validate_decision


ROUTE_ID = "MODEL_TIER_ROUTER_DOGFOOD_R2_HARNESS_REPAIR_AND_TWO_LANE_REAL_RUNS"
CONTROL_BRANCH = (
    "mtr-dogfood/mtr-docs-private-executor-r1/fixed_premium_control-1"
)
CONTROL_COMMIT = "e544cb7ee7497aa7706a06ef4aa55bfcf18bcca1"


class PayloadValidationError(ValueError):
    """Raised before a child process starts when an internal payload is invalid."""


@dataclass
class InvocationBudget:
    maximum: int = 5
    process_starts: int = 0
    pre_model_payload_rejections: int = 0

    @property
    def remaining(self) -> int:
        return self.maximum - self.process_starts

    def require_available(self) -> None:
        if self.remaining <= 0:
            raise RuntimeError("CHILD_INVOCATION_LIMIT_REACHED")

    def record_process_start(self) -> None:
        self.require_available()
        self.process_starts += 1

    def record_payload_rejection(self) -> None:
        self.pre_model_payload_rejections += 1


def validate_instance(value: Any, schema: dict[str, Any], location: str = "$") -> None:
    expected = schema.get("type")
    if expected is not None and not _matches_type(value, expected):
        raise PayloadValidationError(f"{location}: expected {expected}")
    if "const" in schema and value != schema["const"]:
        raise PayloadValidationError(f"{location}: const mismatch")
    if "enum" in schema and value not in schema["enum"]:
        raise PayloadValidationError(f"{location}: enum mismatch")
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        missing = [name for name in required if name not in value]
        if missing:
            raise PayloadValidationError(f"{location}: missing fields {sorted(missing)}")
        if schema.get("additionalProperties") is False:
            unknown = sorted(set(value) - set(properties))
            if unknown:
                raise PayloadValidationError(f"{location}: unknown fields {unknown}")
        for name, child in value.items():
            if name in properties:
                validate_instance(child, properties[name], f"{location}.{name}")
    elif isinstance(value, list) and isinstance(schema.get("items"), dict):
        for index, child in enumerate(value):
            validate_instance(child, schema["items"], f"{location}[{index}]")


def _matches_type(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "null":
        return value is None
    return False


def validate_codex_output_schema(schema: dict[str, Any]) -> None:
    unsupported = {"$schema", "const", "minLength", "uniqueItems"}

    def walk(node: Any, location: str) -> None:
        if isinstance(node, dict):
            bad = sorted(unsupported.intersection(node))
            if bad:
                raise PayloadValidationError(
                    f"{location}: unsupported schema keywords {bad}"
                )
            if "enum" in node and "type" not in node:
                raise PayloadValidationError(f"{location}: enum requires explicit type")
            node_type = node.get("type")
            if node_type == "object":
                properties = node.get("properties")
                required = node.get("required")
                if not isinstance(properties, dict) or node.get("additionalProperties") is not False:
                    raise PayloadValidationError(f"{location}: object schema must be closed")
                if sorted(required or []) != sorted(properties):
                    raise PayloadValidationError(
                        f"{location}: every object property must be required"
                    )
            for key, child in node.items():
                walk(child, f"{location}.{key}")
        elif isinstance(node, list):
            for index, child in enumerate(node):
                walk(child, f"{location}[{index}]")

    if not isinstance(schema, dict) or schema.get("type") != "object":
        raise PayloadValidationError("$: final output schema must be an object schema")
    walk(schema, "$")


def validate_launch_payloads(
    task: dict[str, Any],
    task_schema: dict[str, Any],
    authority: dict[str, Any],
    authority_schema: dict[str, Any],
    decision: dict[str, Any],
    output_schema: dict[str, Any],
    known_profiles: set[str],
) -> dict[str, Any]:
    validate_instance(task, task_schema)
    validate_instance(authority, authority_schema)
    decision_payload = {
        key: child
        for key, child in decision.items()
        if key != "dogfood_decision_digest"
    }
    validated_decision = validate_decision(decision_payload, known_profiles)
    validate_codex_output_schema(output_schema)
    return validated_decision


def validate_child_transport(
    worktree: str | Path,
    command: list[str],
    prompt: str,
    forbidden_paths: list[str | Path],
) -> None:
    root = Path(worktree).resolve()
    for match in re.findall(r"(?i)\b[a-z]:[\\/][^\s\"'<>|]+", prompt):
        candidate = match.rstrip(".,;:)]}")
        if not is_contained(root, candidate):
            raise PayloadValidationError("child prompt contains a path outside the worktree")
    if "--add-dir" in command:
        raise PayloadValidationError("child command contains an additional writable directory")
    for flag in ("-C", "--output-schema", "--output-last-message"):
        if flag not in command:
            raise PayloadValidationError(f"child command is missing {flag}")
        index = command.index(flag)
        if index + 1 >= len(command) or not is_contained(root, command[index + 1]):
            raise PayloadValidationError(f"child {flag} path is outside the worktree")
    combined = "\n".join([prompt, *command]).casefold()
    for path in forbidden_paths:
        normalized = str(Path(path).resolve()).replace("/", "\\").rstrip("\\").casefold()
        slash = normalized.replace("\\", "/")
        backslash_combined = combined.replace("/", "\\")
        slash_combined = combined.replace("\\", "/")
        if (
            normalized + "\\" in backslash_combined
            or slash + "/" in slash_combined
            or any(
                token.replace("/", "\\").rstrip("\\").casefold() == normalized
                for token in command
            )
        ):
            raise PayloadValidationError("child transport contains an external repository path")


def final_output_valid(path: str | Path, schema: dict[str, Any]) -> bool:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        validate_instance(value, schema)
    except (OSError, UnicodeError, json.JSONDecodeError, PayloadValidationError):
        return False
    return True


def classify_attempt(
    execution: dict[str, Any],
    changed_paths: list[str],
    automated_acceptance: bool | None = None,
) -> str | None:
    infrastructure = execution.get("infrastructure_failure_class")
    if infrastructure:
        return str(infrastructure)
    if not execution.get("model_execution_observed"):
        return "DEPENDENCY_OR_ENVIRONMENT_FAILURE"
    if not changed_paths:
        return "IMPLEMENTATION_INCOMPLETE"
    if automated_acceptance is False:
        return "VALIDATOR_FAILURE_AFTER_SUCCESSFUL_MODEL_RUN"
    return None


def classify_child_claim(value: dict[str, Any]) -> str | None:
    if value.get("status") not in {"blocked", "failed"}:
        return None
    text = " ".join(
        [
            str(value.get("summary", "")),
            *[str(item) for item in value.get("notes", [])],
        ]
    )
    if re.search(
        r"read[- ]only(?: filesystem| sandbox)?|workspace filesystem is read-only|"
        r"write access .* required",
        text,
        re.I,
    ):
        return "HOST_POLICY_REJECTED_CHILD_FILESYSTEM_ACCESS"
    return None


def assert_control_action_allowed(action: str) -> None:
    if action in {"rerun", "merge", "modify"}:
        raise RuntimeError("UNAUTHORIZED_CONTROL_RERUN_OR_MERGE")


def validate_r2_repository_scope(settings: dict[str, Any]) -> None:
    expected = {"model-tier-router", "qwen-redaction-standalone"}
    actual = set(settings.get("repositories", {}))
    if actual != expected:
        raise PayloadValidationError("R2 repository scope is not the exact two-repository allowlist")
    forbidden_names = {"canonical-memories", "shortage-B", "qwen", "trading-authority-OS"}
    if forbidden_names.intersection(actual):
        raise PayloadValidationError("out-of-scope repository is present in R2 final gates")
