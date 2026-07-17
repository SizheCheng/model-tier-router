"""Strict offline validation for the JSON Schema subset used by this project."""

from __future__ import annotations

import re
import sysconfig
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any, Mapping

from .strict_json import strict_json_loads


class SchemaValidationError(ValueError):
    """A non-sensitive schema failure with a stable location and keyword."""

    def __init__(self, path: str, keyword: str, member: str | None = None) -> None:
        self.path = path
        self.keyword = keyword
        self.member = member
        suffix = f":{member}" if member is not None else ""
        super().__init__(f"{path}:{keyword}{suffix}")


_ANNOTATION_KEYWORDS = {
    "$comment", "$id", "$schema", "default", "description", "examples", "title"
}
_ASSERTION_KEYWORDS = {
    "additionalProperties", "allOf", "anyOf", "const", "else", "enum", "if",
    "items", "maxItems", "maxLength", "maximum", "minItems", "minLength",
    "minimum", "not", "oneOf", "pattern", "properties", "required", "then",
    "type", "uniqueItems",
}
_SUPPORTED_KEYWORDS = _ANNOTATION_KEYWORDS | _ASSERTION_KEYWORDS

_VALIDATION_PORT_RESULT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "accepted", "obligation", "supervised_full_suite_required", "code",
    ],
    "properties": {
        "accepted": {"type": "boolean"},
        "obligation": {
            "type": "string",
            "enum": [
                "not_required", "conditional", "conditional_supervised", "required",
            ],
        },
        "supervised_full_suite_required": {"type": "boolean"},
        "code": {
            "type": "string",
            "pattern": "^(?:|[A-Z][A-Z0-9_]*)$",
        },
    },
}
_SCHEMA_PATHS = {
    "advisory-decision.schema.json": "schemas/advisory-decision.schema.json",
    "advisory-request.schema.json": "schemas/advisory-request.schema.json",
    "capability-profile.schema.json": "schemas/capability-profile.schema.json",
    "policy.schema.json": "schemas/policy.schema.json",
    "router-assessment.schema.json": "schemas/governed/router-assessment.schema.json",
    "router-decision.schema.json": "schemas/governed/router-decision.schema.json",
    "task-envelope.schema.json": "schemas/governed/task-envelope.schema.json",
}
_PROJECT_SCHEMA_NAMES = frozenset(_SCHEMA_PATHS)



def validate(instance: Any, schema: Mapping[str, Any], path: str = "$") -> None:
    """Validate an instance without network access or third-party dependencies."""

    _check_schema_definition(schema, path)
    if not isinstance(schema, Mapping):
        raise SchemaValidationError(path, "invalid_schema")
    unsupported = set(schema) - _SUPPORTED_KEYWORDS
    if unsupported:
        raise SchemaValidationError(path, "unsupported_schema_keyword", sorted(unsupported)[0])

    if "type" in schema:
        allowed = schema["type"]
        names = allowed if isinstance(allowed, list) else [allowed]
        if not names or not all(isinstance(name, str) for name in names):
            raise SchemaValidationError(path, "invalid_schema_type")
        if not any(_matches_type(instance, name) for name in names):
            raise SchemaValidationError(path, "type")

    if "const" in schema and not _json_equal(instance, schema["const"]):
        raise SchemaValidationError(path, "const")
    if "enum" in schema:
        values = schema["enum"]
        if not isinstance(values, list) or not any(_json_equal(instance, value) for value in values):
            raise SchemaValidationError(path, "enum")

    if isinstance(instance, str):
        if len(instance) < int(schema.get("minLength", 0)):
            raise SchemaValidationError(path, "minLength")
        if "maxLength" in schema and len(instance) > int(schema["maxLength"]):
            raise SchemaValidationError(path, "maxLength")
        if "pattern" in schema and re.search(str(schema["pattern"]), instance) is None:
            raise SchemaValidationError(path, "pattern")

    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            raise SchemaValidationError(path, "minimum")
        if "maximum" in schema and instance > schema["maximum"]:
            raise SchemaValidationError(path, "maximum")

    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < int(schema["minItems"]):
            raise SchemaValidationError(path, "minItems")
        if "maxItems" in schema and len(instance) > int(schema["maxItems"]):
            raise SchemaValidationError(path, "maxItems")
        if schema.get("uniqueItems") is True:
            for index, item in enumerate(instance):
                if any(_json_equal(item, previous) for previous in instance[:index]):
                    raise SchemaValidationError(path, "uniqueItems", str(index))
        if "items" in schema:
            for index, item in enumerate(instance):
                validate(item, schema["items"], f"{path}[{index}]")

    if isinstance(instance, dict):
        required = schema.get("required", [])
        if not isinstance(required, list) or not all(isinstance(key, str) for key in required):
            raise SchemaValidationError(path, "invalid_schema_required")
        for key in required:
            if key not in instance:
                raise SchemaValidationError(path, "required", key)
        properties = schema.get("properties", {})
        if not isinstance(properties, Mapping):
            raise SchemaValidationError(path, "invalid_schema_properties")
        additional = schema.get("additionalProperties", True)
        unknown = set(instance) - set(properties)
        if additional is False and unknown:
            raise SchemaValidationError(path, "additionalProperties", sorted(unknown)[0])
        if isinstance(additional, Mapping):
            for key in unknown:
                validate(instance[key], additional, f"{path}.{key}")
        elif additional not in {True, False}:
            raise SchemaValidationError(path, "invalid_schema_additionalProperties")
        for key, subschema in properties.items():
            if key in instance:
                validate(instance[key], subschema, f"{path}.{key}")

    for subschema in schema.get("allOf", []):
        validate(instance, subschema, path)
    if "anyOf" in schema:
        branches = schema["anyOf"]
        if not isinstance(branches, list) or not branches:
            raise SchemaValidationError(path, "anyOf")
        branch_matches = [
            _matches_schema(instance, branch, path) for branch in branches
        ]
        if not any(branch_matches):
            raise SchemaValidationError(path, "anyOf")
    if "oneOf" in schema:
        branches = schema["oneOf"]
        if not isinstance(branches, list) or sum(
            _matches_schema(instance, branch, path) for branch in branches
        ) != 1:
            raise SchemaValidationError(path, "oneOf")
    if "not" in schema and _matches_schema(instance, schema["not"], path):
        raise SchemaValidationError(path, "not")
    if "if" in schema:
        branch = "then" if _matches_schema(instance, schema["if"], path) else "else"
        if branch in schema:
            validate(instance, schema[branch], path)


def _check_schema_definition(
    schema: object,
    path: str,
    seen: set[int] | None = None,
) -> None:
    if not isinstance(schema, Mapping):
        raise SchemaValidationError(path, "invalid_schema")
    active = set() if seen is None else seen
    identity = id(schema)
    if identity in active:
        raise SchemaValidationError(path, "invalid_schema_cycle")
    active.add(identity)
    try:
        unsupported = set(schema) - _SUPPORTED_KEYWORDS
        if unsupported:
            raise SchemaValidationError(
                path,
                "unsupported_schema_keyword",
                sorted(unsupported)[0],
            )
        properties = schema.get("properties", {})
        if not isinstance(properties, Mapping):
            raise SchemaValidationError(path, "invalid_schema_properties")
        for name, subschema in properties.items():
            if not isinstance(name, str):
                raise SchemaValidationError(path, "invalid_schema_property_name")
            _check_schema_definition(subschema, f"{path}.properties.{name}", active)

        if "additionalProperties" in schema:
            additional = schema["additionalProperties"]
            if isinstance(additional, Mapping):
                _check_schema_definition(
                    additional,
                    f"{path}.additionalProperties",
                    active,
                )
            elif not isinstance(additional, bool):
                raise SchemaValidationError(
                    path,
                    "invalid_schema_additionalProperties",
                )

        if "items" in schema:
            _check_schema_definition(schema["items"], f"{path}.items", active)

        for keyword in ("allOf", "anyOf", "oneOf"):
            if keyword not in schema:
                continue
            branches = schema[keyword]
            if not isinstance(branches, list) or not branches:
                raise SchemaValidationError(path, f"invalid_schema_{keyword}")
            for index, branch in enumerate(branches):
                _check_schema_definition(
                    branch,
                    f"{path}.{keyword}[{index}]",
                    active,
                )

        for keyword in ("not", "if", "then", "else"):
            if keyword in schema:
                _check_schema_definition(
                    schema[keyword],
                    f"{path}.{keyword}",
                    active,
                )
    finally:
        active.remove(identity)

def _matches_schema(instance: Any, schema: Mapping[str, Any], path: str) -> bool:
    try:
        validate(instance, schema, path)
    except SchemaValidationError as exc:
        if exc.keyword.startswith("invalid_schema") or exc.keyword in {
            "schema_object_required",
            "unsupported_schema_keyword",
        }:
            raise
        return False
    return True


def _json_equal(left: Any, right: Any) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return left == right
    if type(left) is not type(right):
        return False
    if isinstance(left, list):
        return len(left) == len(right) and all(_json_equal(a, b) for a, b in zip(left, right))
    if isinstance(left, dict):
        return set(left) == set(right) and all(_json_equal(left[key], right[key]) for key in left)
    return left == right


def _matches_type(value: Any, name: str) -> bool:
    return {
        "null": value is None,
        "boolean": isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "string": isinstance(value, str),
        "array": isinstance(value, list),
        "object": isinstance(value, dict),
    }.get(name, False)


@lru_cache(maxsize=None)
def load_project_schema(name: str) -> Mapping[str, Any]:
    if name not in _PROJECT_SCHEMA_NAMES:
        raise ValueError("unknown project schema")
    path = Path(__file__).resolve().parents[2] / _SCHEMA_PATHS[name]
    if path.is_file():
        raw = path.read_bytes()
    else:
        try:
            raw = (
                resources.files("model_tier_router")
                .joinpath("data", "schemas", name)
                .read_bytes()
            )
        except FileNotFoundError:
            installed = (
                Path(sysconfig.get_path("data"))
                / "model_tier_router"
                / "data"
                / "schemas"
                / name
            )
            raw = installed.read_bytes()
    payload = strict_json_loads(raw)
    if not isinstance(payload, dict):
        raise SchemaValidationError("$", "schema_object_required")
    return payload


def validate_task_envelope(instance: Any) -> None:
    validate(instance, load_project_schema("task-envelope.schema.json"))


def validate_advisory_request(instance: Any) -> None:
    validate(instance, load_project_schema("advisory-request.schema.json"))


def validate_advisory_decision(instance: Any) -> None:
    validate(instance, load_project_schema("advisory-decision.schema.json"))


def validate_capability_profile(instance: Any) -> None:
    validate(instance, load_project_schema("capability-profile.schema.json"))


def validate_policy(instance: Any) -> None:
    validate(instance, load_project_schema("policy.schema.json"))


def validate_router_assessment(instance: Any) -> None:
    validate(instance, load_project_schema("router-assessment.schema.json"))


def validate_router_decision(instance: Any) -> None:
    validate(instance, load_project_schema("router-decision.schema.json"))


def validate_validation_port_result(instance: Any) -> None:
    """Validate the complete four-field public validation verifier result."""

    validate(instance, _VALIDATION_PORT_RESULT_SCHEMA)



__all__ = [
    "SchemaValidationError", "load_project_schema", "validate",
    "validate_advisory_decision", "validate_advisory_request",
    "validate_capability_profile", "validate_policy",
    "validate_router_assessment", "validate_router_decision",
    "validate_task_envelope",
    "validate_validation_port_result",
]
