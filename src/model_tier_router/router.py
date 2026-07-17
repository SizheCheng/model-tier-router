"""Compatibility imports for historical model_tier_router.router users."""

from .compat.legacy import (
    ASSESSMENT_ARTIFACT_TYPE,
    ASSESSMENT_SCHEMA_VERSION,
    DECISION_SCHEMA_VERSION,
    TASK_SCHEMA_VERSION,
    assess_mapping,
)
from .governed.router import GovernedRouter, route_mapping

__all__ = [
    "ASSESSMENT_ARTIFACT_TYPE", "ASSESSMENT_SCHEMA_VERSION",
    "DECISION_SCHEMA_VERSION", "GovernedRouter", "TASK_SCHEMA_VERSION",
    "assess_mapping", "route_mapping",
]
