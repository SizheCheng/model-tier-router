"""Deterministic advisory capability-profile router."""

from .api import assess
from .compat.legacy import assess_mapping
from .governed import (
    ApprovalResult,
    DispatchBindingResult,
    GovernedRouter,
    ReceiptResult,
    RouterPorts,
    ValidationResult,
    route_mapping,
)
from .strict_json import (
    DuplicateKeyError,
    JSONResourceLimitError,
    canonical_json_bytes,
    strict_json_loads,
)

__all__ = [
    "ApprovalResult", "DispatchBindingResult", "DuplicateKeyError",
    "GovernedRouter", "JSONResourceLimitError", "ReceiptResult", "RouterPorts",
    "ValidationResult", "assess", "assess_mapping", "canonical_json_bytes",
    "route_mapping", "strict_json_loads",
]
