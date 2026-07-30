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
from .host_dispatch import (
    HostAtomicTurnLauncher,
    HostDispatchError,
    build_atomic_launch_intent,
    build_dispatch_proposal,
    launch_atomic_turn_start,
    validate_atomic_launch_intent,
    validate_atomic_launch_receipt,
    validate_dispatch_proposal,
)
from .strict_json import (
    DuplicateKeyError,
    JSONResourceLimitError,
    canonical_json_bytes,
    strict_json_loads,
)

__all__ = [
    "ApprovalResult", "DispatchBindingResult", "DuplicateKeyError",
    "GovernedRouter", "HostAtomicTurnLauncher", "HostDispatchError",
    "JSONResourceLimitError", "ReceiptResult", "RouterPorts", "ValidationResult",
    "assess", "assess_mapping", "build_atomic_launch_intent",
    "build_dispatch_proposal", "canonical_json_bytes", "launch_atomic_turn_start",
    "route_mapping", "strict_json_loads", "validate_atomic_launch_intent",
    "validate_atomic_launch_receipt", "validate_dispatch_proposal",
]
