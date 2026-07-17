"""Optional governed compatibility API."""

from .contracts import (
    ApprovalResult,
    DispatchBindingResult,
    ReceiptResult,
    RouterPorts,
    ValidationResult,
)
from .router import GovernedRouter, route_mapping

__all__ = [
    "ApprovalResult", "DispatchBindingResult", "GovernedRouter", "ReceiptResult",
    "RouterPorts", "ValidationResult", "route_mapping",
]
