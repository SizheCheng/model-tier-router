"""Provider-agnostic verification contracts for optional governed mode."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Sequence


@dataclass(frozen=True)
class ApprovalResult:
    verified: bool
    code: str = ""


@dataclass(frozen=True)
class ValidationResult:
    accepted: bool
    obligation: str
    supervised_full_suite_required: bool
    code: str


@dataclass(frozen=True)
class DispatchBindingResult:
    canonical: bool
    code: str = ""


@dataclass(frozen=True)
class ReceiptResult:
    valid: bool
    authority_state: str
    code: str = ""


class ApprovalVerifier(Protocol):
    def verify(
        self, *, approval_reference: str, task_id: str,
        reviewer_required: bool, human_required: bool,
    ) -> ApprovalResult: ...


class ValidationVerifier(Protocol):
    def verify(
        self, *, task_id: str, obligation: str,
        supervised_full_suite_required: bool,
    ) -> ValidationResult: ...


class CanonicalDispatchVerifier(Protocol):
    def verify(
        self, *, task_id: str, decision_id: str,
        direct_model_override: str | None,
    ) -> DispatchBindingResult: ...


class AuthorityReceiptVerifier(Protocol):
    def verify(
        self, *, receipt_id: str, decision_id: str,
        budget_class: str, mutation_scope: Sequence[str],
    ) -> ReceiptResult: ...


@dataclass(frozen=True)
class RouterPorts:
    approval: ApprovalVerifier | None = None
    validation: ValidationVerifier | None = None
    canonical_dispatch: CanonicalDispatchVerifier | None = None
    authority_receipt: AuthorityReceiptVerifier | None = None


__all__ = [
    "ApprovalResult", "ApprovalVerifier", "AuthorityReceiptVerifier",
    "CanonicalDispatchVerifier", "DispatchBindingResult", "ReceiptResult",
    "RouterPorts", "ValidationResult", "ValidationVerifier",
]
