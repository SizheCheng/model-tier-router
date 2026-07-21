from __future__ import annotations

from typing import Any, Iterable


VOLATILE_REF_PREFIXES = ("refs/codex/turn-diffs/",)
INTEGRITY_STATUSES = frozenset({
    "passed",
    "failed",
    "not_evaluated",
    "incomplete",
})


def stable_git_ref_lines(lines: Iterable[str]) -> list[str]:
    """Return deterministic refs after excluding Codex UI bookkeeping refs."""

    stable: list[str] = []
    for line in lines:
        text = str(line).strip()
        if not text:
            continue
        parts = text.split(maxsplit=1)
        if len(parts) != 2:
            raise ValueError("invalid Git ref row")
        ref_name = parts[1]
        if any(ref_name.startswith(prefix) for prefix in VOLATILE_REF_PREFIXES):
            continue
        stable.append(text)
    return sorted(stable, key=str.casefold)


def repository_integrity_status(
    *,
    checks_executed: bool,
    unchanged: bool | None,
    mismatches: Iterable[str] = (),
) -> dict[str, Any]:
    """Encode repository integrity without conflating unknown with mutation."""

    if not isinstance(checks_executed, bool):
        raise TypeError("checks_executed must be boolean")
    mismatch_rows = sorted({str(item) for item in mismatches if str(item)})
    if not checks_executed:
        if unchanged is not None or mismatch_rows:
            raise ValueError("an unexecuted check cannot report an outcome")
        status = "not_evaluated"
    elif unchanged is None:
        status = "incomplete"
    elif unchanged is True:
        if mismatch_rows:
            raise ValueError("a passing check cannot contain mismatches")
        status = "passed"
    elif unchanged is False:
        status = "failed"
    else:
        raise TypeError("unchanged must be boolean or null")
    result = {
        "status": status,
        "checks_executed": checks_executed,
        "mismatches": mismatch_rows,
    }
    if unchanged is not None:
        result["unchanged"] = unchanged
    return result


__all__ = [
    "INTEGRITY_STATUSES",
    "VOLATILE_REF_PREFIXES",
    "repository_integrity_status",
    "stable_git_ref_lines",
]
