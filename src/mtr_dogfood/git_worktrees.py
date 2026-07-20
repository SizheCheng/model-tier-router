from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

from .config import is_contained, same_path


class GitContractError(RuntimeError):
    pass


def _git(
    repository: str | Path,
    *arguments: str,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    if check and completed.returncode != 0:
        raise GitContractError(completed.stderr.strip() or completed.stdout.strip())
    return completed


def repository_state(repository: str | Path) -> dict[str, Any]:
    root = _git(repository, "rev-parse", "--show-toplevel").stdout.strip()
    head_result = _git(repository, "rev-parse", "--verify", "HEAD", check=False)
    head = head_result.stdout.strip() if head_result.returncode == 0 else None
    branch = _git(repository, "branch", "--show-current").stdout.strip()
    status = _git(repository, "status", "--porcelain=v2").stdout.splitlines()
    git_dir_text = _git(repository, "rev-parse", "--git-dir").stdout.strip()
    git_dir = Path(repository, git_dir_text).resolve() if not Path(git_dir_text).is_absolute() else Path(git_dir_text)
    locks = sorted(path.name for path in git_dir.glob("*.lock"))
    operation_names = (
        "MERGE_HEAD",
        "CHERRY_PICK_HEAD",
        "REVERT_HEAD",
        "BISECT_LOG",
        "rebase-apply",
        "rebase-merge",
    )
    operations = [name for name in operation_names if (git_dir / name).exists()]
    return {
        "root": root,
        "head": head,
        "branch": branch,
        "status": status,
        "clean": not status,
        "locks": locks,
        "active_operations": operations,
        "remotes": _git(repository, "remote").stdout.splitlines(),
        "tags": _git(repository, "tag").stdout.splitlines(),
    }


def require_clean_baseline(
    repository: str | Path,
    expected_root: str | Path,
    expected_head: str,
) -> dict[str, Any]:
    state = repository_state(repository)
    if not same_path(state["root"], expected_root):
        raise GitContractError("target repository root mismatch")
    if state["head"] != expected_head:
        raise GitContractError("target primary HEAD changed")
    if not state["clean"]:
        raise GitContractError("target repository dirty")
    if state["locks"] or state["active_operations"]:
        raise GitContractError("active Git operation or lock")
    return state


def create_worktree(
    repository: str | Path,
    pool_root: str | Path,
    worktree: str | Path,
    branch: str,
    baseline: str,
) -> Path:
    target = Path(worktree).resolve()
    if not is_contained(pool_root, target) or same_path(pool_root, target):
        raise GitContractError("worktree path escapes pool")
    if target.exists():
        raise GitContractError("worktree path already exists")
    target.parent.mkdir(parents=True, exist_ok=True)
    branch_ref = f"refs/heads/{branch}"
    existing = _git(
        repository, "show-ref", "--verify", "--quiet", branch_ref, check=False
    )
    if existing.returncode == 0:
        branch_head = _git(repository, "rev-parse", branch_ref).stdout.strip()
        if branch_head != baseline:
            raise GitContractError("existing attempt branch is not at the baseline")
        _git(repository, "worktree", "add", str(target), branch)
    else:
        _git(repository, "worktree", "add", "-b", branch, str(target), baseline)
    if _git(target, "rev-parse", "HEAD").stdout.strip() != baseline:
        raise GitContractError("worktree baseline mismatch")
    return target


def remove_worktree(repository: str | Path, pool_root: str | Path, worktree: str | Path) -> None:
    target = Path(worktree).resolve()
    if not is_contained(pool_root, target) or same_path(pool_root, target):
        raise GitContractError("refusing to remove path outside pool")
    _git(repository, "worktree", "remove", "--force", str(target))


def changed_paths(worktree: str | Path) -> list[str]:
    unstaged = _git(worktree, "diff", "--name-only").stdout.splitlines()
    untracked = _git(
        worktree, "ls-files", "--others", "--exclude-standard"
    ).stdout.splitlines()
    return sorted(set(unstaged + untracked))


def diff_bytes(worktree: str | Path) -> bytes:
    tracked = subprocess.run(
        ["git", "-C", str(worktree), "diff", "--binary", "--no-ext-diff"],
        capture_output=True,
        check=True,
    ).stdout
    untracked_parts = []
    for path in _git(worktree, "ls-files", "--others", "--exclude-standard").stdout.splitlines():
        file_path = Path(worktree, path)
        if file_path.is_file():
            untracked_parts.append(b"\nUNTRACKED " + path.encode("utf-8") + b"\n" + file_path.read_bytes())
    return tracked + b"".join(untracked_parts)


def commit_exact_paths(
    worktree: str | Path,
    paths: list[str],
    subject: str,
    name: str,
    email: str,
) -> str:
    if not paths:
        raise GitContractError("no paths to commit")
    _git(worktree, "add", "--", *paths)
    staged = _git(worktree, "diff", "--cached", "--name-only").stdout.splitlines()
    if sorted(staged) != sorted(paths):
        raise GitContractError("staged paths differ from validated paths")
    check = _git(worktree, "diff", "--cached", "--check", check=False)
    if check.returncode != 0:
        raise GitContractError("cached diff check failed")
    _git(
        worktree,
        "-c",
        f"user.name={name}",
        "-c",
        f"user.email={email}",
        "commit",
        "-m",
        subject,
    )
    return _git(worktree, "rev-parse", "HEAD").stdout.strip()


def can_fast_forward(
    repository: str | Path,
    expected_head: str,
    commit: str,
) -> bool:
    state = repository_state(repository)
    if state["head"] != expected_head or not state["clean"] or state["locks"]:
        return False
    check = _git(repository, "merge-base", "--is-ancestor", expected_head, commit, check=False)
    return check.returncode == 0


def fast_forward(repository: str | Path, expected_head: str, commit: str) -> str:
    if not can_fast_forward(repository, expected_head, commit):
        raise GitContractError("fast-forward preconditions failed")
    _git(repository, "merge", "--ff-only", commit)
    return _git(repository, "rev-parse", "HEAD").stdout.strip()
