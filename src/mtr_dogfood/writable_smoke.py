from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable

from .config import is_contained, load_json, same_path
from .git_worktrees import changed_paths, diff_bytes
from .r2_contract import (
    PayloadValidationError,
    classify_child_claim,
    final_output_valid,
    validate_child_transport,
    validate_codex_output_schema,
)
from .receipts import write_json
from .runtime_contract import ProcessAccounting


Launcher = Callable[..., dict[str, Any]]
AncestryGuard = Callable[[], dict[str, Any]]
ExecutableResolver = Callable[[], str]


def _remove_tree(path: Path) -> None:
    def make_writable_and_retry(function, failed_path, _error):
        os.chmod(failed_path, stat.S_IWRITE)
        function(failed_path)

    if path.exists():
        shutil.rmtree(path, onerror=make_writable_and_retry)


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("WRITABLE_SMOKE_GIT_FAILURE")
    return completed.stdout.strip()


def build_external_codex_command(
    executable: str,
    worktree: str | Path,
    model: str,
    reasoning_effort: str,
    output_schema: str | Path,
    output_file: str | Path,
) -> list[str]:
    return [
        executable,
        "exec",
        "-C",
        str(Path(worktree).resolve()),
        "--ephemeral",
        "--model",
        model,
        "-c",
        f'model_reasoning_effort="{reasoning_effort}"',
        "-c",
        "memories.generate_memories=false",
        "--sandbox",
        "workspace-write",
        "--ask-for-approval",
        "never",
        "--json",
        "--output-schema",
        str(Path(output_schema).resolve()),
        "--output-last-message",
        str(Path(output_file).resolve()),
        "-",
    ]


def validate_external_command_shape(command: list[str], worktree: str | Path) -> None:
    if len(command) != 21:
        raise PayloadValidationError("external command argument count mismatch")
    expected_literals = {
        1: "exec",
        2: "-C",
        4: "--ephemeral",
        5: "--model",
        7: "-c",
        9: "-c",
        10: "memories.generate_memories=false",
        11: "--sandbox",
        12: "workspace-write",
        13: "--ask-for-approval",
        14: "never",
        15: "--json",
        16: "--output-schema",
        18: "--output-last-message",
        20: "-",
    }
    if any(command[index] != value for index, value in expected_literals.items()):
        raise PayloadValidationError("external command literal or order mismatch")
    if not re.fullmatch(r'model_reasoning_effort="(?:low|medium|high)"', command[8]):
        raise PayloadValidationError("external command reasoning effort mismatch")
    if command[12] != "workspace-write":
        raise PayloadValidationError("external command sandbox mismatch")
    if command[14] != "never":
        raise PayloadValidationError("external command approval mismatch")
    if "--add-dir" in command:
        raise PayloadValidationError("external command adds a writable directory")
    if not same_path(command[3], worktree):
        raise PayloadValidationError("external command working directory mismatch")


def _fixture_prompt(fixture: Path, result_path: str) -> str:
    return f"""Work only inside this synthetic Git repository: {fixture}

Create the exact file {result_path} containing the exact UTF-8 text
WORKSPACE_WRITE_OK followed by one newline.

Do not modify any other tracked or untracked path. Do not read outside this
repository. Do not use network tools, web search, credentials, apps, plugins,
or subagents. Do not run Git mutation commands. Return only the required
structured final result.
"""


def _raw_hashes(raw_directory: Path) -> dict[str, str]:
    return {
        path.relative_to(raw_directory).as_posix(): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in sorted(raw_directory.rglob("*"))
        if path.is_file()
    }


def run_writable_smoke(
    contract: dict[str, Any],
    harness_root: str | Path,
    budget: ProcessAccounting,
    launcher: Launcher,
    ancestry_guard: AncestryGuard,
    executable_resolver: ExecutableResolver,
    raw_directory: str | Path,
    receipt_path: str | Path,
    *,
    fixture_parent: str | Path | None = None,
) -> dict[str, Any]:
    # This guard intentionally precedes fixture creation and executable resolution.
    ancestry_guard()
    harness = Path(harness_root).resolve()
    raw = Path(raw_directory)
    raw.mkdir(parents=True, exist_ok=True)
    parent = Path(fixture_parent or tempfile.gettempdir()).resolve()
    protected = [
        harness,
        Path(contract["paths"]["worktree_pool"]).resolve(),
        *[Path(entry["path"]).resolve() for entry in contract["repositories"].values()],
    ]
    if any(is_contained(root, parent) for root in protected):
        raise RuntimeError("WRITABLE_SMOKE_TEMP_INSIDE_REAL_REPOSITORY")
    fixture = Path(tempfile.mkdtemp(prefix="mtr-dogfood-r3-smoke-", dir=parent))
    if any(is_contained(root, fixture) for root in protected):
        shutil.rmtree(fixture, ignore_errors=True)
        raise RuntimeError("WRITABLE_SMOKE_FIXTURE_PATH_REJECTED")

    smoke = contract["fixture_smoke"]
    receipt: dict[str, Any] = {
        "schema_version": "1.0.0",
        "status": "failed",
        "accepted": False,
        "failure_class": "ENVIRONMENT_FAILURE",
        "fixture_created": True,
        "fixture_removed": False,
        "child_process_started": False,
        "model_execution_observed": False,
        "model_execution_completed": False,
        "final_output_valid": False,
        "worktree_local_transport_validated": False,
        "additional_writable_directory_count": 0,
        "filesystem_mutation_observed": False,
        "validator_completed": False,
        "changed_paths": [],
        "git_status": [],
        "diff_sha256": hashlib.sha256(b"").hexdigest(),
        "raw_log_sha256": {},
        "usage": {
            "input_tokens": None,
            "cached_input_tokens": None,
            "output_tokens": None,
            "reasoning_output_tokens": None,
        },
    }
    result: dict[str, Any] = {}
    output_valid = False
    mutation = False
    try:
        _git(fixture, "init", "-q")
        (fixture / "README.md").write_text(smoke["readme_text"], encoding="utf-8")
        _git(fixture, "add", "--", "README.md")
        _git(
            fixture,
            "-c",
            f"user.name={contract['commit_identity']['name']}",
            "-c",
            f"user.email={contract['commit_identity']['email']}",
            "commit",
            "-q",
            "-m",
            "Initialize writable smoke fixture",
        )
        baseline = _git(fixture, "rev-parse", "HEAD")
        if _git(fixture, "status", "--porcelain=v1"):
            raise RuntimeError("WRITABLE_SMOKE_BASELINE_DIRTY")

        metadata = fixture / ".mtr-dogfood-r3"
        metadata.mkdir()
        local_schema = metadata / "writable-smoke-result.schema.json"
        final_output = metadata / "final-result.json"
        source_schema = harness / contract["paths"]["writable_smoke_schema"]
        shutil.copyfile(source_schema, local_schema)
        output_schema = load_json(local_schema)
        budget.record_prelaunch()
        validate_codex_output_schema(output_schema)
        schema_digest = hashlib.sha256(local_schema.read_bytes()).hexdigest()
        profile = smoke["model_profile"]
        mapping = contract["model_mapping"][profile]
        command = build_external_codex_command(
            "codex.exe",
            fixture,
            mapping["model"],
            mapping["reasoning_effort"],
            local_schema,
            final_output,
        )
        validate_external_command_shape(command, fixture)
        prompt = _fixture_prompt(fixture, smoke["result_path"])
        validate_child_transport(fixture, command, prompt, protected)
        receipt["worktree_local_transport_validated"] = True
        ancestry_guard()
        try:
            command[0] = executable_resolver()
        except FileNotFoundError:
            result = {
                "exit_code": None,
                "child_process_started": False,
                "model_execution_observed": False,
                "model_execution_completed": False,
                "infrastructure_failure_class": "MISSING_COMMAND",
                "host_policy_failure_count": 0,
                "input_tokens": None,
                "cached_input_tokens": None,
                "output_tokens": None,
                "reasoning_output_tokens": None,
            }
        else:
            budget.require_start_available()
            starts_before = budget.os_child_process_started
            result = launcher(
                command=command,
                prompt=prompt,
                raw_directory=raw,
                worktree=fixture,
                timeout_seconds=int(smoke["timeout_seconds"]),
                on_process_started=budget.record_process_start,
            )
            started_delta = budget.os_child_process_started - starts_before
            if started_delta != int(bool(result.get("child_process_started"))):
                raise RuntimeError("ENVIRONMENT_FAILURE")
        receipt.update(
            {
                "child_process_started": bool(result.get("child_process_started")),
                "model_execution_observed": bool(result.get("model_execution_observed")),
                "model_execution_completed": bool(result.get("model_execution_completed")),
                "usage": {
                    key: result.get(key)
                    for key in (
                        "input_tokens",
                        "cached_input_tokens",
                        "output_tokens",
                        "reasoning_output_tokens",
                    )
                },
            }
        )
        output_valid = final_output_valid(final_output, output_schema)
        claim: dict[str, Any] = load_json(final_output) if output_valid else {}
        if final_output.exists():
            shutil.copyfile(final_output, raw / "final-result.json")
        schema_unchanged = (
            local_schema.exists()
            and hashlib.sha256(local_schema.read_bytes()).hexdigest() == schema_digest
        )
        claim_failure = classify_child_claim(claim) if output_valid else None
        infrastructure = result.get("infrastructure_failure_class") or claim_failure
        _remove_tree(metadata)
        _remove_tree(fixture / ".mtr-dogfood-r2")

        paths = changed_paths(fixture)
        mutation = bool(paths)
        status_lines = _git(
            fixture, "status", "--porcelain=v1", "--untracked-files=all"
        ).splitlines()
        patch = diff_bytes(fixture)
        result_file = fixture / smoke["result_path"]
        exact_bytes = (
            result_file.is_file()
            and result_file.read_bytes() == smoke["result_text"].encode("utf-8")
        )
        accepted = bool(
            result.get("child_process_started")
            and result.get("model_execution_observed")
            and result.get("model_execution_completed")
            and result.get("exit_code") == 0
            and infrastructure is None
            and output_valid
            and schema_unchanged
            and claim.get("status") == "completed"
            and claim.get("prohibited_action_attempted") is False
            and claim.get("changed_paths") == [smoke["result_path"]]
            and paths == [smoke["result_path"]]
            and status_lines == [f"?? {smoke['result_path']}"]
            and exact_bytes
        )
        if infrastructure:
            failure_class = str(infrastructure)
        elif not output_valid or not schema_unchanged:
            failure_class = "SCHEMA_REJECTION"
        elif not result.get("model_execution_observed"):
            failure_class = "ENVIRONMENT_FAILURE"
        elif not accepted:
            failure_class = "WRITABLE_SMOKE_VALIDATION_FAILURE"
        else:
            failure_class = ""
        receipt.update(
            {
                "status": "passed" if accepted else "failed",
                "accepted": accepted,
                "failure_class": failure_class,
                "baseline_head": baseline,
                "final_output_valid": output_valid,
                "filesystem_mutation_observed": mutation,
                "validator_completed": True,
                "changed_paths": paths,
                "git_status": status_lines,
                "diff_sha256": hashlib.sha256(patch).hexdigest(),
            }
        )
    except (OSError, subprocess.SubprocessError, RuntimeError, PayloadValidationError) as exc:
        receipt["failure_class"] = (
            str(exc) if str(exc).isupper() else "ENVIRONMENT_FAILURE"
        )
    finally:
        receipt["raw_log_sha256"] = _raw_hashes(raw)
        _remove_tree(fixture)
        receipt["fixture_removed"] = not fixture.exists()
        budget.record_result(
            result,
            final_output_valid=output_valid,
            filesystem_mutation=mutation,
            validator_completed=bool(receipt.get("validator_completed")),
        )
        write_json(receipt_path, receipt)
    return receipt


__all__ = [
    "build_external_codex_command",
    "run_writable_smoke",
    "validate_external_command_shape",
]
