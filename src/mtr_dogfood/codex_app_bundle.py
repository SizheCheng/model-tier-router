from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from .config import canonical_json_bytes


RUNTIME_NAME = "mtr-dogfood-codex-hook.pyz"
REQUIREMENTS_NAME = "requirements.toml"
MANIFEST_NAME = "codex-app-enforcement-manifest.json"
HOOK_EVENTS = (
    ("SessionStart", "startup|resume|clear|compact", "Initializing managed dogfood data"),
    ("UserPromptSubmit", None, "Assessing and recording development task"),
    ("SubagentStart", "*", "Recording dogfood subagent start"),
    ("PreToolUse", "*", "Recording dogfood tool intent"),
    ("PermissionRequest", "*", "Recording dogfood approval request"),
    ("PostToolUse", "*", "Recording dogfood tool result"),
    ("PreCompact", "manual|auto", "Recording dogfood pre-compaction state"),
    ("PostCompact", "manual|auto", "Recording dogfood post-compaction state"),
    ("SubagentStop", "*", "Finalizing dogfood subagent data"),
    ("Stop", None, "Finalizing dogfood turn data"),
)


class CodexAppBundleError(RuntimeError):
    pass


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _git(repository: Path, *arguments: str, text: bool = True) -> str | bytes:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        capture_output=True,
        text=text,
        check=False,
    )
    if completed.returncode != 0:
        raise CodexAppBundleError("SOURCE_GIT_QUERY_FAILED")
    return completed.stdout


def _repository_state(repository: Path) -> dict[str, str]:
    if not repository.is_dir():
        raise CodexAppBundleError("SOURCE_REPOSITORY_MISSING")
    head = str(_git(repository, "rev-parse", "HEAD")).strip()
    status = str(
        _git(repository, "status", "--porcelain", "--untracked-files=all")
    ).strip()
    if re.fullmatch(r"[0-9a-f]{40}", head) is None or status:
        raise CodexAppBundleError("SOURCE_REPOSITORY_NOT_CLEAN_COMMIT")
    return {"path": str(repository), "head": head, "status": status}


def _git_bytes(repository: Path, source_path: str) -> bytes:
    value = _git(repository, "show", f"HEAD:{source_path}", text=False)
    if not isinstance(value, bytes):
        raise CodexAppBundleError("SOURCE_GIT_BYTES_INVALID")
    return value


def _router_files(router_repository: Path) -> dict[str, bytes]:
    listing = str(
        _git(
            router_repository,
            "ls-tree",
            "-r",
            "--name-only",
            "HEAD",
            "--",
            "src/model_tier_router",
        )
    )
    result: dict[str, bytes] = {}
    for line in listing.splitlines():
        if not line.endswith(".py"):
            continue
        relative = PurePosixPath(line).relative_to("src")
        result[str(relative)] = _git_bytes(router_repository, line)
    if "model_tier_router/__init__.py" not in result:
        raise CodexAppBundleError("ROUTER_PACKAGE_INCOMPLETE")
    return result


def deterministic_zipapp(files: dict[str, bytes], output: str | Path) -> dict[str, Any]:
    required = {"__main__.py", "mtr_dogfood/codex_app_enforcement.py", "model_tier_router/__init__.py"}
    if not required.issubset(files):
        raise CodexAppBundleError("RUNTIME_FILE_SET_INCOMPLETE")
    destination = Path(output).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise CodexAppBundleError("RUNTIME_TARGET_EXISTS")
    temporary = destination.with_name(destination.name + ".tmp")
    try:
        with zipfile.ZipFile(
            temporary,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        ) as archive:
            for name in sorted(files):
                path = PurePosixPath(name)
                if (
                    path.is_absolute()
                    or ".." in path.parts
                    or "\\" in name
                    or name.endswith("/")
                ):
                    raise CodexAppBundleError("RUNTIME_PATH_INVALID")
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                archive.writestr(info, files[name])
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    raw = destination.read_bytes()
    return {"path": str(destination), "bytes": len(raw), "sha256": _sha256(raw)}


def _toml_literal(value: str) -> str:
    if "'" in value or "\n" in value or "\r" in value:
        raise CodexAppBundleError("TOML_LITERAL_UNSUPPORTED")
    return f"'{value}'"


def render_requirements(install_root: str | Path, data_root: str | Path) -> str:
    install = Path(install_root).resolve()
    data = Path(data_root).resolve()
    runtime = install / RUNTIME_NAME
    command = f'py -3 "{runtime}" --data-root "{data}"'
    lines = [
        "# Managed model-tier-router dogfood enforcement for Codex local clients.",
        "# Generated from committed, zero-model-qualified source.",
        "",
        "[features]",
        "hooks = true",
        "",
        "[hooks]",
        f"windows_managed_dir = {_toml_literal(str(install))}",
    ]
    for event, matcher, status in HOOK_EVENTS:
        lines.extend(["", f"[[hooks.{event}]]"])
        if matcher is not None:
            lines.append(f"matcher = {_toml_literal(matcher)}")
        lines.extend(
            [
                "",
                f"[[hooks.{event}.hooks]]",
                'type = "command"',
                f"command = {_toml_literal(command)}",
                f"command_windows = {_toml_literal(command)}",
                "timeout = 30",
                f"statusMessage = {_toml_literal(status)}",
            ]
        )
    text = "\n".join(lines) + "\n"
    parsed = tomllib.loads(text)
    if parsed.get("features", {}).get("hooks") is not True:
        raise CodexAppBundleError("REQUIREMENTS_FEATURE_GATE_INVALID")
    configured = parsed.get("hooks", {})
    if any(event not in configured for event, _matcher, _status in HOOK_EVENTS):
        raise CodexAppBundleError("REQUIREMENTS_HOOK_SET_INCOMPLETE")
    return text


def build_managed_bundle(
    output_directory: str | Path,
    *,
    dogfood_repository: str | Path,
    router_repository: str | Path,
    install_root: str | Path,
    data_root: str | Path,
) -> dict[str, Any]:
    output = Path(output_directory).resolve()
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise CodexAppBundleError("BUNDLE_OUTPUT_NOT_EMPTY")
    output.mkdir(parents=True, exist_ok=True)
    dogfood = Path(dogfood_repository).resolve()
    router = Path(router_repository).resolve()
    dogfood_state = _repository_state(dogfood)
    router_state = _repository_state(router)
    files = _router_files(router)
    files.update(
        {
            "__main__.py": (
                b"from mtr_dogfood.codex_app_enforcement import main\n"
                b"raise SystemExit(main())\n"
            ),
            "mtr_dogfood/__init__.py": b'"""Managed Codex hook runtime."""\n',
            "mtr_dogfood/codex_app_enforcement.py": _git_bytes(
                dogfood, "src/mtr_dogfood/codex_app_enforcement.py"
            ),
        }
    )
    artifact = deterministic_zipapp(files, output / RUNTIME_NAME)
    requirements_raw = render_requirements(install_root, data_root).encode("utf-8")
    (output / REQUIREMENTS_NAME).write_bytes(requirements_raw)
    manifest = {
        "schema_version": "1.0.0",
        "component_id": "MTR_CODEX_APP_DEVELOPMENT_DATA_R1",
        "status": "prepared_zero_model",
        "artifact": artifact,
        "requirements": {
            "path": str(output / REQUIREMENTS_NAME),
            "sha256": _sha256(requirements_raw),
            "managed_hook_count": len(HOOK_EVENTS),
            "events": [event for event, _matcher, _status in HOOK_EVENTS],
            "allow_managed_hooks_only": False,
        },
        "installation": {
            "install_root": str(Path(install_root).resolve()),
            "data_root": str(Path(data_root).resolve()),
            "system_requirements_path": str(
                Path(os.environ.get("ProgramData", r"C:\ProgramData"))
                / "OpenAI"
                / "Codex"
                / REQUIREMENTS_NAME
            ),
        },
        "source": {
            "dogfood_repository": dogfood_state,
            "router_repository": router_state,
            "source_dirty": False,
            "source_materialization": "git_object_database_head",
        },
        "real_model_process_starts": 0,
        "real_model_requests": 0,
        "network_requests": 0,
    }
    manifest_raw = canonical_json_bytes(manifest)
    (output / MANIFEST_NAME).write_bytes(manifest_raw)
    return manifest


def verify_bundle(bundle_directory: str | Path) -> dict[str, Any]:
    root = Path(bundle_directory).resolve()
    manifest_path = root / MANIFEST_NAME
    try:
        import json

        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise CodexAppBundleError("BUNDLE_MANIFEST_INVALID") from exc
    artifact = root / RUNTIME_NAME
    requirements = root / REQUIREMENTS_NAME
    if (
        manifest.get("status") != "prepared_zero_model"
        or not artifact.is_file()
        or not requirements.is_file()
        or _sha256(artifact.read_bytes()) != manifest.get("artifact", {}).get("sha256")
        or _sha256(requirements.read_bytes())
        != manifest.get("requirements", {}).get("sha256")
    ):
        raise CodexAppBundleError("BUNDLE_INTEGRITY_INVALID")
    parsed = tomllib.loads(requirements.read_text(encoding="utf-8"))
    configured = parsed.get("hooks", {})
    if any(event not in configured for event, _matcher, _status in HOOK_EVENTS):
        raise CodexAppBundleError("BUNDLE_HOOK_SET_INVALID")
    return {
        "schema_version": "1.0.0",
        "status": "passed",
        "artifact_sha256": manifest["artifact"]["sha256"],
        "requirements_sha256": manifest["requirements"]["sha256"],
        "managed_hook_count": len(HOOK_EVENTS),
        "real_model_process_starts": 0,
        "real_model_requests": 0,
        "network_requests": 0,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="build-codex-app-enforcement")
    parser.add_argument("--output-directory", required=True)
    parser.add_argument("--dogfood-repository", required=True)
    parser.add_argument("--router-repository", required=True)
    parser.add_argument("--install-root", required=True)
    parser.add_argument("--data-root", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        manifest = build_managed_bundle(
            args.output_directory,
            dogfood_repository=args.dogfood_repository,
            router_repository=args.router_repository,
            install_root=args.install_root,
            data_root=args.data_root,
        )
        result = {
            "schema_version": "1.0.0",
            "status": "passed",
            "manifest": manifest,
            "verification": verify_bundle(args.output_directory),
        }
    except Exception as exc:
        result = {
            "schema_version": "1.0.0",
            "status": "failed",
            "error_type": type(exc).__name__,
            "error": str(exc),
            "real_model_process_starts": 0,
            "real_model_requests": 0,
            "network_requests": 0,
        }
    sys.stdout.buffer.write(canonical_json_bytes(result))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
