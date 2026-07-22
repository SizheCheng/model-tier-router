from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath


ASSETS = {
    "authority-receipt.schema.json": "schemas/authority-receipt.schema.json",
    "bounded-writer-receipt.schema.json": "schemas/bounded-writer-receipt.schema.json",
    "bounded-writer.py": "src/mtr_dogfood/bounded_writer.py",
    "host-materialization-lanes.json": "config/host-materialization-lanes.json",
    "proposed-files-result.schema.json": "schemas/proposed-files-result.schema.json",
    "task.schema.json": "schemas/task.schema.json",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip())
    return completed.stdout.strip()


def source_status(root: Path, output_directory: Path) -> str:
    arguments = ["status", "--porcelain=v1", "--untracked-files=all", "--", "."]
    try:
        relative_output = output_directory.resolve().relative_to(root.resolve())
    except ValueError:
        pass
    else:
        arguments.append(f":(exclude){relative_output.as_posix()}")
    return git(root, *arguments)


def bare_cr_count(raw: bytes) -> int:
    return raw.replace(b"\r\n", b"").count(b"\r")


def powershell_ast_errors(path: Path) -> list[str]:
    command = (
        "$tokens=$null;$errors=$null;"
        "[System.Management.Automation.Language.Parser]::ParseFile("
        f"'{str(path).replace("'", "''")}',[ref]$tokens,[ref]$errors)|Out-Null;"
        "$errors | ForEach-Object { $_.Message };"
        "if($errors.Count){exit 1}"
    )
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
    )
    errors = [line for line in completed.stdout.splitlines() if line.strip()]
    if completed.returncode != 0 and not errors:
        errors = [completed.stderr.strip() or "PowerShell AST parse failed"]
    return errors


def create_deterministic_zipapp(source: Path, target: Path) -> None:
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(item for item in source.rglob("*") if item.is_file()):
            relative = path.relative_to(source).as_posix()
            info = zipfile.ZipInfo(
                relative,
                date_time=(1980, 1, 1, 0, 0, 0),
            )
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes())

def materialize_head(root: Path, head: str, target: Path) -> Path:
    listing = subprocess.run(
        ["git", "-C", str(root), "ls-tree", "-rz", "--full-tree", head],
        capture_output=True,
        check=False,
    )
    if listing.returncode != 0:
        raise RuntimeError(
            listing.stderr.decode("utf-8", "replace").strip()
            or "SOURCE_HEAD_TREE_FAILED"
        )
    entries: list[tuple[str, str]] = []
    seen: set[str] = set()
    for raw_entry in listing.stdout.split(b"\0"):
        if not raw_entry:
            continue
        metadata, separator, raw_name = raw_entry.partition(b"\t")
        fields = metadata.decode("ascii", "strict").split()
        try:
            relative = raw_name.decode("utf-8", "strict")
        except UnicodeError as exc:
            raise RuntimeError("SOURCE_HEAD_PATH_INVALID") from exc
        path = PurePosixPath(relative)
        if (
            separator != b"\t"
            or len(fields) != 3
            or fields[1] != "blob"
            or fields[0] not in {"100644", "100755"}
            or path.is_absolute()
            or not path.parts
            or ".." in path.parts
            or ".git" in path.parts
            or "\\" in relative
            or ":" in relative
            or relative in seen
        ):
            raise RuntimeError("SOURCE_HEAD_TREE_UNSAFE")
        seen.add(relative)
        entries.append((relative, fields[2]))
    if not entries:
        raise RuntimeError("SOURCE_HEAD_TREE_EMPTY")
    objects = subprocess.run(
        ["git", "-C", str(root), "cat-file", "--batch"],
        input="".join(f"{object_id}\n" for _, object_id in entries).encode(
            "ascii"
        ),
        capture_output=True,
        check=False,
    )
    if objects.returncode != 0:
        raise RuntimeError(
            objects.stderr.decode("utf-8", "replace").strip()
            or "SOURCE_HEAD_OBJECT_READ_FAILED"
        )
    cursor = 0
    payloads: list[bytes] = []
    for _, expected_object_id in entries:
        line_end = objects.stdout.find(b"\n", cursor)
        if line_end < 0:
            raise RuntimeError("SOURCE_HEAD_OBJECT_STREAM_INVALID")
        header = objects.stdout[cursor:line_end].decode("ascii", "strict").split()
        if (
            len(header) != 3
            or header[0] != expected_object_id
            or header[1] != "blob"
        ):
            raise RuntimeError("SOURCE_HEAD_OBJECT_STREAM_INVALID")
        size = int(header[2])
        start = line_end + 1
        finish = start + size
        if finish >= len(objects.stdout) or objects.stdout[finish:finish + 1] != b"\n":
            raise RuntimeError("SOURCE_HEAD_OBJECT_STREAM_INVALID")
        payloads.append(objects.stdout[start:finish])
        cursor = finish + 1
    if cursor != len(objects.stdout):
        raise RuntimeError("SOURCE_HEAD_OBJECT_STREAM_INVALID")
    target.mkdir(parents=True, exist_ok=False)
    for (relative, _), payload in zip(entries, payloads, strict=True):
        destination = target.joinpath(*PurePosixPath(relative).parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    return target

def build(
    output_directory: Path,
    *,
    entrypoint: str = "qualification",
) -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    dirty_source = source_status(root, output_directory)
    source_head = git(root, "rev-parse", "HEAD")
    output_directory.mkdir(parents=True, exist_ok=True)
    entrypoints = {
        "qualification": (
            "mtr-dogfood-qualification.pyz",
            "qualification/RUN_QUALIFICATION.ps1",
            "qualification",
        ),
        "final-execution": (
            "mtr-dogfood-final-execution.pyz",
            "final_execution/RUN_FINAL_TWO_PRODUCT_LANES.ps1",
            "final_execution",
        ),
        "remaining-lane": (
            "mtr-dogfood-remaining-lane.pyz",
            "final_execution/RUN_FINAL_REMAINING_QWEN_LANE.ps1",
            "remaining_lane_execution",
        ),
        "product-lane": (
            "mtr-dogfood-product-lane.pyz",
            "final_execution/RUN_PRODUCT_LANE.ps1",
            "product_execution",
        ),
    }
    try:
        artifact_name, wrapper_name, module = entrypoints[entrypoint]
    except KeyError as exc:
        raise RuntimeError("UNKNOWN_ARTIFACT_ENTRYPOINT") from exc
    artifact = output_directory / artifact_name
    wrapper = output_directory / Path(wrapper_name).name

    with tempfile.TemporaryDirectory(prefix="mtr-qualification-build-") as temporary:
        temporary_root = Path(temporary)
        source_root = (
            root
            if dirty_source
            else materialize_head(root, source_head, temporary_root / "source-head")
        )
        stage = temporary_root / "stage"
        stage.mkdir()
        package = stage / "mtr_dogfood"
        shutil.copytree(
            source_root / "src" / "mtr_dogfood",
            package,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        (package / "_release_metadata.json").write_bytes(
            canonical(
                {
                    "schema_version": "1.0.0",
                    "source_head": source_head,
                    "source_dirty": bool(dirty_source),
                    "source_materialization": (
                        "dirty_worktree_candidate"
                        if dirty_source
                        else "git_object_database_head"
                    ),
                    "entrypoint": entrypoint,
                }
            )
        )
        assets = package / "_qualification_assets"
        assets.mkdir()
        for name, relative in ASSETS.items():
            shutil.copyfile(source_root / relative, assets / name)

        (stage / "__main__.py").write_text(
            f"from mtr_dogfood.{module} import main\n"
            "raise SystemExit(main())\n",
            encoding="utf-8",
            newline="\n",
        )
        create_deterministic_zipapp(stage, artifact)

        wrapper_source = source_root / wrapper_name
        wrapper_raw = wrapper_source.read_bytes()
        if bare_cr_count(wrapper_raw):
            raise RuntimeError("POWERSHELL_WRAPPER_BARE_CR")
        ast_errors = powershell_ast_errors(wrapper_source)
        if ast_errors:
            raise RuntimeError(f"POWERSHELL_WRAPPER_AST_INVALID: {ast_errors}")
        shutil.copyfile(wrapper_source, wrapper)

    self_test = subprocess.run(
        [sys.executable, "-B", str(artifact), "--self-test"],
        capture_output=True,
        text=True,
        check=False,
    )
    if self_test.returncode != 0:
        raise RuntimeError(self_test.stderr or self_test.stdout)
    self_test_value = json.loads(self_test.stdout)
    if self_test_value.get("status") != "passed":
        raise RuntimeError("ARTIFACT_SELF_TEST_FAILED")

    manifest = {
        "schema_version": "1.0.0",
        "entrypoint": entrypoint,
        "artifact_status": (
            "candidate_uncommitted_source" if dirty_source else "committed_source"
        ),
        "built_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source_head": source_head,
        "source_dirty": bool(dirty_source),
        "source_materialization": (
            "dirty_worktree_candidate" if dirty_source else "git_object_database_head"
        ),
        "artifact": {
            "path": str(artifact.resolve()),
            "bytes": artifact.stat().st_size,
            "sha256": sha256(artifact),
            "self_test": self_test_value,
        },
        "wrapper": {
            "path": str(wrapper.resolve()),
            "bytes": wrapper.stat().st_size,
            "sha256": sha256(wrapper),
            "bare_cr_count": bare_cr_count(wrapper.read_bytes()),
            "powershell_ast_errors": [],
        },
        "real_model_process_starts": 0,
        "real_model_requests": 0,
    }
    (output_directory / "artifact-manifest.json").write_bytes(canonical(manifest))
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-directory", required=True)
    parser.add_argument(
        "--entrypoint",
        choices=("qualification", "final-execution", "remaining-lane", "product-lane"),
        default="qualification",
    )
    args = parser.parse_args(argv)
    value = build(
        Path(args.output_directory).resolve(),
        entrypoint=args.entrypoint,
    )
    sys.stdout.buffer.write(canonical(value))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
