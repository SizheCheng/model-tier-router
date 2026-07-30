from __future__ import annotations

import json
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

from model_tier_router.codex_bundle import (
    HOOK_EVENTS,
    build_managed_bundle,
    deterministic_zipapp,
    render_requirements,
    verify_bundle,
)


def _git(repository: Path, *arguments: str) -> None:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr)


def _repository(path: Path, files: dict[str, bytes]) -> Path:
    path.mkdir(parents=True)
    _git(path, "init", "-q", "-b", "main")
    _git(path, "config", "core.longpaths", "true")
    _git(path, "config", "user.name", "Bundle Fixture")
    _git(path, "config", "user.email", "bundle.invalid")
    for relative, raw in files.items():
        target = path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    _git(path, "add", "--", ".")
    _git(path, "commit", "-q", "-m", "fixture")
    return path


class CodexAppBundleTests(unittest.TestCase):
    def test_zipapp_is_reproducible(self):
        files = {
            "__main__.py": b"print('ok')\n",
            "model_tier_router/codex_app.py": b"VALUE = 1\n",
            "model_tier_router/__init__.py": b"def assess(value): return value\n",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = deterministic_zipapp(files, root / "first.pyz")
            second = deterministic_zipapp(files, root / "second.pyz")
            self.assertEqual(first["sha256"], second["sha256"])
            self.assertEqual(first["bytes"], second["bytes"])

    def test_requirements_enable_managed_hooks_without_disabling_user_hooks(self):
        text = render_requirements(
            r"C:\ProgramData\OpenAI\Codex\managed-hooks\model-tier-router-r1",
            r"C:\Fixture\.codex\model-tier-router-data",
        )
        value = tomllib.loads(text)
        self.assertTrue(value["features"]["hooks"])
        self.assertNotIn("allow_managed_hooks_only", value)
        self.assertEqual(
            {name for name, _matcher, _status in HOOK_EVENTS},
            {name for name, entries in value["hooks"].items() if isinstance(entries, list)},
        )
        for name, _matcher, _status in HOOK_EVENTS:
            self.assertEqual(len(value["hooks"][name]), 1)
            command = value["hooks"][name][0]["hooks"][0]["command_windows"]
            self.assertIn("model-tier-router-codex-hook.pyz", command)

    def test_bundle_uses_clean_committed_sources_and_verifies_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = _repository(
                root / "source",
                {
                    "src/model_tier_router/__init__.py": (
                        b"def assess(value): return value\n"
                    ),
                    "src/model_tier_router/codex_app.py": b"def main(): return 0\n",
                    "src/model_tier_router/helper.py": b"VALUE = 1\n",
                },
            )
            output = root / "bundle"
            manifest = build_managed_bundle(
                output,
                repository=source,
                install_root=root / "managed",
                data_root=root / "data",
            )
            self.assertFalse(manifest["source"]["source_dirty"])
            self.assertEqual(manifest["requirements"]["managed_hook_count"], 10)
            self.assertEqual(manifest["real_model_process_starts"], 0)
            verification = verify_bundle(output)
            self.assertEqual(verification["status"], "passed")
            self.assertEqual(verification["managed_hook_count"], 10)
            artifact = output / "model-tier-router-codex-hook.pyz"
            artifact.write_bytes(artifact.read_bytes() + b"tamper")
            with self.assertRaisesRegex(Exception, "BUNDLE_INTEGRITY_INVALID"):
                verify_bundle(output)


if __name__ == "__main__":
    unittest.main()
