from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from mtr_dogfood.config import is_contained
from mtr_dogfood.external_runner import (
    _extract_windows_paths,
    _normalized_windows_path,
    _scan_child_commands,
)
from mtr_dogfood.runtime_contract import ProcessAccounting


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "r3d-unauthorized-action-event.json"
PWSH = r"C:\Users\sizhe\AppData\Local\Microsoft\WindowsApps\pwsh.exe"


def powershell(script: str) -> str:
    return f'"{PWSH}" -Command "{script}"'


class ChildCommandScannerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.worktree = self.root / "allowed"
        self.worktree.mkdir()
        self.events = self.root / "events.jsonl"

    def tearDown(self):
        self.temporary.cleanup()

    def scan_event(self, event: dict, protected: list[Path] | None = None):
        self.events.write_text(json.dumps(event) + "\n", encoding="utf-8")
        return _scan_child_commands(
            self.events,
            protected or [],
            self.worktree,
        )

    def scan_command(self, command: str, protected: list[Path] | None = None):
        return self.scan_event({
            "type": "item.completed",
            "item": {
                "id": "fixture-command",
                "type": "command_execution",
                "command": command,
            },
        }, protected)

    def assert_external_mode(self, script: str, expected_mode: str):
        outside = self.root / "outside" / "target.txt"
        scan = self.scan_command(powershell(script.format(path=outside)))
        self.assertTrue(scan["external_path_access_detected"])
        self.assertEqual(
            scan["command_records"][0]["path_candidates"][0]["access_mode"],
            expected_mode,
        )

    def test_exact_r3d_event_proves_legacy_trigger_and_repaired_result(self):
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        command = fixture["event"]["item"]["command"]
        legacy_candidates = _extract_windows_paths(command)
        self.assertEqual(
            _normalized_windows_path(legacy_candidates[0][0]),
            fixture["legacy_first_candidate"],
        )
        self.assertFalse(is_contained(self.worktree, legacy_candidates[0][0]))

        scan = self.scan_event(fixture["event"])
        self.assertFalse(scan["external_path_access_detected"])
        record = scan["command_records"][0]
        self.assertEqual(record["event_index"], 0)
        self.assertEqual(record["executable_paths"][0]["access_mode"], "execute")
        self.assertEqual(record["path_candidates"], [])

    def test_external_file_read_is_rejected(self):
        self.assert_external_mode("Get-Content -LiteralPath '{path}'", "read")

    def test_external_directory_enumeration_is_rejected(self):
        outside = self.root / "outside"
        scan = self.scan_command(
            powershell(f"Get-ChildItem -LiteralPath '{outside}'")
        )
        self.assertTrue(scan["external_path_access_detected"])
        self.assertEqual(
            scan["command_records"][0]["path_candidates"][0]["access_mode"],
            "enumerate",
        )

    def test_external_write_is_rejected(self):
        self.assert_external_mode(
            "Set-Content -LiteralPath '{path}' -Value blocked",
            "write",
        )

    def test_external_delete_is_rejected(self):
        self.assert_external_mode("Remove-Item -LiteralPath '{path}'", "delete")

    def test_router_and_dogfood_source_paths_are_rejected(self):
        for protected in (
            Path(r"C:\Users\sizhe\Documents\model-tier-router"),
            Path(r"C:\Users\sizhe\Documents\model-tier-router-dogfood"),
        ):
            with self.subTest(protected=protected):
                scan = self.scan_command(
                    powershell(f"Get-Content -LiteralPath '{protected / 'README.md'}'"),
                    [protected],
                )
                self.assertTrue(scan["external_path_access_detected"])
                self.assertEqual(
                    scan["command_records"][0]["path_candidates"][0]["protected_root"],
                    str(protected.resolve(strict=False)),
                )

    def test_user_profile_credential_access_is_rejected(self):
        scan = self.scan_command(
            powershell(r"Get-Content $env:USERPROFILE\.ssh\id_rsa")
        )
        self.assertTrue(scan["credential_access_detected"])

    def test_remote_and_forbidden_git_actions_are_rejected(self):
        scan = self.scan_command("git push origin main")
        self.assertTrue(scan["remote_operation_attempted"])
        self.assertTrue(scan["forbidden_action_detected"])

    def test_executable_path_is_recorded_but_is_not_a_data_operand(self):
        scan = self.scan_command(powershell("Get-ChildItem -LiteralPath 'smoke'"))
        self.assertFalse(scan["external_path_access_detected"])
        record = scan["command_records"][0]
        self.assertEqual(record["executable"], PWSH)
        self.assertEqual(record["executable_paths"][0]["access_mode"], "execute")
        self.assertEqual(record["path_candidates"], [])

    def test_workspace_local_absolute_and_relative_paths_are_accepted(self):
        local = self.worktree / "smoke" / "result.txt"
        for command in (
            powershell(f"Get-Content -LiteralPath '{local}'"),
            powershell(r"Get-Content -LiteralPath 'smoke\result.txt'"),
        ):
            with self.subTest(command=command):
                scan = self.scan_command(command)
                self.assertFalse(scan["external_path_access_detected"])

    def test_parent_traversal_is_rejected(self):
        scan = self.scan_command(
            powershell(r"Get-Content -LiteralPath '..\outside\secret.txt'")
        )
        self.assertTrue(scan["external_path_access_detected"])

    def test_case_insensitive_windows_containment_is_accepted(self):
        local = str(self.worktree / "smoke" / "result.txt").upper()
        scan = self.scan_command(powershell(f"Get-Content -LiteralPath '{local}'"))
        self.assertFalse(scan["external_path_access_detected"])

    def test_directory_prefix_collision_is_rejected(self):
        collision = Path(str(self.worktree) + "-escape") / "secret.txt"
        scan = self.scan_command(
            powershell(f"Get-Content -LiteralPath '{collision}'")
        )
        self.assertTrue(scan["external_path_access_detected"])

    def test_quoted_space_and_unicode_paths_are_parsed_and_rejected(self):
        for outside in (
            self.root / "outside folder" / "secret file.txt",
            self.root / "外部目录" / "秘密.txt",
        ):
            with self.subTest(outside=outside):
                scan = self.scan_command(
                    powershell(f"Get-Content -LiteralPath '{outside}'")
                )
                self.assertTrue(scan["external_path_access_detected"])
                self.assertEqual(
                    scan["command_records"][0]["path_candidates"][0]["raw"],
                    str(outside),
                )

    def test_reparse_point_escape_fails_closed(self):
        outside = self.root / "outside"
        outside.mkdir()
        link = self.worktree / "junction"
        if os.name == "nt":
            completed = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(link), str(outside)],
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)
        else:
            link.symlink_to(outside, target_is_directory=True)
        scan = self.scan_command(
            powershell(f"Get-Content -LiteralPath '{link / 'secret.txt'}'")
        )
        self.assertTrue(scan["external_path_access_detected"])
        self.assertFalse(
            scan["command_records"][0]["path_candidates"][0]["inside_worktree"]
        )

    def test_stdout_path_mention_is_not_treated_as_access(self):
        scan = self.scan_event({
            "type": "item.completed",
            "item": {
                "id": "message",
                "type": "agent_message",
                "text": r"Observed C:\Users\sizhe\outside.txt in prose only.",
            },
        })
        self.assertFalse(scan["external_path_access_detected"])
        self.assertEqual(scan["command_records"], [])

    def test_parent_runner_schema_and_output_paths_are_not_child_commands(self):
        scan = self.scan_event({
            "type": "thread.started",
            "schema_path": r"C:\Users\sizhe\packet\schema.json",
            "output_last_message": r"C:\Users\sizhe\packet\result.json",
        })
        self.assertFalse(scan["external_path_access_detected"])
        self.assertEqual(scan["command_records"], [])

    def test_unparseable_or_incomplete_shell_command_fails_closed(self):
        commands = (
            '"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -Command Get-Content',
            f'"{PWSH}" -Command',
        )
        for command in commands:
            with self.subTest(command=command):
                scan = self.scan_command(command)
                self.assertTrue(scan["unparseable_command_detected"])
                self.assertTrue(scan["external_path_access_detected"])

    def test_scanning_does_not_consume_attempt_budget_or_launch_a_process(self):
        accounting = ProcessAccounting(maximum=5)
        before = (
            accounting.os_child_process_started,
            accounting.remaining,
        )
        scan = self.scan_command(powershell("Get-ChildItem -LiteralPath 'smoke'"))
        after = (
            accounting.os_child_process_started,
            accounting.remaining,
        )
        self.assertFalse(scan["external_path_access_detected"])
        self.assertEqual(before, after)
        self.assertEqual(after, (0, 5))


if __name__ == "__main__":
    unittest.main()
