from __future__ import annotations

import hashlib
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
    _windows_path_kind,
)
from mtr_dogfood.runtime_contract import ProcessAccounting


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "r3d-unauthorized-action-event.json"
R3F_FIXTURE = ROOT / "tests" / "fixtures" / "r3f-workspace-relative-path-events.json"
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

    def scan_event(
        self,
        event: dict,
        protected: list[Path] | None = None,
        model_read_only: bool = False,
    ):
        self.events.write_text(json.dumps(event) + "\n", encoding="utf-8")
        return _scan_child_commands(
            self.events,
            protected or [],
            self.worktree,
            model_read_only=model_read_only,
        )

    def scan_command(
        self,
        command: str,
        protected: list[Path] | None = None,
        model_read_only: bool = False,
    ):
        return self.scan_event({
            "type": "item.completed",
            "item": {
                "id": "fixture-command",
                "type": "command_execution",
                "command": command,
            },
        }, protected, model_read_only)

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
        self.assertTrue(record["path_candidates"])
        self.assertTrue(all(
            candidate["inside_worktree"] for candidate in record["path_candidates"]
        ))

    def test_exact_r3f_events_bind_trigger_and_resolve_against_verified_cwd(self):
        fixture = json.loads(R3F_FIXTURE.read_text(encoding="utf-8"))
        raw_lines = []
        for entry in fixture["events"]:
            raw = json.dumps(entry["event"], separators=(",", ":"))
            self.assertEqual(
                hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                entry["raw_json_sha256"],
            )
            self.assertEqual(
                entry["event"]["item"]["command"], fixture["decoded_command"]
            )
            raw_lines.append(raw)

        legacy_input = fixture["pre_repair_extraction_input"]
        offset = fixture["legacy_candidate_offset"]
        legacy = fixture["legacy_candidate"]
        self.assertEqual(legacy_input[offset : offset + len(legacy)], legacy)
        self.assertEqual(legacy_input[offset - 1], ".")
        self.assertFalse(any(
            candidate == legacy
            for candidate, _ in _extract_windows_paths(legacy_input)
        ))

        self.events.write_text(
            "{}\n" * 10 + "\n".join(raw_lines) + "\n", encoding="utf-8"
        )
        cwd = Path(fixture["verified_cwd"])
        scan = _scan_child_commands(self.events, [], cwd)
        self.assertFalse(scan["external_path_access_detected"])
        self.assertEqual(
            [record["event_index"] for record in scan["command_records"]], [10, 11]
        )
        expected = str((cwd / "smoke" / "result.txt").resolve(strict=False))
        for record in scan["command_records"]:
            self.assertEqual(record["shell_string"], fixture["decoded_shell_payload"])
            self.assertEqual(len(record["path_candidates"]), 1)
            candidate = record["path_candidates"][0]
            self.assertEqual(candidate["raw"], fixture["original_path_operand"])
            self.assertEqual(candidate["normalized"], fixture["expected_normalized_path"])
            self.assertEqual(candidate["path_kind"], "relative")
            self.assertEqual(candidate["cwd_resolved"], expected)
            self.assertEqual(candidate["canonical"], expected)
            self.assertEqual(candidate["access_mode"], fixture["expected_access_mode"])
            self.assertTrue(candidate["inside_worktree"])

    def test_exact_mtr_r2_python_literal_is_not_an_external_path(self):
        fixture = ROOT / "tests" / "fixtures" / "mtr-r2-python-literal-path-events.jsonl"
        raw = fixture.read_text(encoding="utf-8").splitlines()
        self.assertEqual(
            [hashlib.sha256(line.encode("utf-8")).hexdigest() for line in raw],
            [
                "678e2d6bcb5f7f3e9d11e1f9c48769fdc4f258b81533ffad2562879556f32964",
                "616206edff24e178b9795f13efa86840fcd19bdc1f8affc81d15be8f559d174d",
            ],
        )
        self.events.write_text("\n".join(raw) + "\n", encoding="utf-8")
        scan = _scan_child_commands(self.events, [], self.worktree)
        self.assertFalse(scan["external_path_access_detected"])
        self.assertEqual(len(scan["command_records"]), 2)
        self.assertTrue(all(
            record["command_source"] == "display_command_fallback"
            and record["path_candidates"] == []
            for record in scan["command_records"]
        ))

    def test_windows_path_kind_taxonomy(self):
        cases = {
            r"smoke\result.txt": "relative",
            r".\smoke\result.txt": "relative",
            r"..\escape.txt": "parent_relative",
            r".\..\escape.txt": "parent_relative",
            r"\rooted.txt": "current_drive_rooted",
            r"C:drive-relative.txt": "drive_relative",
            r"C:\absolute.txt": "drive_absolute",
            r"\\server\share\file.txt": "unc",
            r"\\?\C:\absolute.txt": "extended_absolute",
            r"\\?\UNC\server\share\file.txt": "extended_unc",
            "/workspace/style/path": "posix_absolute",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(_windows_path_kind(value), expected)

    def test_relative_path_forms_resolve_inside_cwd(self):
        cases = (
            r"smoke\result.txt",
            r".\smoke\result.txt",
            r"folder with spaces\result file.txt",
            r"相对目录\结果.txt",
        )
        for relative in cases:
            with self.subTest(relative=relative):
                scan = self.scan_command(
                    powershell(f"Get-Content -LiteralPath '{relative}'")
                )
                self.assertFalse(scan["external_path_access_detected"])
                candidate = scan["command_records"][0]["path_candidates"][0]
                self.assertTrue(candidate["inside_worktree"])
                self.assertEqual(candidate["path_kind"], "relative")

    def test_non_relative_windows_path_kinds_fail_closed(self):
        cases = (
            (r"\rooted.txt", "current_drive_rooted"),
            (r"C:drive-relative.txt", "drive_relative"),
            (r"C:\external\file.txt", "drive_absolute"),
            (r"\\server\share\file.txt", "unc"),
            (r"\\?\C:\external\file.txt", "extended_absolute"),
            (r"\\?\UNC\server\share\file.txt", "extended_unc"),
            ("/workspace/style/path", "posix_absolute"),
        )
        for path, kind in cases:
            with self.subTest(path=path):
                raw_event = {
                    "type": "item.completed",
                    "item": {
                        "id": "transport",
                        "type": "command_execution",
                        "command": powershell(f"Get-Content -LiteralPath '{path}'"),
                    },
                }
                transport = json.dumps(raw_event)
                decoded = json.loads(transport)
                self.assertEqual(decoded, raw_event)
                scan = self.scan_event(decoded)
                self.assertTrue(scan["external_path_access_detected"])
                candidate = scan["command_records"][0]["path_candidates"][0]
                self.assertEqual(candidate["path_kind"], kind)
                self.assertFalse(candidate["inside_worktree"])

    def test_parent_relative_variants_are_rejected(self):
        for path in (r"..\escape.txt", r".\..\escape.txt"):
            with self.subTest(path=path):
                scan = self.scan_command(
                    powershell(f"Get-Content -LiteralPath '{path}'")
                )
                self.assertTrue(scan["external_path_access_detected"])
                self.assertEqual(
                    scan["command_records"][0]["path_candidates"][0]["path_kind"],
                    "parent_relative",
                )

    def test_json_transport_decodes_once_and_true_unc_remains_unc(self):
        command = powershell(r"Get-Content -LiteralPath '\\server\share\file.txt'")
        encoded = json.dumps({"command": command})
        decoded = json.loads(encoded)["command"]
        self.assertEqual(decoded, command)
        scan = self.scan_command(decoded)
        candidate = scan["command_records"][0]["path_candidates"][0]
        self.assertEqual(candidate["raw"], r"\\server\share\file.txt")
        self.assertEqual(candidate["path_kind"], "unc")
        self.assertTrue(scan["external_path_access_detected"])

    def test_repeated_backslashes_in_non_path_text_are_not_rewritten(self):
        literal = r"literal\\name.txt"
        scan = self.scan_command(powershell(f"Write-Output '{literal}'"))
        self.assertFalse(scan["external_path_access_detected"])
        self.assertEqual(scan["command_records"][0]["path_candidates"], [])
        self.assertIn(literal, scan["command_records"][0]["shell_string"])

    def test_structured_event_fields_take_precedence_over_display_command(self):
        event = {
            "type": "item.completed",
            "item": {
                "id": "structured",
                "type": "command_execution",
                "command": powershell(
                    r"Get-Content -LiteralPath '\\server\share\display-only.txt'"
                ),
                "executable": PWSH,
                "argv": [
                    "-Command",
                    r"Get-Content -LiteralPath '.\smoke\structured.txt'",
                ],
                "cwd": str(self.worktree),
            },
        }
        scan = self.scan_event(event)
        self.assertFalse(scan["external_path_access_detected"])
        record = scan["command_records"][0]
        self.assertEqual(record["command_source"], "structured_event")
        self.assertTrue(record["event_cwd_verified"])
        self.assertEqual(record["path_candidates"][0]["path_kind"], "relative")
        self.assertTrue(record["path_candidates"][0]["inside_worktree"])

    def test_structured_event_cwd_mismatch_fails_closed(self):
        event = {
            "type": "item.completed",
            "item": {
                "id": "mismatched-cwd",
                "type": "command_execution",
                "executable": PWSH,
                "argv": ["-Command", "Get-Content -LiteralPath 'smoke.txt'"],
                "cwd": str(self.root / "outside"),
            },
        }
        scan = self.scan_event(event)
        self.assertTrue(scan["external_path_access_detected"])
        self.assertTrue(scan["unparseable_command_detected"])
        self.assertFalse(scan["command_records"][0]["event_cwd_verified"])

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
        self.assertEqual(len(record["path_candidates"]), 1)
        self.assertEqual(record["path_candidates"][0]["raw"], "smoke")
        self.assertTrue(record["path_candidates"][0]["inside_worktree"])

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

    def test_bitconverter_hash_format_is_not_a_direct_write(self):
        scan = self.scan_command(
            powershell(
                "$sha = [byte[]](0); "
                "[BitConverter]::ToString($sha).Replace('-', '').ToLowerInvariant()"
            ),
            model_read_only=True,
        )
        self.assertFalse(scan["model_direct_write_attempt_detected"])
        self.assertFalse(scan["bounded_write_violation_detected"])
        self.assertFalse(scan["command_records"][0]["write_capable"])

    def test_node_stdout_hash_emit_is_not_a_direct_write(self):
        scan = self.scan_command(
            "node -e \"process.stdout.write(require('crypto')"
            ".createHash('sha256').update('WORKSPACE_WRITE_OK\\n')"
            ".digest('hex'))\"",
            model_read_only=True,
        )
        self.assertFalse(scan["model_direct_write_attempt_detected"])
        self.assertFalse(scan["bounded_write_violation_detected"])
        self.assertFalse(scan["command_records"][0]["write_capable"])

    def test_safe_hash_format_does_not_mask_a_real_write(self):
        scan = self.scan_command(
            powershell(
                "$sha = [byte[]](0); "
                "[BitConverter]::ToString($sha).Replace('-', ''); "
                "Set-Content -LiteralPath '.\\smoke\\result.txt' -Value blocked"
            ),
            model_read_only=True,
        )
        self.assertTrue(scan["model_direct_write_attempt_detected"])
        self.assertTrue(scan["bounded_write_security_violation_detected"])
        self.assertTrue(scan["command_records"][0]["write_capable"])

    def test_safe_stdio_emit_does_not_mask_another_stream_write(self):
        scan = self.scan_command(
            "node -e \"process.stdout.write('ok'); stream.write('blocked')\"",
            model_read_only=True,
        )
        self.assertTrue(scan["model_direct_write_attempt_detected"])
        self.assertTrue(scan["bounded_write_security_violation_detected"])
        self.assertTrue(scan["command_records"][0]["write_capable"])

    def test_parent_runner_schema_and_output_paths_are_not_child_commands(self):
        scan = self.scan_event({
            "type": "thread.started",
            "schema_path": r"C:\Users\sizhe\packet\schema.json",
            "output_last_message": r"C:\Users\sizhe\packet\result.json",
        })
        self.assertFalse(scan["external_path_access_detected"])
        self.assertEqual(scan["command_records"], [])

    def test_unparseable_shell_is_indeterminate_without_invented_external_access(self):
        commands = (
            '"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -Command Get-Content',
            f'"{PWSH}" -Command',
        )
        for command in commands:
            with self.subTest(command=command):
                scan = self.scan_command(command)
                self.assertTrue(scan["unparseable_command_detected"])
                self.assertFalse(scan["external_path_access_detected"])

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
