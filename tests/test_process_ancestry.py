from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from mtr_dogfood.process_ancestry import (
    NestedCodexAncestorError,
    ProcessAncestryError,
    sanitize_process_record,
    verify_standalone_powershell,
    walk_ancestor_chain,
)


FIXTURE_PATH = (
    Path(__file__).parent / "fixtures" / "r5f_ancestry_precheck_snapshot.json"
)
USER_SID = "S-1-5-21-3094882294-810501253-2852307982-1001"
SNAPSHOT_TIME = "2026-07-21T06:09:14Z"


def process_row(
    pid,
    parent_pid,
    name,
    minute,
    *,
    executable_path=None,
    command_line=None,
    **identity,
):
    value = {
        "pid": pid,
        "parent_pid": parent_pid,
        "name": name,
        "executable_path": (
            executable_path
            if executable_path is not None
            else rf"C:\Windows\{name}"
        ),
        "creation_time_utc": f"2026-07-21T00:{minute:02d}:00Z",
        **identity,
    }
    if command_line is not None:
        value["command_line"] = command_line
    return value


def trusted_explorer(pid=50, parent_pid=4772, minute=1, **overrides):
    value = process_row(
        pid,
        parent_pid,
        "explorer.exe",
        minute,
        executable_path=r"C:\Windows\explorer.exe",
        session_id=1,
        user_sid=USER_SID,
        process_alive=True,
        parent_present_in_snapshot=False,
        shell_window_process_id=pid,
        is_current_session_shell=True,
        signature_status="Valid",
        signer_subject="CN=Microsoft Windows, O=Microsoft Corporation",
        executable_sha256="a" * 64,
        identity_query_status="complete",
        snapshot_captured_at_utc=SNAPSHOT_TIME,
    )
    value.update(overrides)
    return value


def trusted_runner(pid=100, parent_pid=50, minute=2, **overrides):
    value = process_row(
        pid,
        parent_pid,
        "powershell.exe",
        minute,
        session_id=1,
        user_sid=USER_SID,
        process_alive=True,
        parent_present_in_snapshot=True,
        shell_window_process_id=50,
        is_current_session_shell=False,
        identity_query_status="captured",
        snapshot_captured_at_utc=SNAPSHOT_TIME,
    )
    value.update(overrides)
    return value


def provider_for(rows):
    calls = []

    def provider(pid):
        calls.append(pid)
        return rows.get(pid)

    provider.calls = calls
    return provider


def fixture_rows():
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    return fixture, {row["pid"]: row for row in fixture["processes"]}


class ProcessAncestryTests(unittest.TestCase):
    def assert_nested(self, rows):
        with self.assertRaises(NestedCodexAncestorError) as raised:
            verify_standalone_powershell(100, provider_for(rows))
        receipt = raised.exception.receipt
        self.assertEqual(
            receipt["hard_stop_code"], "NESTED_CODEX_ANCESTOR_DETECTED"
        )
        self.assertEqual(
            receipt["completion_classification"], "PROVEN_CODEX_ANCESTOR"
        )
        return receipt

    def assert_failed(self, rows, code):
        with self.assertRaises(ProcessAncestryError) as raised:
            verify_standalone_powershell(100, provider_for(rows))
        self.assertNotIsInstance(raised.exception, NestedCodexAncestorError)
        self.assertEqual(raised.exception.code, code)
        self.assertFalse(raised.exception.receipt["evidence_complete"])
        return raised.exception.receipt

    def assert_anchor_failure(self, **overrides):
        return self.assert_failed(
            {100: trusted_runner(), 50: trusted_explorer(**overrides)},
            "TRUSTED_SHELL_ANCHOR_IDENTITY_FAILED",
        )

    def test_exact_r5f_fixture_reproduces_old_incomplete_semantics(self):
        _, rows = fixture_rows()
        with self.assertRaises(ProcessAncestryError) as raised:
            walk_ancestor_chain(24572, provider_for(rows))
        self.assertEqual(raised.exception.code, "PROCESS_ANCESTRY_INCOMPLETE")
        self.assertEqual([r["pid"] for r in raised.exception.records], [24572, 8404])

    def test_exact_r5f_fixture_is_accepted_by_repaired_semantics(self):
        fixture, rows = fixture_rows()
        receipt = verify_standalone_powershell(
            24572,
            provider_for(rows),
            explorer_path=fixture["expected_explorer_path"],
        )
        self.assertEqual(
            receipt["completion_classification"],
            "ANCESTRY_VERIFIED_TO_TRUSTED_WINDOWS_SHELL_ANCHOR",
        )
        self.assertTrue(receipt["trusted_shell_anchor"]["identity_verified"])

    def test_explorer_path_spoof_is_rejected(self):
        self.assert_anchor_failure(executable_path=r"C:\Temp\explorer.exe")

    def test_renamed_non_explorer_is_not_an_anchor(self):
        rows = {
            100: trusted_runner(),
            50: process_row(50, 4772, "renamed-shell.exe", 1),
        }
        self.assert_failed(rows, "ANCESTRY_PARENT_MISSING_BEFORE_TRUST_ANCHOR")

    def test_explorer_in_another_session_is_rejected(self):
        self.assert_anchor_failure(session_id=2)

    def test_explorer_under_another_user_is_rejected(self):
        self.assert_anchor_failure(user_sid="S-1-5-21-OTHER")

    def test_explorer_not_current_session_shell_is_rejected(self):
        self.assert_anchor_failure(is_current_session_shell=False)

    def test_explorer_shell_window_pid_mismatch_is_rejected(self):
        self.assert_anchor_failure(shell_window_process_id=999)

    def test_explorer_identity_query_failure_is_rejected(self):
        self.assert_anchor_failure(identity_query_status="incomplete")

    def test_missing_explorer_parent_is_accepted_only_after_identity_proof(self):
        receipt = verify_standalone_powershell(
            100, provider_for({100: trusted_runner(), 50: trusted_explorer()})
        )
        self.assertEqual(receipt["completion_mode"], "verified_interactive_shell_anchor")
        self.assertIn("parent_absent", receipt["termination_reason"])

    def test_missing_parent_before_anchor_is_rejected(self):
        receipt = self.assert_failed(
            {100: trusted_runner(parent_pid=70)},
            "ANCESTRY_PARENT_MISSING_BEFORE_TRUST_ANCHOR",
        )
        self.assertEqual(receipt["ancestor_count"], 1)

    def test_queryable_explorer_parent_continues_to_os_root(self):
        provider = provider_for({
            100: trusted_runner(),
            50: trusted_explorer(parent_pid=10, parent_present_in_snapshot=True),
            10: process_row(10, 0, "cmd.exe", 0),
        })
        receipt = verify_standalone_powershell(100, provider)
        self.assertEqual(
            receipt["completion_classification"], "ANCESTRY_VERIFIED_TO_OS_ROOT"
        )
        self.assertEqual(provider.calls, [100, 50, 10])

    def test_parent_marked_live_but_unavailable_is_rejected(self):
        self.assert_failed(
            {
                100: trusted_runner(),
                50: trusted_explorer(parent_present_in_snapshot=True),
            },
            "ANCESTRY_PID_INCONSISTENT",
        )

    def test_pid_identity_mismatch_is_rejected(self):
        self.assert_failed(
            {
                100: trusted_runner(),
                50: trusted_explorer(pid=51),
            },
            "ANCESTRY_PID_INCONSISTENT",
        )

    def test_creation_time_inversion_is_rejected(self):
        self.assert_failed(
            {100: trusted_runner(minute=2), 50: trusted_explorer(minute=3)},
            "ANCESTRY_CREATION_TIME_INCONSISTENT",
        )

    def test_ancestor_cycle_is_rejected(self):
        self.assert_failed(
            {
                100: trusted_runner(),
                50: trusted_explorer(
                    parent_pid=100, parent_present_in_snapshot=True
                ),
            },
            "PROCESS_ANCESTRY_CYCLE_DETECTED",
        )

    def test_explorer_to_powershell_is_accepted(self):
        receipt = verify_standalone_powershell(
            100, provider_for({100: trusted_runner(), 50: trusted_explorer()})
        )
        self.assertTrue(receipt["ordinary_powershell_ancestor_verified"])

    def test_explorer_windows_terminal_powershell_is_accepted(self):
        receipt = verify_standalone_powershell(100, provider_for({
            100: trusted_runner(parent_pid=70, minute=3),
            70: process_row(70, 50, "WindowsTerminal.exe", 2),
            50: trusted_explorer(),
        }))
        self.assertEqual(receipt["ancestor_count"], 3)

    def test_explorer_cmd_powershell_is_accepted(self):
        receipt = verify_standalone_powershell(100, provider_for({
            100: trusted_runner(parent_pid=70, minute=3),
            70: process_row(70, 50, "cmd.exe", 2),
            50: trusted_explorer(),
        }))
        self.assertTrue(receipt["ordinary_powershell_ancestor_verified"])

    def test_multiple_ordinary_powershell_ancestors_are_accepted(self):
        receipt = verify_standalone_powershell(100, provider_for({
            100: trusted_runner(parent_pid=80, minute=4),
            80: process_row(80, 60, "pwsh.exe", 3),
            60: process_row(60, 50, "powershell.exe", 2),
            50: trusted_explorer(),
        }))
        self.assertEqual(receipt["ancestor_count"], 4)

    def test_codex_app_ancestor_is_rejected(self):
        self.assert_nested({
            100: trusted_runner(parent_pid=90, minute=4),
            90: process_row(90, 50, "codex-app.exe", 3),
            50: trusted_explorer(),
        })

    def test_codex_cli_ancestor_is_rejected(self):
        self.assert_nested({
            100: trusted_runner(parent_pid=90, minute=4),
            90: process_row(90, 50, "codex.exe", 3),
            50: trusted_explorer(),
        })

    def test_node_hosted_codex_cli_ancestor_is_rejected(self):
        receipt = self.assert_nested({
            100: trusted_runner(parent_pid=90, minute=4),
            90: process_row(
                90,
                50,
                "node.exe",
                3,
                executable_path=r"C:\Program Files\nodejs\node.exe",
                command_line=r'node.exe "C:\tools\@openai\codex\bin\codex.js" exec',
            ),
            50: trusted_explorer(),
        })
        self.assertEqual(
            receipt["trigger_process"]["command_classification"],
            "node_hosted_codex_cli",
        )

    def test_embedded_terminal_descended_from_codex_is_rejected(self):
        self.assert_nested({
            100: trusted_runner(parent_pid=90, minute=5),
            90: process_row(90, 80, "WindowsTerminal.exe", 4),
            80: process_row(80, 50, "chatgpt.exe", 3),
            50: trusted_explorer(),
        })

    def test_unrelated_live_codex_process_is_ignored(self):
        provider = provider_for({
            100: trusted_runner(),
            50: trusted_explorer(),
            777: process_row(777, 0, "codex.exe", 0),
        })
        receipt = verify_standalone_powershell(100, provider)
        self.assertFalse(receipt["nested_codex_ancestor_detected"])
        self.assertNotIn(777, provider.calls)

    def test_command_text_mentioning_codex_does_not_trigger(self):
        receipt = verify_standalone_powershell(100, provider_for({
            100: trusted_runner(command_line='powershell -Command "echo codex"'),
            50: trusted_explorer(),
        }))
        self.assertFalse(receipt["nested_codex_ancestor_detected"])

    def test_path_merely_containing_codex_does_not_trigger(self):
        receipt = verify_standalone_powershell(100, provider_for({
            100: process_row(100, 50, "powershell.exe", 2),
            50: process_row(
                50,
                0,
                "cmd.exe",
                1,
                executable_path=r"C:\Users\codex-notes\cmd.exe",
            ),
        }))
        self.assertFalse(receipt["nested_codex_ancestor_detected"])

    def test_precheck_and_runner_calls_use_identical_semantics(self):
        rows = {100: trusted_runner(), 50: trusted_explorer()}
        precheck = verify_standalone_powershell(100, provider_for(copy.deepcopy(rows)))
        runner = verify_standalone_powershell(100, provider_for(copy.deepcopy(rows)))
        self.assertEqual(precheck, runner)

    def test_operating_system_root_completion_remains_supported(self):
        receipt = verify_standalone_powershell(100, provider_for({
            100: process_row(100, 50, "powershell.exe", 2),
            50: process_row(50, 0, "cmd.exe", 1),
        }))
        self.assertEqual(
            receipt["completion_classification"], "ANCESTRY_VERIFIED_TO_OS_ROOT"
        )

    def test_explorer_named_os_root_still_requires_trusted_identity(self):
        self.assert_failed(
            {
                100: process_row(100, 50, "powershell.exe", 2),
                50: process_row(50, 0, "explorer.exe", 1),
            },
            "TRUSTED_SHELL_ANCHOR_IDENTITY_FAILED",
        )

    def test_invalid_signature_is_rejected(self):
        self.assert_anchor_failure(signature_status="NotSigned")

    def test_non_microsoft_signer_is_rejected(self):
        self.assert_anchor_failure(signer_subject="CN=Example Corporation")

    def test_missing_executable_hash_is_rejected(self):
        self.assert_anchor_failure(executable_sha256="")

    def test_missing_user_identity_is_rejected(self):
        self.assert_anchor_failure(user_sid="")

    def test_missing_runner_user_identity_is_rejected(self):
        self.assert_failed(
            {100: trusted_runner(user_sid=""), 50: trusted_explorer()},
            "TRUSTED_SHELL_ANCHOR_IDENTITY_FAILED",
        )

    def test_missing_session_identity_is_rejected(self):
        self.assert_anchor_failure(session_id=None)

    def test_parent_absence_must_be_from_snapshot(self):
        self.assert_anchor_failure(parent_present_in_snapshot=None)

    def test_snapshot_timestamp_is_required(self):
        self.assert_anchor_failure(snapshot_captured_at_utc="")

    def test_exited_explorer_is_rejected(self):
        self.assert_anchor_failure(process_alive=False)

    def test_arbitrary_windows_terminal_with_missing_parent_is_rejected(self):
        self.assert_failed(
            {
                100: trusted_runner(parent_pid=70),
                70: process_row(70, 4772, "WindowsTerminal.exe", 1),
            },
            "ANCESTRY_PARENT_MISSING_BEFORE_TRUST_ANCHOR",
        )

    def test_nonpowershell_runner_is_rejected_distinctly(self):
        with self.assertRaises(ProcessAncestryError) as raised:
            verify_standalone_powershell(
                100, provider_for({100: process_row(100, 0, "cmd.exe", 2)})
            )
        self.assertEqual(raised.exception.code, "NONORDINARY_POWERSHELL_RUNNER")

    def test_harness_child_ancestor_is_rejected(self):
        self.assert_nested({
            100: trusted_runner(parent_pid=90, minute=4),
            90: process_row(90, 50, "external-dogfood-runner.exe", 3),
            50: trusted_explorer(),
        })

    def test_unknown_os_root_is_ambiguous(self):
        with self.assertRaises(ProcessAncestryError) as raised:
            verify_standalone_powershell(100, provider_for({
                100: process_row(100, 90, "powershell.exe", 3),
                90: process_row(90, 0, "unknown-host.exe", 2),
            }))
        self.assertEqual(
            raised.exception.code, "ANCESTRY_CLASSIFICATION_AMBIGUOUS"
        )

    def test_inaccessible_parent_metadata_fails_closed(self):
        rows = {100: trusted_runner(parent_pid=50)}

        def provider(pid):
            if pid == 50:
                raise ProcessAncestryError("PROCESS_ANCESTRY_METADATA_INACCESSIBLE")
            return rows.get(pid)

        with self.assertRaises(ProcessAncestryError) as raised:
            verify_standalone_powershell(100, provider)
        self.assertEqual(
            raised.exception.code, "PROCESS_ANCESTRY_METADATA_INACCESSIBLE"
        )

    def test_legacy_depth_limit_still_fails_closed(self):
        with self.assertRaises(ProcessAncestryError) as raised:
            walk_ancestor_chain(
                100,
                provider_for({
                    100: process_row(100, 90, "powershell.exe", 3),
                    90: process_row(90, 0, "explorer.exe", 2),
                }),
                maximum_depth=1,
            )
        self.assertEqual(raised.exception.code, "PROCESS_ANCESTRY_DEPTH_EXCEEDED")

    def test_raw_command_line_is_not_persisted(self):
        row = sanitize_process_record(process_row(
            100,
            0,
            "powershell.exe",
            2,
            command_line="powershell.exe secret-token private-prompt",
        ))
        self.assertNotIn("command_line", row)
        self.assertNotIn("secret-token", str(row))
        self.assertNotIn("private-prompt", str(row))


if __name__ == "__main__":
    unittest.main()
