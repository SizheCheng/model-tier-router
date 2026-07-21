from __future__ import annotations

import unittest

from mtr_dogfood.process_ancestry import (
    NestedCodexAncestorError,
    ProcessAncestryError,
    sanitize_process_record,
    verify_standalone_powershell,
    walk_ancestor_chain,
)


def process_row(
    pid,
    parent_pid,
    name,
    minute,
    *,
    executable_path=None,
    command_line=None,
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
    }
    if command_line is not None:
        value["command_line"] = command_line
    return value


def provider_for(rows):
    calls = []

    def provider(pid):
        calls.append(pid)
        return rows.get(pid)

    provider.calls = calls
    return provider


class ProcessAncestryTests(unittest.TestCase):
    def assert_nested(self, rows):
        with self.assertRaises(NestedCodexAncestorError) as raised:
            verify_standalone_powershell(100, provider_for(rows))
        self.assertEqual(
            raised.exception.receipt["hard_stop_code"],
            "NESTED_CODEX_ANCESTOR_DETECTED",
        )
        return raised.exception.receipt

    def assert_incomplete(self, rows, code="PROCESS_ANCESTRY_INCOMPLETE"):
        with self.assertRaises(ProcessAncestryError) as raised:
            verify_standalone_powershell(100, provider_for(rows))
        self.assertNotIsInstance(raised.exception, NestedCodexAncestorError)
        self.assertEqual(raised.exception.code, code)
        self.assertFalse(raised.exception.receipt["evidence_complete"])
        return raised.exception.receipt

    def test_explorer_to_powershell_ordinary_chain_is_accepted(self):
        provider = provider_for({
            100: process_row(100, 50, "powershell.exe", 2),
            50: process_row(50, 0, "explorer.exe", 1),
        })
        receipt = verify_standalone_powershell(100, provider)
        self.assertTrue(receipt["ordinary_powershell_ancestor_verified"])
        self.assertTrue(receipt["evidence_complete"])
        self.assertFalse(receipt["nested_codex_ancestor_detected"])

    def test_windows_terminal_ordinary_chain_is_accepted(self):
        receipt = verify_standalone_powershell(100, provider_for({
            100: process_row(100, 70, "powershell.exe", 3),
            70: process_row(70, 50, "WindowsTerminal.exe", 2),
            50: process_row(50, 0, "explorer.exe", 1),
        }))
        self.assertEqual(
            [row["process_class"] for row in receipt["ancestors"]],
            ["ordinary_shell", "ordinary_shell", "ordinary_shell"],
        )

    def test_cmd_to_powershell_ordinary_chain_is_accepted(self):
        receipt = verify_standalone_powershell(100, provider_for({
            100: process_row(100, 70, "powershell.exe", 3),
            70: process_row(70, 50, "cmd.exe", 2),
            50: process_row(50, 0, "explorer.exe", 1),
        }))
        self.assertTrue(receipt["ordinary_powershell_ancestor_verified"])

    def test_multiple_ordinary_powershell_ancestors_are_accepted(self):
        receipt = verify_standalone_powershell(100, provider_for({
            100: process_row(100, 80, "powershell.exe", 4),
            80: process_row(80, 60, "pwsh.exe", 3),
            60: process_row(60, 50, "powershell.exe", 2),
            50: process_row(50, 0, "explorer.exe", 1),
        }))
        self.assertEqual(receipt["ancestor_count"], 4)

    def test_codex_app_ancestor_is_rejected(self):
        self.assert_nested({
            100: process_row(100, 90, "powershell.exe", 3),
            90: process_row(90, 0, "codex-app.exe", 2),
        })

    def test_codex_cli_ancestor_is_rejected(self):
        self.assert_nested({
            100: process_row(100, 90, "powershell.exe", 3),
            90: process_row(90, 0, "codex.exe", 2),
        })

    def test_node_hosted_codex_cli_ancestor_is_rejected(self):
        receipt = self.assert_nested({
            100: process_row(100, 90, "powershell.exe", 3),
            90: process_row(
                90,
                0,
                "node.exe",
                2,
                executable_path=r"C:\Program Files\nodejs\node.exe",
                command_line=(
                    r'node.exe "C:\tools\@openai\codex\bin\codex.js" exec'
                ),
            ),
        })
        self.assertEqual(
            receipt["trigger_process"]["command_classification"],
            "node_hosted_codex_cli",
        )

    def test_embedded_terminal_descended_from_codex_app_is_rejected(self):
        self.assert_nested({
            100: process_row(100, 90, "powershell.exe", 4),
            90: process_row(90, 80, "WindowsTerminal.exe", 3),
            80: process_row(80, 0, "chatgpt.exe", 2),
        })

    def test_unrelated_parallel_codex_process_is_not_queried_or_rejected(self):
        provider = provider_for({
            100: process_row(100, 50, "powershell.exe", 2),
            50: process_row(50, 0, "explorer.exe", 1),
            777: process_row(777, 0, "codex.exe", 1),
        })
        receipt = verify_standalone_powershell(100, provider)
        self.assertFalse(receipt["nested_codex_ancestor_detected"])
        self.assertEqual(provider.calls, [100, 50])

    def test_process_name_containing_codex_is_not_classified_as_codex(self):
        with self.assertRaises(ProcessAncestryError) as raised:
            verify_standalone_powershell(100, provider_for({
                100: process_row(100, 90, "powershell.exe", 3),
                90: process_row(90, 0, "codex-notes-viewer.exe", 2),
            }))
        self.assertEqual(
            raised.exception.code,
            "PROCESS_ANCESTRY_CLASSIFICATION_AMBIGUOUS",
        )
        self.assertNotIsInstance(raised.exception, NestedCodexAncestorError)

    def test_path_containing_codex_does_not_reclassify_explorer(self):
        receipt = verify_standalone_powershell(100, provider_for({
            100: process_row(100, 50, "powershell.exe", 2),
            50: process_row(
                50,
                0,
                "explorer.exe",
                1,
                executable_path=r"C:\Users\codex-notes\explorer.exe",
            ),
        }))
        self.assertFalse(receipt["nested_codex_ancestor_detected"])

    def test_command_line_mentioning_codex_text_is_not_execution_identity(self):
        receipt = verify_standalone_powershell(100, provider_for({
            100: process_row(
                100,
                50,
                "powershell.exe",
                2,
                command_line='powershell.exe -Command "Write-Output codex"',
            ),
            50: process_row(50, 0, "explorer.exe", 1),
        }))
        self.assertFalse(receipt["nested_codex_ancestor_detected"])

    def test_missing_parent_fails_closed_with_distinct_code(self):
        receipt = self.assert_incomplete({
            100: process_row(100, 50, "powershell.exe", 2),
        })
        self.assertEqual(receipt["ancestor_count"], 1)
        self.assertFalse(receipt["nested_codex_ancestor_detected"])

    def test_inaccessible_parent_metadata_fails_closed(self):
        rows = {100: process_row(100, 50, "powershell.exe", 2)}

        def provider(pid):
            if pid == 50:
                raise ProcessAncestryError(
                    "PROCESS_ANCESTRY_METADATA_INACCESSIBLE"
                )
            return rows.get(pid)

        with self.assertRaises(ProcessAncestryError) as raised:
            verify_standalone_powershell(100, provider)
        self.assertEqual(
            raised.exception.code,
            "PROCESS_ANCESTRY_METADATA_INACCESSIBLE",
        )
        self.assertFalse(raised.exception.receipt["evidence_complete"])

    def test_pid_reuse_creation_time_mismatch_fails_closed(self):
        receipt = self.assert_incomplete(
            {
                100: process_row(100, 50, "powershell.exe", 2),
                50: process_row(50, 0, "explorer.exe", 3),
            },
            "PROCESS_ANCESTRY_PID_REUSE_OR_SNAPSHOT_INCONSISTENT",
        )
        self.assertEqual(receipt["ancestor_count"], 2)

    def test_ancestor_cycle_is_detected(self):
        self.assert_incomplete(
            {
                100: process_row(100, 50, "powershell.exe", 3),
                50: process_row(50, 100, "explorer.exe", 2),
            },
            "PROCESS_ANCESTRY_CYCLE_DETECTED",
        )

    def test_captured_snapshot_remains_classifiable_after_process_exit(self):
        rows = {
            100: process_row(100, 50, "powershell.exe", 2),
            50: process_row(50, 0, "explorer.exe", 1),
        }

        def provider(pid):
            return rows.pop(pid, None)

        receipt = verify_standalone_powershell(100, provider)
        self.assertTrue(receipt["ordinary_powershell_ancestor_verified"])
        self.assertEqual(rows, {})

    def test_wt_host_is_accepted_when_ordinary(self):
        receipt = verify_standalone_powershell(100, provider_for({
            100: process_row(100, 70, "pwsh.exe", 3),
            70: process_row(70, 50, "wt.exe", 2),
            50: process_row(50, 0, "explorer.exe", 1),
        }))
        self.assertTrue(receipt["ordinary_powershell_ancestor_verified"])

    def test_historical_r5d_fixture_reproduces_incomplete_original_result(self):
        legacy_receipt = {
            "complete": False,
            "nested_codex_detected": False,
            "ordinary_powershell": True,
            "passed": False,
            "records": [
                {"pid": 23308, "parent_pid": 8404, "name": "powershell.exe"},
                {"pid": 8404, "parent_pid": 4772, "name": "explorer.exe"},
            ],
        }
        self.assertFalse(legacy_receipt["passed"])
        self.assertFalse(legacy_receipt["complete"])
        self.assertFalse(legacy_receipt["nested_codex_detected"])

    def test_historical_r5d_fixture_gets_incomplete_not_nested_classification(self):
        rows = {
            23308: process_row(23308, 8404, "powershell.exe", 3),
            8404: process_row(8404, 4772, "explorer.exe", 2),
        }
        with self.assertRaises(ProcessAncestryError) as raised:
            verify_standalone_powershell(23308, provider_for(rows))
        receipt = raised.exception.receipt
        self.assertEqual(
            raised.exception.code,
            "PROCESS_ANCESTRY_INCOMPLETE",
        )
        self.assertEqual(receipt["hard_stop_code"], "PROCESS_ANCESTRY_INCOMPLETE")
        self.assertFalse(receipt["nested_codex_ancestor_detected"])

    def test_nonpowershell_runner_is_rejected_distinctly(self):
        with self.assertRaises(ProcessAncestryError) as raised:
            verify_standalone_powershell(100, provider_for({
                100: process_row(100, 0, "cmd.exe", 2),
            }))
        self.assertEqual(raised.exception.code, "NONORDINARY_POWERSHELL_RUNNER")

    def test_harness_child_ancestor_is_rejected(self):
        self.assert_nested({
            100: process_row(100, 90, "powershell.exe", 3),
            90: process_row(90, 0, "external-dogfood-runner.exe", 2),
        })

    def test_depth_limit_fails_closed(self):
        with self.assertRaises(ProcessAncestryError) as raised:
            walk_ancestor_chain(
                100,
                provider_for({
                    100: process_row(100, 90, "powershell.exe", 3),
                    90: process_row(90, 0, "explorer.exe", 2),
                }),
                maximum_depth=1,
            )
        self.assertEqual(
            raised.exception.code,
            "PROCESS_ANCESTRY_DEPTH_EXCEEDED",
        )

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

    def test_captured_codex_is_rejected_even_if_older_parent_is_missing(self):
        receipt = self.assert_nested({
            100: process_row(100, 90, "powershell.exe", 4),
            90: process_row(90, 80, "codex.exe", 3),
        })
        self.assertFalse(receipt["evidence_complete"])
        self.assertTrue(receipt["nested_codex_ancestor_detected"])


if __name__ == "__main__":
    unittest.main()
