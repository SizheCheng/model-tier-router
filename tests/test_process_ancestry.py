from __future__ import annotations

import unittest

from mtr_dogfood.process_ancestry import (
    NestedCodexAncestorError,
    verify_standalone_powershell,
)


def provider_for(rows):
    calls = []

    def provider(pid):
        calls.append(pid)
        return rows.get(pid)

    provider.calls = calls
    return provider


class ProcessAncestryTests(unittest.TestCase):
    def test_ordinary_powershell_ancestor_fixture_is_accepted(self):
        provider = provider_for({
            100: {
                "pid": 100,
                "parent_pid": 50,
                "name": "powershell.exe",
                "executable_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            },
            50: {
                "pid": 50,
                "parent_pid": 0,
                "name": "explorer.exe",
                "executable_path": r"C:\Windows\explorer.exe",
            },
        })
        receipt = verify_standalone_powershell(100, provider)
        self.assertTrue(receipt["ordinary_powershell_ancestor_verified"])
        self.assertFalse(receipt["nested_codex_ancestor_detected"])

    def test_codex_direct_parent_fixture_is_rejected(self):
        provider = provider_for({
            100: {"pid": 100, "parent_pid": 90, "name": "powershell.exe"},
            90: {"pid": 90, "parent_pid": 0, "name": "codex.exe"},
        })
        with self.assertRaises(NestedCodexAncestorError) as raised:
            verify_standalone_powershell(100, provider)
        self.assertEqual(
            raised.exception.receipt["hard_stop_code"],
            "NESTED_CODEX_ANCESTOR_DETECTED",
        )

    def test_codex_grandparent_fixture_is_rejected(self):
        provider = provider_for({
            100: {"pid": 100, "parent_pid": 90, "name": "powershell.exe"},
            90: {"pid": 90, "parent_pid": 80, "name": "cmd.exe"},
            80: {"pid": 80, "parent_pid": 0, "name": "codex-cli.exe"},
        })
        with self.assertRaises(NestedCodexAncestorError):
            verify_standalone_powershell(100, provider)

    def test_harness_child_parent_fixture_is_rejected(self):
        provider = provider_for({
            100: {"pid": 100, "parent_pid": 90, "name": "powershell.exe"},
            90: {
                "pid": 90,
                "parent_pid": 0,
                "name": "external-dogfood-runner.exe",
            },
        })
        with self.assertRaises(NestedCodexAncestorError):
            verify_standalone_powershell(100, provider)

    def test_unrelated_parallel_codex_process_is_not_queried_or_rejected(self):
        provider = provider_for({
            100: {"pid": 100, "parent_pid": 50, "name": "powershell.exe"},
            50: {"pid": 50, "parent_pid": 0, "name": "explorer.exe"},
            777: {"pid": 777, "parent_pid": 0, "name": "codex.exe"},
        })
        receipt = verify_standalone_powershell(100, provider)
        self.assertFalse(receipt["nested_codex_ancestor_detected"])
        self.assertEqual(provider.calls, [100, 50])

    def test_sanitized_metadata_never_persists_raw_command_lines(self):
        provider = provider_for({
            100: {
                "pid": 100,
                "parent_pid": 0,
                "name": "powershell.exe",
                "executable_path": r"C:\Windows\powershell.exe",
                "command_line": "powershell.exe secret-token private-prompt",
                "environment": {"SECRET": "value"},
            },
        })
        receipt = verify_standalone_powershell(100, provider)
        row = receipt["ancestors"][0]
        self.assertEqual(
            set(row),
            {"pid", "parent_pid", "executable_name", "command_identity"},
        )
        self.assertNotIn("secret-token", str(receipt))
        self.assertNotIn("private-prompt", str(receipt))


if __name__ == "__main__":
    unittest.main()
