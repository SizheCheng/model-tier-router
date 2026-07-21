from __future__ import annotations

import unittest

from mtr_dogfood.source_integrity import (
    repository_integrity_status,
    stable_git_ref_lines,
)


class SourceIntegritySemanticsTests(unittest.TestCase):
    def test_pass_is_reported_only_when_checks_executed(self):
        receipt = repository_integrity_status(
            checks_executed=True,
            unchanged=True,
        )
        self.assertEqual(receipt["status"], "passed")
        self.assertTrue(receipt["unchanged"])
        self.assertEqual(receipt["mismatches"], [])

    def test_not_evaluated_is_not_false_mutation(self):
        receipt = repository_integrity_status(
            checks_executed=False,
            unchanged=None,
        )
        self.assertEqual(receipt["status"], "not_evaluated")
        self.assertNotIn("unchanged", receipt)
        self.assertFalse(receipt["checks_executed"])

    def test_unexecuted_check_cannot_report_false(self):
        with self.assertRaises(ValueError):
            repository_integrity_status(
                checks_executed=False,
                unchanged=False,
            )

    def test_real_source_mismatch_remains_failure(self):
        receipt = repository_integrity_status(
            checks_executed=True,
            unchanged=False,
            mismatches=["router_source"],
        )
        self.assertEqual(receipt["status"], "failed")
        self.assertFalse(receipt["unchanged"])
        self.assertEqual(receipt["mismatches"], ["router_source"])

    def test_incomplete_check_has_null_boolean(self):
        receipt = repository_integrity_status(
            checks_executed=True,
            unchanged=None,
            mismatches=["metadata_unavailable"],
        )
        self.assertEqual(receipt["status"], "incomplete")
        self.assertNotIn("unchanged", receipt)

    def test_codex_turn_diff_refs_are_excluded_from_source_identity(self):
        lines = [
            "a" * 40 + " refs/heads/main",
            "b" * 40 + " refs/codex/turn-diffs/captures/123/session/base",
        ]
        self.assertEqual(
            stable_git_ref_lines(lines),
            ["a" * 40 + " refs/heads/main"],
        )

    def test_real_branch_ref_changes_remain_visible(self):
        before = stable_git_ref_lines([
            "a" * 40 + " refs/heads/main",
        ])
        after = stable_git_ref_lines([
            "b" * 40 + " refs/heads/main",
        ])
        self.assertNotEqual(before, after)

    def test_malformed_ref_row_fails_closed(self):
        with self.assertRaises(ValueError):
            stable_git_ref_lines(["not-a-ref-row"])


if __name__ == "__main__":
    unittest.main()
