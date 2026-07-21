from __future__ import annotations

import unittest

from mtr_dogfood.product_readiness import evaluate_canaries


def record(repository: str, media: str, *, head: str = "a" * 40, accepted: bool = True):
    return {
        "schema_version": "1.0.0",
        "route_id": repository.upper(),
        "repository_id": repository,
        "lane_id": repository + "-lane",
        "risk": "LOW_RISK",
        "media_families": [media],
        "runtime_source_head": head,
        "runtime_artifact_sha256": "b" * 64,
        "qualification_release_only": False,
        "accepted": accepted,
    }


class ProductReadinessTests(unittest.TestCase):
    def test_three_heterogeneous_products_on_one_release_are_eligible(self):
        result = evaluate_canaries([
            record("python-product", "python"),
            record("typescript-product", "typescript"),
            record("docs-product", "markdown"),
        ])
        self.assertEqual(result["status"], "passed")
        self.assertTrue(result["eligible_for_default_product_development"])
        self.assertEqual(result["failure_codes"], [])
        self.assertEqual(result["real_model_process_starts_created_by_evaluator"], 0)

    def test_count_diversity_release_and_acceptance_fail_closed(self):
        result = evaluate_canaries([
            record("same-product", "python"),
            record("same-product", "python", head="c" * 40, accepted=False),
        ])
        self.assertEqual(result["status"], "blocked")
        self.assertFalse(result["eligible_for_default_product_development"])
        self.assertEqual(
            set(result["failure_codes"]),
            {
                "INSUFFICIENT_CANARY_COUNT",
                "INSUFFICIENT_REPOSITORY_DIVERSITY",
                "INSUFFICIENT_MEDIA_DIVERSITY",
                "COMPONENT_RELEASE_DRIFT",
                "CANARY_NOT_ACCEPTED",
            },
        )


if __name__ == "__main__":
    unittest.main()
