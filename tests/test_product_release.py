from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mtr_dogfood.product_release import (
    ProductReleaseError,
    evaluate_qualifications,
    qualification_record,
)


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _record(repository: str, media: str) -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "route_id": repository.upper().replace("-", "_") + "_R1",
        "repository_id": repository,
        "lane_id": repository + "-lane-r1",
        "media_families": [media],
        "runtime_source_head": "a" * 40,
        "runtime_artifact_sha256": "b" * 64,
        "packet_manifest_sha256": "c" * 64,
        "qualification_closeout_path": "qualification/execution-closeout.json",
        "validator_count": 1,
        "changed_paths": ["synthetic.txt"],
        "accepted": True,
    }


def _make_packet(root: Path) -> Path:
    packet = root / "packet"
    frozen = packet / "frozen"
    frozen.mkdir(parents=True)
    artifact = packet / "mtr-dogfood-product-lane.pyz"
    artifact.write_bytes(b"artifact")
    lane_id = "fixture-lane-r1"
    contract = {
        "schema_version": "2.0.0",
        "route_id": "FIXTURE_RELEASE_R1",
        "repository_id": "fixture-product",
        "qualification_release_only": True,
    }
    task = {
        "risk": "LOW_RISK",
        "changed_path_patterns": ["docs/synthetic.md"],
        "validator_plan": {
            "commands": [
                {"name": "focused", "layer": "focused"},
                {"name": "full", "layer": "full"},
            ]
        },
    }
    policy = {
        "lanes": [
            {
                "lane_id": lane_id,
                "aliases": [
                    {
                        "target_alias": "synthetic_doc",
                        "relative_path": "docs/synthetic.md",
                        "media_type": "text/markdown",
                    }
                ],
            }
        ]
    }
    candidate = {
        "proposed_files": [
            {"target_alias": "synthetic_doc", "content": "synthetic\n"}
        ]
    }
    _write_json(frozen / "product-contract.json", contract)
    _write_json(frozen / "task.json", task)
    _write_json(frozen / "policy.json", policy)
    _write_json(frozen / "decision.json", {"status": "recommended"})
    _write_json(frozen / "candidate.json", candidate)
    manifest = {
        "schema_version": "1.0.0",
        "route_id": "FIXTURE_RELEASE_R1",
        "qualification_release_only": True,
        "maximum_new_starts": 1,
        "no_retry": True,
        "stop_on_first_failure": True,
        "historical_input": {
            "input_mode": "declarative_product_contract_v2",
            "product_contract_snapshot": "frozen/product-contract.json",
            "product_contract_sha256": _sha256(
                frozen / "product-contract.json"
            ),
        },
        "lane_policy": {
            "snapshot": "frozen/policy.json",
            "sha256": _sha256(frozen / "policy.json"),
        },
        "runtime_release": {
            "source_dirty": False,
            "source_materialization": "git_object_database_head",
            "source_head": "a" * 40,
            "artifact_sha256": _sha256(artifact),
        },
        "lanes": [
            {
                "lane_id": lane_id,
                "repository_id": "fixture-product",
                "task_snapshot": "frozen/task.json",
                "task_sha256": _sha256(frozen / "task.json"),
                "decision_snapshot": "frozen/decision.json",
                "decision_sha256": _sha256(frozen / "decision.json"),
                "qualification_candidate_snapshot": "frozen/candidate.json",
                "qualification_candidate_sha256": _sha256(
                    frozen / "candidate.json"
                ),
            }
        ],
    }
    _write_json(packet / "FINAL_EXECUTION_MANIFEST.json", manifest)
    closeout = {
        "status": "passed",
        "qualification_only": True,
        "campaign_started": False,
        "starts_consumed": 0,
        "source_repositories_unchanged": True,
        "packet": {"manifest_sha256": "d" * 64},
        "runtime_artifact": {"sha256": _sha256(artifact)},
        "process_accounting": {
            "os_child_process_started": 0,
            "model_execution_observed": 0,
            "model_execution_completed": 0,
            "final_output_validated": 1,
            "validator_completed": 2,
        },
        "outcomes": [
            {
                "lane_id": lane_id,
                "accepted": True,
                "qualification_fixture": True,
                "qualification_state": "POST_MATERIALIZATION_VALIDATED",
                "real_model_process_starts": 0,
                "real_model_requests": 0,
                "changed_paths": ["docs/synthetic.md"],
                "validation": {
                    "automated_acceptance": True,
                    "validator_side_effect_free": True,
                    "validator_stage_passed": True,
                    "required_validator_count": 2,
                    "validator_results": [
                        {
                            "name": "focused",
                            "layer": "focused",
                            "passed": True,
                        },
                        {"name": "full", "layer": "full", "passed": True},
                    ],
                },
            }
        ],
    }
    _write_json(
        packet / "results" / "qualification" / "execution-closeout.json",
        closeout,
    )
    return packet


class ProductReleaseTests(unittest.TestCase):
    def test_three_qualification_products_unlock_only_real_canaries(self):
        result = evaluate_qualifications(
            [
                _record("python-product", "python"),
                _record("typescript-product", "typescript"),
                _record("docs-product", "markdown"),
            ]
        )
        self.assertEqual(result["status"], "passed")
        self.assertTrue(result["eligible_for_separately_authorized_real_canaries"])
        self.assertFalse(result["eligible_for_default_product_development"])
        self.assertEqual(result["failure_codes"], [])
        self.assertEqual(result["real_model_process_starts_created_by_evaluator"], 0)

    def test_release_drift_and_reused_identity_fail_closed(self):
        first = _record("same-product", "python")
        second = dict(first)
        second["runtime_source_head"] = "e" * 40
        result = evaluate_qualifications([first, second])
        self.assertEqual(result["status"], "blocked")
        self.assertIn("QUALIFICATION_IDENTITY_REUSED", result["failure_codes"])
        self.assertIn("COMPONENT_RELEASE_DRIFT", result["failure_codes"])

    def test_packet_evidence_requires_exact_validator_accounting(self):
        with tempfile.TemporaryDirectory() as temporary:
            packet = _make_packet(Path(temporary))
            with mock.patch(
                "mtr_dogfood.product_release.verify_packet",
                return_value={"manifest_sha256": "d" * 64},
            ):
                record = qualification_record(packet)
                self.assertTrue(record["accepted"])
                self.assertEqual(record["validator_count"], 2)
                closeout_path = (
                    packet
                    / "results"
                    / "qualification"
                    / "execution-closeout.json"
                )
                closeout = json.loads(closeout_path.read_text(encoding="utf-8"))
                closeout["process_accounting"]["validator_completed"] = 1
                _write_json(closeout_path, closeout)
                with self.assertRaisesRegex(
                    ProductReleaseError, "QUALIFICATION_EVIDENCE_INVALID"
                ):
                    qualification_record(packet)

    def test_qualification_rejects_a_real_campaign_latch(self):
        with tempfile.TemporaryDirectory() as temporary:
            packet = _make_packet(Path(temporary))
            _write_json(packet / "results" / "campaign-state.json", {})
            with mock.patch(
                "mtr_dogfood.product_release.verify_packet",
                return_value={"manifest_sha256": "d" * 64},
            ):
                with self.assertRaisesRegex(
                    ProductReleaseError, "QUALIFICATION_CAMPAIGN_LATCH_PRESENT"
                ):
                    qualification_record(packet)


if __name__ == "__main__":
    unittest.main()
