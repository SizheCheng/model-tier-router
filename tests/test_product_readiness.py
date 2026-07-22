from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mtr_dogfood.product_readiness import canary_record, evaluate_canaries
from tests.test_product_release import _make_packet, _sha256, _write_json


def record(
    repository: str,
    media: str,
    *,
    head: str = "a" * 40,
    accepted: bool = True,
):
    return {
        "schema_version": "1.0.0",
        "route_id": repository.upper(),
        "repository_id": repository,
        "lane_id": repository + "-lane",
        "risk": "LOW_RISK",
        "media_families": [media],
        "runtime_source_head": head,
        "runtime_artifact_sha256": "b" * 64,
        "packet_manifest_sha256": "c" * 64,
        "qualification_release_only": False,
        "accepted": accepted,
    }


def _make_real_packet(root: Path) -> Path:
    packet = _make_packet(root)
    manifest_path = packet / "FINAL_EXECUTION_MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["qualification_release_only"] = False
    manifest["campaign_id"] = manifest["route_id"]
    contract_path = packet / manifest["historical_input"][
        "product_contract_snapshot"
    ]
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    contract["qualification_release_only"] = False
    _write_json(contract_path, contract)
    manifest["historical_input"]["product_contract_sha256"] = _sha256(
        contract_path
    )
    _write_json(manifest_path, manifest)

    closeout_path = (
        packet / "results" / "qualification" / "execution-closeout.json"
    )
    closeout = json.loads(closeout_path.read_text(encoding="utf-8"))
    closeout.update(
        {
            "route_id": manifest["route_id"],
            "qualification_only": False,
            "campaign_started": True,
            "starts_consumed": 1,
            "maximum_new_starts": 1,
            "no_retry": True,
            "stop_on_first_failure": True,
            "pre_reservation_qualification": {
                "status": "passed",
                "qualification_state": "POST_MATERIALIZATION_VALIDATED",
                "model_process_starts": 0,
                "model_requests": 0,
                "validator_process_starts": 2,
            },
        }
    )
    closeout["process_accounting"].update(
        {
            "os_child_process_started": 1,
            "model_execution_observed": 1,
            "model_execution_completed": 1,
        }
    )
    closeout["outcomes"][0]["accepted"] = True
    closeout["outcomes"][0]["validation"]["required_validator_count"] = 2
    _write_json(closeout_path, closeout)
    lane_id = manifest["lanes"][0]["lane_id"]
    _write_json(
        packet / "results" / "campaign-state.json",
        {
            "campaign_id": manifest["campaign_id"],
            "lane_id": lane_id,
            "maximum_real_starts": 1,
            "starts_consumed": 1,
            "no_retry": True,
            "process_started": True,
            "reservation_state": "TERMINAL",
            "accepted": True,
            "terminal_status": "accepted",
        },
    )
    return packet


class ProductReadinessTests(unittest.TestCase):
    def test_three_heterogeneous_products_on_one_release_are_eligible(self):
        result = evaluate_canaries(
            [
                record("python-product", "python"),
                record("typescript-product", "typescript"),
                record("docs-product", "markdown"),
            ]
        )
        self.assertEqual(result["status"], "passed")
        self.assertTrue(result["eligible_for_default_product_development"])
        self.assertEqual(result["failure_codes"], [])
        self.assertEqual(result["real_model_process_starts_created_by_evaluator"], 0)

    def test_count_diversity_release_and_acceptance_fail_closed(self):
        result = evaluate_canaries(
            [
                record("same-product", "python"),
                record(
                    "same-product", "python", head="c" * 40, accepted=False
                ),
            ]
        )
        self.assertEqual(result["status"], "blocked")
        self.assertFalse(result["eligible_for_default_product_development"])
        self.assertEqual(
            set(result["failure_codes"]),
            {
                "INSUFFICIENT_CANARY_COUNT",
                "INSUFFICIENT_REPOSITORY_DIVERSITY",
                "CANARY_IDENTITY_REUSED",
                "INSUFFICIENT_MEDIA_DIVERSITY",
                "COMPONENT_RELEASE_DRIFT",
                "CANARY_NOT_ACCEPTED",
            },
        )

    def test_canary_record_requires_exact_one_model_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            packet = _make_real_packet(Path(temporary))
            with mock.patch(
                "mtr_dogfood.product_readiness.verify_packet",
                return_value={"manifest_sha256": "d" * 64},
            ):
                result = canary_record(packet)
                self.assertTrue(result["accepted"])
                closeout_path = Path(result["closeout_path"])
                closeout = json.loads(closeout_path.read_text(encoding="utf-8"))
                closeout["process_accounting"]["model_execution_completed"] = 0
                _write_json(closeout_path, closeout)
                self.assertFalse(canary_record(packet)["accepted"])


if __name__ == "__main__":
    unittest.main()
