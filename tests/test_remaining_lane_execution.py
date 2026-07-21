from __future__ import annotations

import hashlib
import json
import subprocess
import shutil
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from mtr_dogfood.remaining_lane_execution import (
    CampaignLedger,
    FinalExecutionError,
    PacketCampaignLatch,
    _validate_manifest,
    self_test,
)
from mtr_dogfood.validation import freeze_validator_plan


ROOT = Path(__file__).resolve().parents[1]
ROUTER = Path(r"C:\Users\sizhe\Documents\model-tier-router")
QWEN = Path(r"C:\Users\sizhe\Documents\qwen-redaction-standalone")
R5K = (
    ROOT / "runs" / "raw" / "r5k-two-product-lane-successor-campaign-3-packet-r1"
)


class RemainingLaneExecutionTests(unittest.TestCase):
    def test_self_test_has_one_start_no_retry_contract(self):
        value = self_test()
        self.assertEqual(value["status"], "passed")
        self.assertEqual(value["component_id"], "MTR_GENERIC_SINGLE_PRODUCT_EXECUTION")
        self.assertEqual(value["maximum_real_starts"], 1)
        self.assertTrue(value["no_retry"])
        self.assertTrue(value["stop_on_first_failure"])
        self.assertEqual(value["real_model_process_starts"], 0)

    def test_packet_latch_permanently_blocks_a_second_invocation(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "results" / "campaign-state.json"
            first = PacketCampaignLatch(path, campaign_id="CANARY_R1")
            second = PacketCampaignLatch(path, campaign_id="CANARY_R1")
            record = first.reserve("lane-r1")
            self.assertEqual(record["starts_consumed"], 1)
            self.assertEqual(record["reservation_state"], "START_RESERVED")
            with self.assertRaisesRegex(
                FinalExecutionError,
                "PACKET_CAMPAIGN_ALREADY_CONSUMED",
            ):
                second.reserve("lane-r1")
            first.finish(
                "lane-r1",
                process_started=False,
                accepted=False,
                terminal_status="LAUNCH_FAILED",
            )
            terminal = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(terminal["reservation_state"], "TERMINAL")
            self.assertEqual(terminal["starts_consumed"], 1)
            with self.assertRaisesRegex(
                FinalExecutionError,
                "PACKET_CAMPAIGN_ALREADY_CONSUMED",
            ):
                second.reserve("lane-r1")

    def test_ledger_allows_exactly_one_reservation(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = CampaignLedger(
                Path(temporary) / "ledger.json",
                qualification_only=True,
                historical_accounting={
                    "r5_ordinal_1_permanently_consumed": True,
                    "r5_ordinal_1_reclaimed": False,
                },
            )
            record = ledger.reserve("qwen-docx-hidden-elements-r1")
            self.assertEqual(ledger.starts_consumed, 0)
            self.assertTrue(
                record["historical_accounting"]["r5_ordinal_1_permanently_consumed"]
            )
            with self.assertRaisesRegex(
                RuntimeError,
                "START_RESERVATION_LIMIT_REACHED|DUPLICATE_LANE_RESERVATION",
            ):
                ledger.reserve("another-lane")

    def test_wrapper_is_static_and_has_no_bare_carriage_return(self):
        wrapper = (
            ROOT
            / "final_execution"
            / "RUN_PRODUCT_LANE.ps1"
        ).read_bytes()
        self.assertEqual(wrapper.replace(b"\r\n", b"").count(b"\r"), 0)
        text = wrapper.decode("utf-8").replace("\r\n", "\n")
        param_block = text.split("\n)\n", 1)[0]
        self.assertNotIn("$PSScriptRoot", param_block)
        self.assertIn("mtr-dogfood-product-lane.pyz", text)
        self.assertIn(r"C:\Users\sizhe\mtr-work\product-r1", text)
        self.assertIn("--source-repository $SourceRepository", text)
        self.assertIn("--runner-pid $PID", text)

    def test_artifact_is_reproducible(self):
        with (
            tempfile.TemporaryDirectory() as first,
            tempfile.TemporaryDirectory() as second,
        ):
            artifacts = []
            for output in (first, second):
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-B",
                        str(ROOT / "scripts" / "build_qualification_artifact.py"),
                        "--output-directory",
                        output,
                        "--entrypoint",
                        "product-lane",
                    ],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=180,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                artifacts.append(
                    (Path(output) / "mtr-dogfood-product-lane.pyz").read_bytes()
                )
            self.assertEqual(artifacts[0], artifacts[1])

    def test_builder_rejects_tampered_source_packet_and_invalid_identifiers(self):
        if not R5K.is_dir() or not ROUTER.is_dir() or not QWEN.is_dir():
            self.skipTest("live source packets and repositories are unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            tampered = base / "tampered-source"
            shutil.copytree(R5K, tampered)
            source_manifest = json.loads(
                (tampered / "EXECUTION_MANIFEST.json").read_text(encoding="utf-8")
            )
            lane = next(
                item
                for item in source_manifest["lanes"]
                if item["lane_id"] == "qwen-docx-hidden-elements-r1"
            )
            task = tampered / lane["task_snapshot"]
            task.write_bytes(task.read_bytes() + b" ")
            common = [
                sys.executable,
                "-B",
                str(ROOT / "scripts" / "build_product_lane_packet.py"),
                "--router-repository",
                str(ROUTER),
                "--source-repository",
                str(QWEN),
            ]
            tamper_result = subprocess.run(
                [
                    *common,
                    "--output-directory",
                    str(base / "tampered-output"),
                    "--source-packet",
                    str(tampered),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
                timeout=120,
            )
            self.assertNotEqual(tamper_result.returncode, 0)
            self.assertIn("SOURCE_PACKET_HASH_DRIFT", tamper_result.stderr)
            extra = base / "extra-source"
            shutil.copytree(R5K, extra)
            (extra / "unlisted.txt").write_text("not authorized", encoding="utf-8")
            extra_result = subprocess.run(
                [
                    *common,
                    "--output-directory",
                    str(base / "extra-output"),
                    "--source-packet",
                    str(extra),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
                timeout=120,
            )
            self.assertNotEqual(extra_result.returncode, 0)
            self.assertIn("SOURCE_PACKET_FILE_SET_DRIFT", extra_result.stderr)
            invalid_route = subprocess.run(
                [
                    *common,
                    "--output-directory",
                    str(base / "invalid-route-output"),
                    "--route-id",
                    "lowercase route",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
                timeout=120,
            )
            self.assertNotEqual(invalid_route.returncode, 0)
            self.assertIn("PRODUCT_ROUTE_IDENTIFIER_INVALID", invalid_route.stderr)
            self.assertFalse((base / "invalid-route-output").exists())

    def test_packet_contains_only_remaining_lane_and_qualifies_without_model(self):
        if not ROUTER.is_dir() or not QWEN.is_dir():
            self.skipTest("live source repositories are unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            packet = base / "packet"
            build = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(ROOT / "scripts" / "build_product_lane_packet.py"),
                    "--output-directory",
                    str(packet),
                    "--router-repository",
                    str(ROUTER),
                    "--source-repository",
                    str(QWEN),
                    "--route-id",
                    "TEST_GENERIC_PRODUCT_EXECUTION_R1",
                    "--historical-accounting-json",
                    '{"prior_consumed_starts":2}',
                    "--branch-prefix",
                    "mtr-test/generic",
                    "--qualification-release-only",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
                timeout=240,
            )
            self.assertEqual(build.returncode, 0, build.stderr)
            manifest = json.loads(
                (packet / "FINAL_EXECUTION_MANIFEST.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["execution_order"], ["qwen-docx-hidden-elements-r1"])
            self.assertEqual(manifest["maximum_new_starts"], 1)
            self.assertEqual(manifest["route_id"], "TEST_GENERIC_PRODUCT_EXECUTION_R1")
            self.assertEqual(manifest["historical_accounting"], {"prior_consumed_starts": 2})
            self.assertTrue(manifest["qualification_release_only"])
            self.assertEqual(manifest["lanes"][0]["branch_prefix"], "mtr-test/generic")
            self.assertEqual(
                manifest["lanes"][0]["repository_id"], "qwen-redaction-standalone"
            )
            result = packet / "results" / "qualification"
            qualify = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(packet / "mtr-dogfood-product-lane.pyz"),
                    "--qualification-only",
                    "--packet-root",
                    str(packet),
                    "--router-repository",
                    str(ROUTER),
                    "--source-repository",
                    str(QWEN),
                    "--workspace-parent",
                    str(base / "workspaces"),
                    "--result-root",
                    str(result),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
                timeout=240,
            )
            self.assertEqual(qualify.returncode, 0, qualify.stderr + qualify.stdout)
            closeout = json.loads(qualify.stdout)
            self.assertEqual(closeout["status"], "passed")
            self.assertFalse(closeout["campaign_started"])
            self.assertEqual(closeout["starts_consumed"], 0)
            self.assertEqual(closeout["maximum_new_starts"], 1)
            self.assertEqual(closeout["process_accounting"]["os_child_process_started"], 0)
            self.assertEqual(
                closeout["outcomes"][0]["qualification_state"],
                "START_RESERVATION_REQUESTED",
            )
            self.assertTrue(closeout["source_repositories_unchanged"])
            self.assertFalse((packet / "results" / "campaign-state.json").exists())
            escaping_manifest = json.loads(json.dumps(manifest))
            escaping_manifest["lane_policy"]["snapshot"] = str(
                (base / "outside-policy.json").resolve()
            )
            with mock.patch(
                "mtr_dogfood.remaining_lane_execution._release_metadata",
                return_value={
                    "schema_version": "1.0.0",
                    "source_head": manifest["runtime_release"]["source_head"],
                    "source_dirty": manifest["runtime_release"]["source_dirty"],
                    "entrypoint": "product-lane",
                },
            ):
                with self.assertRaisesRegex(
                    FinalExecutionError,
                    "FROZEN_INPUT_PATH_INVALID",
                ):
                    _validate_manifest(
                        packet,
                        escaping_manifest,
                        packet / "mtr-dogfood-product-lane.pyz",
                        ROUTER,
                        QWEN,
                        qualification_only=True,
                    )
            with self.assertRaisesRegex(
                FinalExecutionError,
                "QUALIFICATION_RELEASE_REAL_EXECUTION_FORBIDDEN",
            ):
                _validate_manifest(
                    packet,
                    manifest,
                    packet / "mtr-dogfood-product-lane.pyz",
                    ROUTER,
                    QWEN,
                    qualification_only=False,
                )
            execution_manifest = dict(manifest)
            execution_manifest["qualification_release_only"] = False
            dirty_release = {
                "schema_version": "1.0.0",
                "source_head": manifest["runtime_release"]["source_head"],
                "source_dirty": True,
                "entrypoint": "product-lane",
            }
            with mock.patch(
                "mtr_dogfood.remaining_lane_execution._release_metadata",
                return_value=dirty_release,
            ):
                with self.assertRaisesRegex(
                    FinalExecutionError,
                    "FINAL_EXECUTION_ARTIFACT_BINDING_DRIFT",
                ):
                    _validate_manifest(
                        packet,
                        execution_manifest,
                        packet / "mtr-dogfood-product-lane.pyz",
                        ROUTER,
                        QWEN,
                        qualification_only=False,
                    )


    def test_declarative_contract_supports_an_unlisted_product_and_path(self):
        if not ROUTER.is_dir():
            self.skipTest("live router repository is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "inventory-product"
            source.mkdir()
            (source / "src").mkdir()
            (source / "src" / "inventory.ts").write_text(
                "export const inventory = [];\n", encoding="utf-8"
            )
            for command in (
                ["git", "init", "-q", "-b", "main"],
                ["git", "config", "user.name", "Product Fixture"],
                ["git", "config", "user.email", "fixture.invalid"],
                ["git", "add", "src/inventory.ts"],
                ["git", "commit", "-q", "-m", "baseline"],
            ):
                completed = subprocess.run(
                    command, cwd=source, capture_output=True, text=True, check=False
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
            head = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=source,
                capture_output=True, text=True, check=True,
            ).stdout.strip()
            validator_plan = {
                "commands": [{
                    "name": "shape", "layer": "focused",
                    "command": [
                        "python", "-B", "-c",
                        "from pathlib import Path; assert Path('src/inventory.ts').is_file()",
                    ],
                    "timeout_seconds": 60,
                }]
            }
            lane_id = "inventory-typescript-contract-r1"
            contract = {
                "schema_version": "1.0.0",
                "route_id": "INVENTORY_TYPESCRIPT_CONTRACT_R1",
                "repository_id": "inventory-product",
                "branch_prefix": "mtr-product/inventory",
                "task": {
                    "schema_version": "1.0.0", "case_id": lane_id,
                    "repository": "inventory-product", "baseline_head": head,
                    "title": "update inventory",
                    "task_text": "Add one synthetic inventory entry.",
                    "changed_path_patterns": ["src/inventory.ts"],
                    "risk": "LOW_RISK", "validator_plan": validator_plan,
                    "validator_plan_digest": freeze_validator_plan(validator_plan),
                    "model_timeout_seconds": 300,
                },
                "routing_request": {
                    "schema_version": "model_tier_router_advisory_request_v1alpha1",
                    "request_id": lane_id,
                    "requirements": {
                        "maximum_cost_class": "medium",
                        "modalities": ["text"], "tool_support": True,
                    },
                    "preferences": ["higher_reasoning"],
                    "evidence": {"modalities": True, "tool_support": True},
                },
                "lane_policy": {
                    "schema_version": "1.0.0",
                    "model_output_success_guaranteed": False,
                    "safety_independent_of_model_output_capacity": True,
                    "lanes": [{
                        "lane_id": lane_id, "maximum_file_count": 1,
                        "maximum_aggregate_content_bytes": 32768,
                        "maximum_serialized_result_bytes": 204800,
                        "required_validation_expectations": 1,
                        "aliases": [{
                            "target_alias": "inventory_typescript",
                            "relative_path": "src/inventory.ts",
                            "media_type": "text/typescript", "encoding": "UTF-8",
                            "allowed_line_endings": ["LF", "CRLF"],
                            "exact_content_bytes": None,
                            "maximum_content_bytes": 32768,
                            "maximum_serialized_bytes": 204800,
                            "nul_prohibited": True,
                            "content_requirements": {
                                "minimum_utf8_bytes": 1,
                                "exact_utf8_content": None,
                                "required_casefold_substrings": ["inventory"],
                                "forbidden_casefold_substrings": [],
                            },
                        }],
                    }],
                },
                "historical_accounting": {"prior_consumed_starts": 0},
                "qualification_release_only": True,
            }
            contract_path = base / "product-contract.json"
            contract_path.write_text(json.dumps(contract), encoding="utf-8")
            packet = base / "packet"
            build = subprocess.run(
                [
                    sys.executable, "-B",
                    str(ROOT / "scripts" / "build_product_lane_packet.py"),
                    "--output-directory", str(packet),
                    "--router-repository", str(ROUTER),
                    "--source-repository", str(source),
                    "--product-contract", str(contract_path),
                ],
                cwd=ROOT, capture_output=True, text=True, check=False, timeout=240,
            )
            self.assertEqual(build.returncode, 0, build.stderr)
            manifest = json.loads(
                (packet / "FINAL_EXECUTION_MANIFEST.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["lanes"][0]["lane_id"], lane_id)
            self.assertEqual(
                manifest["historical_input"]["input_mode"],
                "declarative_product_contract_v1",
            )
            frozen_contract = (
                packet
                / manifest["historical_input"]["product_contract_snapshot"]
            )
            self.assertEqual(frozen_contract.read_bytes(), contract_path.read_bytes())
            self.assertEqual(
                manifest["historical_input"]["product_contract_sha256"],
                hashlib.sha256(frozen_contract.read_bytes()).hexdigest(),
            )
            packet_policy = json.loads(
                (packet / manifest["lane_policy"]["snapshot"]).read_text(encoding="utf-8")
            )
            self.assertEqual(
                packet_policy["lanes"][0]["aliases"][0]["relative_path"],
                "src/inventory.ts",
            )
            result = packet / "results" / "qualification"
            qualify = subprocess.run(
                [
                    sys.executable, "-B",
                    str(packet / "mtr-dogfood-product-lane.pyz"),
                    "--qualification-only", "--packet-root", str(packet),
                    "--router-repository", str(ROUTER),
                    "--source-repository", str(source),
                    "--workspace-parent", str(base / "workspaces"),
                    "--result-root", str(result),
                ],
                cwd=ROOT, capture_output=True, text=True, check=False, timeout=240,
            )
            self.assertEqual(qualify.returncode, 0, qualify.stderr + qualify.stdout)
            closeout = json.loads(qualify.stdout)
            self.assertEqual(closeout["status"], "passed")
            self.assertFalse(closeout["campaign_started"])
            self.assertEqual(closeout["starts_consumed"], 0)
            self.assertEqual(
                closeout["outcomes"][0]["qualification_state"],
                "START_RESERVATION_REQUESTED",
            )


if __name__ == "__main__":
    unittest.main()