from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.build_final_remaining_lane_packet import _strict_json
from mtr_dogfood.external_runner import _render_plan
from mtr_dogfood.remaining_lane_execution import (
    FinalExecutionError,
    _verify_reservation_inputs,
    run,
)
from mtr_dogfood.validation import (
    VALIDATOR_AUTHORITY,
    _validator_environment,
    validate_validator_authority,
)


ROOT = Path(__file__).resolve().parents[1]


def validator(command: list[str], **extra: object) -> dict[str, object]:
    return {
        "commands": [{
            "name": "contract-test",
            "layer": "focused",
            "command": command,
            "timeout_seconds": 60,
            **extra,
        }]
    }


class ProductContractV2Tests(unittest.TestCase):
    def test_strict_json_rejects_duplicate_nonfinite_and_invalid_utf8(self):
        invalid_values = (
            b'{"outer":{"value":1,"value":2}}',
            b'{"value":NaN}',
            b'{"value":Infinity}',
            b'\xff',
        )
        for raw in invalid_values:
            with self.subTest(raw=raw):
                with self.assertRaises((UnicodeError, ValueError)):
                    _strict_json(raw)

    def test_validator_authority_accepts_only_bounded_test_commands(self):
        allowed = validator([
            "python", "-B", "-m", "pytest", "-q", "tests/test_unit.py",
            "--basetemp", "{run_temp}/pytest",
        ])
        validate_validator_authority(allowed, dict(VALIDATOR_AUTHORITY))

        rejected = (
            validator(["python", "-c", "print('no')"]),
            validator(["powershell.exe", "-Command", "Get-ChildItem"]),
            validator([
                r"C:\Python\python.exe", "-m", "pytest", "tests/test_unit.py",
            ]),
            validator([
                "python", "-m", "pytest", r"C:\outside\test_unit.py",
            ]),
            validator(["python", "-m", "pytest", "@args.txt"]),
            validator(["python", "-m", "pytest", "../outside/test_unit.py"]),
            validator(["python", "-m", "pytest", "https://example.invalid/test.py"]),
            validator(["npm", "run", "deploy"]),
            validator(
                ["python", "-m", "pytest", "tests/test_unit.py"],
                env={"OPENAI_API_KEY": "not-allowed"},
            ),
            validator(
                ["python", "-m", "pytest", "tests/test_unit.py"],
                env={"TEMP": r"C:\outside"},
            ),
        )
        for plan in rejected:
            with self.subTest(plan=plan):
                with self.assertRaises(ValueError):
                    validate_validator_authority(
                        plan, dict(VALIDATOR_AUTHORITY)
                    )

        modified_authority = dict(VALIDATOR_AUTHORITY)
        modified_authority["os_sandbox_enforced"] = True
        with self.assertRaises(ValueError):
            validate_validator_authority(allowed, modified_authority)

    def test_validator_environment_scrubs_host_secrets(self):
        plan = validator(
            ["python", "-m", "unittest", "tests.test_unit"],
            env={"TEMP": "{run_temp}"},
            pythonpath_src=True,
        )
        entry = plan["commands"][0]
        with mock.patch.dict(
            os.environ,
            {"OPENAI_API_KEY": "secret", "GITHUB_TOKEN": "secret"},
            clear=False,
        ):
            environment = _validator_environment(entry, Path("C:/worktree"))
        self.assertNotIn("OPENAI_API_KEY", environment)
        self.assertNotIn("GITHUB_TOKEN", environment)
        self.assertEqual(environment["PYTHONDONTWRITEBYTECODE"], "1")
        self.assertTrue(environment["PYTHONPATH"].endswith("src"))

    def test_windows_placeholder_rendering_is_structural(self):
        plan = {
            "commands": [{
                "command": [
                    "python", "-m", "pytest", "{worktree}/tests",
                    "--basetemp", "{run_temp}/pytest",
                ],
                "env": {"TEMP": "{run_temp}"},
            }]
        }
        original = json.loads(json.dumps(plan))
        rendered = _render_plan(
            plan,
            Path(r"C:\Users\Example\worktree"),
            Path(r"C:\Users\Example\run-temp"),
        )
        self.assertEqual(plan, original)
        self.assertEqual(
            rendered["commands"][0]["env"]["TEMP"],
            r"C:\Users\Example\run-temp",
        )
        self.assertEqual(json.loads(json.dumps(rendered)), rendered)

    def test_builder_has_no_implicit_historical_packet(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "packet"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(ROOT / "scripts" / "build_product_lane_packet.py"),
                    "--output-directory",
                    str(output),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(
                "PRODUCT_CONTRACT_OR_SOURCE_PACKET_REQUIRED",
                completed.stderr,
            )
            self.assertFalse(output.exists())

    def test_schema_and_example_publish_the_exact_v2_authority(self):
        schema = json.loads(
            (ROOT / "schemas" / "product-lane-contract.schema.json").read_text(
                encoding="utf-8"
            )
        )
        example = json.loads(
            (ROOT / "examples" / "product-lane-contract.example.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(schema["properties"]["schema_version"]["const"], "2.0.0")
        self.assertEqual(example["validator_authority"], VALIDATOR_AUTHORITY)
        self.assertEqual(
            schema["properties"]["qualification_candidate"]["$ref"],
            "proposed-files-result.schema.json",
        )
        self.assertIn("qualification_candidate", schema["required"])

    def test_reservation_guard_rechecks_packet_manifest_and_repositories(self):
        packet = Path("C:/packet")
        binding = {
            "repository_id": "product",
            "source_head": "s" * 40,
            "source_branch": "main",
        }
        manifest = {
            "router_source_head": "r" * 40,
            "lanes": [binding],
        }
        repositories = {
            "model-tier-router": Path("C:/router"),
            "product": Path("C:/product"),
        }

        def state(path: Path) -> dict[str, object]:
            return {
                "head": "r" * 40 if path.name == "router" else "s" * 40,
                "branch": "main",
                "status": [],
            }

        with (
            mock.patch(
                "mtr_dogfood.remaining_lane_execution.verify_packet"
            ) as verify,
            mock.patch(
                "mtr_dogfood.remaining_lane_execution.load_json",
                return_value=manifest,
            ),
            mock.patch(
                "mtr_dogfood.remaining_lane_execution._repository_state",
                side_effect=state,
            ),
        ):
            _verify_reservation_inputs(
                packet, manifest, repositories, binding
            )
            verify.assert_called_once_with(packet)

        with (
            mock.patch(
                "mtr_dogfood.remaining_lane_execution.verify_packet"
            ),
            mock.patch(
                "mtr_dogfood.remaining_lane_execution.load_json",
                return_value={**manifest, "router_source_head": "x" * 40},
            ),
        ):
            with self.assertRaisesRegex(
                FinalExecutionError, "PRE_RESERVATION_MANIFEST_DRIFT"
            ):
                _verify_reservation_inputs(
                    packet, manifest, repositories, binding
                )

    def test_failed_real_preflight_never_reaches_launcher_or_latch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            packet = root / "packet"
            results = packet / "results"
            result = results / "run"
            packet.mkdir()
            results.mkdir()
            router = root / "router"
            source = root / "source"
            router.mkdir()
            source.mkdir()
            binding = {
                "repository_id": "product",
                "source_head": "s" * 40,
                "source_branch": "main",
                "qualification_candidate_snapshot": "frozen/candidate.json",
            }
            manifest = {
                "lanes": [binding],
                "router_source_head": "r" * 40,
            }
            failed_preflight = {
                "status": "failed",
                "starts_consumed": 0,
                "campaign_started": False,
                "process_accounting": {
                    "os_child_process_started": 0,
                    "model_execution_observed": 0,
                },
            }
            launcher = mock.Mock()

            def state(path: Path) -> dict[str, object]:
                return {
                    "path": str(path),
                    "head": "r" * 40 if path == router else "s" * 40,
                    "branch": "main",
                    "status": [],
                }

            with (
                mock.patch(
                    "mtr_dogfood.remaining_lane_execution.verify_packet",
                    return_value={"status": "passed"},
                ),
                mock.patch(
                    "mtr_dogfood.remaining_lane_execution.load_json",
                    return_value=manifest,
                ),
                mock.patch(
                    "mtr_dogfood.remaining_lane_execution._validate_manifest"
                ),
                mock.patch(
                    "mtr_dogfood.remaining_lane_execution._repository_state",
                    side_effect=state,
                ),
                mock.patch(
                    "mtr_dogfood.remaining_lane_execution._clone_repository",
                    return_value=source,
                ),
                mock.patch(
                    "mtr_dogfood.remaining_lane_execution._run_lanes",
                    return_value=failed_preflight,
                ) as run_lanes,
            ):
                with self.assertRaisesRegex(
                    FinalExecutionError,
                    "PRE_RESERVATION_CANDIDATE_QUALIFICATION_FAILED",
                ):
                    run(
                        packet_root=packet,
                        router_repository=router,
                        source_repository=source,
                        workspace_parent=root / "workspace",
                        result_root=result,
                        runner_pid=123,
                        qualification_only=False,
                        launcher=launcher,
                    )
            self.assertEqual(run_lanes.call_count, 1)
            self.assertTrue(run_lanes.call_args.kwargs["qualification_only"])
            launcher.assert_not_called()
            self.assertFalse((results / "campaign-state.json").exists())


if __name__ == "__main__":
    unittest.main()