from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from mtr_dogfood.product_matrix import (
    ProductMatrixError,
    _run_command,
    _strict_json,
    execute_matrix,
    load_matrix,
)


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _repository(path: Path) -> str:
    path.mkdir(parents=True)
    (path / "README.md").write_text("fixture\n", encoding="utf-8")
    for command in (
        ["git", "init", "-q", "-b", "main"],
        ["git", "config", "core.longpaths", "true"],
        ["git", "config", "user.name", "Matrix Fixture"],
        ["git", "config", "user.email", "fixture.invalid"],
        ["git", "add", "README.md"],
        ["git", "commit", "-q", "-m", "baseline"],
    ):
        completed = subprocess.run(
            command, cwd=path, capture_output=True, text=True, check=False
        )
        if completed.returncode != 0:
            raise AssertionError(completed.stderr)
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=path,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def _matrix_fixture(root: Path) -> tuple[Path, Path]:
    router = root / "router"
    _repository(router)
    products = []
    for ordinal in range(1, 4):
        source = root / f"product-{ordinal}"
        head = _repository(source)
        repository_id = f"product-{ordinal}"
        lane_id = f"product-{ordinal}-lane-r1"
        contract = {
            "schema_version": "2.0.0",
            "route_id": f"PRODUCT_{ordinal}_RELEASE_R1",
            "repository_id": repository_id,
            "qualification_release_only": True,
            "task": {
                "case_id": lane_id,
                "repository": repository_id,
                "baseline_head": head,
            },
        }
        contract_path = root / "contracts" / f"product-{ordinal}.json"
        _write_json(contract_path, contract)
        products.append(
            {
                "packet_name": f"product-{ordinal}",
                "product_contract": str(contract_path.relative_to(root)),
                "source_repository": str(source.relative_to(root)),
            }
        )
    matrix = root / "matrix.json"
    _write_json(
        matrix,
        {
            "schema_version": "1.0.0",
            "release_id": "MATRIX_RELEASE_R1",
            "products": products,
        },
    )
    return matrix, router


def _completed(command: list[str], returncode: int, payload: object):
    return subprocess.CompletedProcess(
        command, returncode, stdout=json.dumps(payload), stderr=""
    )


def _build_payload() -> dict[str, object]:
    return {
        "status": "prepared_no_model_execution",
        "real_model_process_starts": 0,
        "real_model_requests": 0,
        "runtime_source_dirty": False,
        "packet_manifest_sha256": "a" * 64,
        "runtime_artifact_sha256": "b" * 64,
    }


def _qualification_payload() -> dict[str, object]:
    return {
        "status": "passed",
        "qualification_only": True,
        "campaign_started": False,
        "starts_consumed": 0,
        "source_repositories_unchanged": True,
        "process_accounting": {
            "os_child_process_started": 0,
            "model_execution_observed": 0,
            "model_execution_completed": 0,
            "final_output_validated": 1,
            "validator_completed": 1,
        },
        "outcomes": [
            {
                "accepted": True,
                "qualification_state": "POST_MATERIALIZATION_VALIDATED",
                "real_model_process_starts": 0,
                "real_model_requests": 0,
            }
        ],
    }


class ProductMatrixTests(unittest.TestCase):
    def test_strict_json_rejects_duplicates_and_nonfinite_numbers(self):
        with self.assertRaises(ValueError):
            _strict_json(b'{"a":1,"a":2}')
        with self.assertRaises(ValueError):
            _strict_json(b'{"a":NaN}')

    def test_failed_command_persists_hash_bound_diagnostics(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stderr = "synthetic traceback\n"

            def runner(command, **kwargs):
                return subprocess.CompletedProcess(
                    command, 2, stdout="", stderr=stderr
                )

            digest = hashlib.sha256(stderr.encode("utf-8")).hexdigest()
            with self.assertRaisesRegex(
                ProductMatrixError,
                f"build:COMMAND_FAILED_EXIT_2:STDERR_SHA256_{digest}",
            ):
                _run_command(
                    ["fixture-builder"],
                    cwd=root,
                    timeout_seconds=1,
                    runner=runner,
                    evidence_directory=root / "evidence",
                    label="build",
                )
            evidence = root / "evidence"
            self.assertEqual(
                (evidence / "build.stderr.txt").read_text(encoding="utf-8"),
                stderr,
            )
            metadata = json.loads(
                (evidence / "build.command.json").read_text(encoding="utf-8")
            )
            self.assertEqual(metadata["exit_code"], 2)
            self.assertEqual(metadata["stderr_sha256"], digest)

    def test_matrix_preflight_binds_three_clean_distinct_products(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            matrix, _ = _matrix_fixture(root)
            spec = load_matrix(matrix)
            self.assertEqual(spec["release_id"], "MATRIX_RELEASE_R1")
            self.assertEqual(len(spec["products"]), 3)
            self.assertEqual(
                {item["repository_id"] for item in spec["products"]},
                {"product-1", "product-2", "product-3"},
            )

            value = json.loads(matrix.read_text(encoding="utf-8"))
            value["products"][1]["source_repository"] = value["products"][0][
                "source_repository"
            ]
            _write_json(matrix, value)
            with self.assertRaisesRegex(
                ProductMatrixError, "PRODUCT_MATRIX_PRODUCT_IDENTITY_REUSED"
            ):
                load_matrix(matrix)

    def test_workspace_root_must_be_disjoint_from_every_product(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            matrix, router = _matrix_fixture(root)
            with self.assertRaisesRegex(
                ProductMatrixError,
                "PRODUCT_MATRIX_WORKSPACE_ROOT_OVERLAPS_PROTECTED_PATH",
            ):
                execute_matrix(
                    matrix,
                    router_repository=router,
                    release_root=root / "release",
                    workspace_root=root / "product-1" / "workspaces",
                )
            self.assertFalse((root / "release").exists())

    def test_execute_matrix_builds_and_qualifies_all_before_release_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            matrix, router = _matrix_fixture(root)
            calls: list[list[str]] = []

            def runner(command, **kwargs):
                calls.append(command)
                payload = (
                    _qualification_payload()
                    if "--qualification-only" in command
                    else _build_payload()
                )
                return _completed(command, 0, payload)
            def evaluator(packets):
                self.assertEqual(len(packets), 3)
                return {
                    "status": "passed",
                    "eligible_for_separately_authorized_real_canaries": True,
                    "eligible_for_default_product_development": False,
                }

            result = execute_matrix(
                matrix,
                router_repository=router,
                release_root=root / "release",
                workspace_root=root / "matrix-workspaces",
                runner=runner,
                evaluator=evaluator,
            )
            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["product_count"], 3)
            self.assertEqual(len(calls), 6)
            self.assertEqual(
                len(list((root / "release" / "diagnostics").rglob("*.*"))),
                18,
            )
            self.assertEqual(result["real_model_process_starts"], 0)
            self.assertTrue(
                result["eligible_for_separately_authorized_real_canaries"]
            )
            self.assertFalse(result["eligible_for_default_product_development"])

    def test_execute_matrix_stops_on_first_qualification_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            matrix, router = _matrix_fixture(root)
            calls: list[list[str]] = []
            qualifications = 0

            def runner(command, **kwargs):
                nonlocal qualifications
                calls.append(command)
                if "--qualification-only" not in command:
                    return _completed(command, 0, _build_payload())
                qualifications += 1
                if qualifications == 2:
                    return _completed(
                        command,
                        1,
                        {"status": "failed", "error": "VALIDATOR_FAILED"},
                    )
                return _completed(command, 0, _qualification_payload())
            result = execute_matrix(
                matrix,
                router_repository=router,
                release_root=root / "release",
                workspace_root=root / "matrix-workspaces",
                runner=runner,
                evaluator=lambda packets: self.fail("release evaluator must not run"),
            )
            self.assertEqual(result["status"], "failed")
            self.assertEqual(
                result["failed_step"], "product-2:qualification"
            )
            self.assertEqual(
                result["failure"], "qualification:VALIDATOR_FAILED"
            )
            self.assertEqual(result["product_count"], 1)
            self.assertEqual(len(calls), 4)
            self.assertEqual(result["real_model_process_starts"], 0)


if __name__ == "__main__":
    unittest.main()
