from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

from .config import canonical_json_bytes
from .product_release import evaluate_packets


class ProductMatrixError(RuntimeError):
    pass


CommandRunner = Callable[..., subprocess.CompletedProcess[str]]
ReleaseEvaluator = Callable[[list[Path]], dict[str, Any]]


def _strict_json(raw: bytes) -> Any:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise ValueError(f"duplicate key: {key}")
            result[key] = value
        return result

    def invalid_constant(value: str) -> Any:
        raise ValueError(f"non-finite number: {value}")

    return json.loads(
        raw.decode("utf-8", errors="strict"),
        object_pairs_hook=pairs,
        parse_constant=invalid_constant,
    )


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise ProductMatrixError("MATRIX_REPOSITORY_QUERY_FAILED")
    return completed.stdout.strip()


def _repository_state(repository: Path) -> dict[str, str]:
    if not repository.is_dir():
        raise ProductMatrixError("MATRIX_SOURCE_REPOSITORY_MISSING")
    return {
        "path": str(repository.resolve()),
        "head": _git(repository, "rev-parse", "HEAD"),
        "branch": _git(repository, "branch", "--show-current"),
        "status": _git(repository, "status", "--porcelain", "--untracked-files=all"),
    }


def _resolve_declared_path(base: Path, value: Any, code: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ProductMatrixError(code)
    path = Path(value)
    return (path if path.is_absolute() else base / path).resolve()


def load_matrix(matrix_path: str | Path) -> dict[str, Any]:
    path = Path(matrix_path).resolve()
    try:
        value = _strict_json(path.read_bytes())
    except (OSError, UnicodeError, ValueError) as exc:
        raise ProductMatrixError("PRODUCT_MATRIX_INVALID_JSON") from exc
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "release_id",
        "products",
    }:
        raise ProductMatrixError("PRODUCT_MATRIX_SCHEMA_INVALID")
    if (
        value.get("schema_version") != "1.0.0"
        or re.fullmatch(r"[A-Z0-9_-]+", str(value.get("release_id", "")))
        is None
        or not isinstance(value.get("products"), list)
        or len(value["products"]) < 3
    ):
        raise ProductMatrixError("PRODUCT_MATRIX_SCHEMA_INVALID")

    products: list[dict[str, Any]] = []
    packet_names: set[str] = set()
    routes: set[str] = set()
    lanes: set[str] = set()
    repository_ids: set[str] = set()
    repository_paths: set[str] = set()
    for item in value["products"]:
        if not isinstance(item, dict) or set(item) != {
            "packet_name",
            "product_contract",
            "source_repository",
        }:
            raise ProductMatrixError("PRODUCT_MATRIX_PRODUCT_INVALID")
        packet_name = item.get("packet_name")
        if (
            not isinstance(packet_name, str)
            or re.fullmatch(r"[a-z0-9][a-z0-9._-]*", packet_name) is None
            or packet_name in packet_names
        ):
            raise ProductMatrixError("PRODUCT_MATRIX_PACKET_NAME_INVALID")
        contract_path = _resolve_declared_path(
            path.parent,
            item.get("product_contract"),
            "PRODUCT_MATRIX_CONTRACT_PATH_INVALID",
        )
        source_repository = _resolve_declared_path(
            path.parent,
            item.get("source_repository"),
            "PRODUCT_MATRIX_SOURCE_PATH_INVALID",
        )
        try:
            contract = _strict_json(contract_path.read_bytes())
        except (OSError, UnicodeError, ValueError) as exc:
            raise ProductMatrixError("PRODUCT_MATRIX_CONTRACT_INVALID") from exc
        task = contract.get("task", {}) if isinstance(contract, dict) else {}
        route = contract.get("route_id") if isinstance(contract, dict) else None
        lane = task.get("case_id") if isinstance(task, dict) else None
        repository_id = (
            contract.get("repository_id") if isinstance(contract, dict) else None
        )
        if (
            not isinstance(route, str)
            or not route
            or not isinstance(lane, str)
            or not lane
            or not isinstance(repository_id, str)
            or not repository_id
            or contract.get("schema_version") != "2.0.0"
            or contract.get("qualification_release_only") is not True
            or task.get("repository") != repository_id
        ):
            raise ProductMatrixError("PRODUCT_MATRIX_CONTRACT_INVALID")
        normalized_repository = os.path.normcase(str(source_repository))
        if (
            route in routes
            or lane in lanes
            or repository_id in repository_ids
            or normalized_repository in repository_paths
        ):
            raise ProductMatrixError("PRODUCT_MATRIX_PRODUCT_IDENTITY_REUSED")
        state = _repository_state(source_repository)
        if state["status"] or task.get("baseline_head") != state["head"]:
            raise ProductMatrixError("PRODUCT_MATRIX_SOURCE_BASELINE_DRIFT")
        packet_names.add(packet_name)
        routes.add(route)
        lanes.add(lane)
        repository_ids.add(repository_id)
        repository_paths.add(normalized_repository)
        products.append(
            {
                "packet_name": packet_name,
                "product_contract": contract_path,
                "product_contract_sha256": hashlib.sha256(
                    contract_path.read_bytes()
                ).hexdigest(),
                "source_repository": source_repository,
                "source_head": state["head"],
                "source_branch": state["branch"],
                "route_id": route,
                "lane_id": lane,
                "repository_id": repository_id,
            }
        )
    return {
        "schema_version": "1.0.0",
        "release_id": value["release_id"],
        "matrix_path": path,
        "matrix_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "products": products,
    }


def _run_command(
    command: list[str],
    *,
    cwd: Path,
    timeout_seconds: int,
    runner: CommandRunner,
) -> dict[str, Any]:
    completed = runner(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout_seconds,
    )
    try:
        payload = _strict_json(completed.stdout.encode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise ProductMatrixError("PRODUCT_MATRIX_COMMAND_OUTPUT_INVALID") from exc
    if not isinstance(payload, dict):
        raise ProductMatrixError("PRODUCT_MATRIX_COMMAND_OUTPUT_INVALID")
    if completed.returncode != 0:
        raise ProductMatrixError(
            str(payload.get("error") or payload.get("failure") or "PRODUCT_MATRIX_COMMAND_FAILED")
        )
    return payload


def execute_matrix(
    matrix_path: str | Path,
    *,
    router_repository: str | Path,
    release_root: str | Path,
    runner: CommandRunner = subprocess.run,
    evaluator: ReleaseEvaluator = evaluate_packets,
    qualification_timeout_seconds: int = 1800,
) -> dict[str, Any]:
    spec = load_matrix(matrix_path)
    router = Path(router_repository).resolve()
    router_state = _repository_state(router)
    if (
        router_state["status"]
        or router_state["branch"] != "main"
        or re.fullmatch(r"[0-9a-f]{40}", router_state["head"]) is None
    ):
        raise ProductMatrixError("PRODUCT_MATRIX_ROUTER_BASELINE_INVALID")
    root = Path(release_root).resolve()
    if root.exists() and (
        not root.is_dir() or any(root.iterdir())
    ):
        raise ProductMatrixError("PRODUCT_MATRIX_RELEASE_ROOT_NOT_EMPTY")
    root.mkdir(parents=True, exist_ok=True)
    packets_root = root / "packets"
    workspaces_root = root / "workspaces"
    packets_root.mkdir()
    workspaces_root.mkdir()
    matrix_snapshot = root / "product-release-matrix.json"
    matrix_snapshot.write_bytes(spec["matrix_path"].read_bytes())

    project_root = Path(__file__).resolve().parents[2]
    product_results: list[dict[str, Any]] = []
    packet_paths: list[Path] = []
    report: dict[str, Any]
    try:
        for product in spec["products"]:
            packet = packets_root / product["packet_name"]
            build = _run_command(
                [
                    sys.executable,
                    "-B",
                    str(project_root / "scripts" / "build_product_lane_packet.py"),
                    "--output-directory",
                    str(packet),
                    "--router-repository",
                    str(router),
                    "--source-repository",
                    str(product["source_repository"]),
                    "--product-contract",
                    str(product["product_contract"]),
                ],
                cwd=project_root,
                timeout_seconds=300,
                runner=runner,
            )
            if (
                build.get("status") != "prepared_no_model_execution"
                or build.get("real_model_process_starts") != 0
                or build.get("real_model_requests") != 0
                or build.get("runtime_source_dirty") is not False
            ):
                raise ProductMatrixError("PRODUCT_MATRIX_BUILD_EVIDENCE_INVALID")
            qualification = _run_command(
                [
                    sys.executable,
                    "-B",
                    str(packet / "mtr-dogfood-product-lane.pyz"),
                    "--qualification-only",
                    "--packet-root",
                    str(packet),
                    "--router-repository",
                    str(router),
                    "--source-repository",
                    str(product["source_repository"]),
                    "--workspace-parent",
                    str(workspaces_root / product["packet_name"]),
                    "--result-root",
                    str(packet / "results" / "qualification"),
                ],
                cwd=project_root,
                timeout_seconds=qualification_timeout_seconds,
                runner=runner,
            )
            accounting = qualification.get("process_accounting", {})
            outcomes = qualification.get("outcomes", [])
            outcome = outcomes[0] if len(outcomes) == 1 else {}
            if (
                qualification.get("status") != "passed"
                or qualification.get("qualification_only") is not True
                or qualification.get("campaign_started") is not False
                or qualification.get("starts_consumed") != 0
                or qualification.get("source_repositories_unchanged") is not True
                or accounting.get("os_child_process_started") != 0
                or accounting.get("model_execution_observed") != 0
                or accounting.get("model_execution_completed") != 0
                or accounting.get("final_output_validated") != 1
                or not isinstance(accounting.get("validator_completed"), int)
                or accounting.get("validator_completed", 0) < 1
                or outcome.get("accepted") is not True
                or outcome.get("qualification_state")
                != "POST_MATERIALIZATION_VALIDATED"
                or outcome.get("real_model_process_starts") != 0
                or outcome.get("real_model_requests") != 0
            ):
                raise ProductMatrixError("PRODUCT_MATRIX_QUALIFICATION_INVALID")
            packet_paths.append(packet)
            product_results.append(
                {
                    "packet_name": product["packet_name"],
                    "route_id": product["route_id"],
                    "lane_id": product["lane_id"],
                    "repository_id": product["repository_id"],
                    "source_head": product["source_head"],
                    "product_contract_sha256": product[
                        "product_contract_sha256"
                    ],
                    "packet_manifest_sha256": build.get(
                        "packet_manifest_sha256"
                    ),
                    "runtime_artifact_sha256": build.get(
                        "runtime_artifact_sha256"
                    ),
                    "qualification_state": qualification["outcomes"][0].get(
                        "qualification_state"
                    ),
                    "validator_completed": accounting.get(
                        "validator_completed"
                    ),
                    "real_model_process_starts": 0,
                    "real_model_requests": 0,
                }
            )
        if _repository_state(router) != router_state:
            raise ProductMatrixError("PRODUCT_MATRIX_ROUTER_FINAL_DRIFT")
        for product in spec["products"]:
            final_state = _repository_state(product["source_repository"])
            if (
                final_state["head"] != product["source_head"]
                or final_state["branch"] != product["source_branch"]
                or final_state["status"]
            ):
                raise ProductMatrixError("PRODUCT_MATRIX_SOURCE_FINAL_DRIFT")
        release = evaluator(packet_paths)
        if (
            release.get("status") != "passed"
            or release.get("eligible_for_separately_authorized_real_canaries")
            is not True
            or release.get("eligible_for_default_product_development") is not False
        ):
            raise ProductMatrixError("PRODUCT_MATRIX_RELEASE_EVALUATION_FAILED")
        report = {
            "schema_version": "1.0.0",
            "release_id": spec["release_id"],
            "status": "passed",
            "matrix_sha256": spec["matrix_sha256"],
            "router_source_head": router_state["head"],
            "product_count": len(product_results),
            "products": product_results,
            "release_evaluation": release,
            "eligible_for_separately_authorized_real_canaries": True,
            "eligible_for_default_product_development": False,
            "real_model_process_starts": 0,
            "real_model_requests": 0,
        }
    except Exception as exc:
        report = {
            "schema_version": "1.0.0",
            "release_id": spec["release_id"],
            "status": "failed",
            "matrix_sha256": spec["matrix_sha256"],
            "router_source_head": router_state["head"],
            "product_count": len(product_results),
            "products": product_results,
            "failure_type": type(exc).__name__,
            "failure": str(exc),
            "eligible_for_separately_authorized_real_canaries": False,
            "eligible_for_default_product_development": False,
            "real_model_process_starts": 0,
            "real_model_requests": 0,
        }
    (root / "product-release-closeout.json").write_bytes(
        canonical_json_bytes(report)
    )
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="run-product-release-matrix")
    parser.add_argument("--matrix", required=True)
    parser.add_argument("--router-repository", required=True)
    parser.add_argument("--release-root", required=True)
    parser.add_argument(
        "--qualification-timeout-seconds", type=int, default=1800
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = execute_matrix(
            args.matrix,
            router_repository=args.router_repository,
            release_root=args.release_root,
            qualification_timeout_seconds=args.qualification_timeout_seconds,
        )
    except Exception as exc:
        result = {
            "schema_version": "1.0.0",
            "status": "failed",
            "failure_type": type(exc).__name__,
            "failure": str(exc),
            "eligible_for_separately_authorized_real_canaries": False,
            "eligible_for_default_product_development": False,
            "real_model_process_starts": 0,
            "real_model_requests": 0,
        }
    sys.stdout.buffer.write(canonical_json_bytes(result))
    return 0 if result.get("status") == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
