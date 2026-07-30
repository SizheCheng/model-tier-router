from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from mtr_dogfood.authorized_dispatcher import (
    activate_kill_switch,
    AuthorizedDispatchError,
    _assignment_bucket,
    build_dispatch_command,
    execute_authorized_dispatch,
    plan_dispatch,
    preflight_authorized_dispatch,
    validate_authorization,
    verify_plan,
)
from mtr_dogfood.config import json_digest


NOW = datetime(2026, 7, 22, 12, 0, tzinfo=timezone.utc)


def _authorization(repository: Path, **changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "1.0.0",
        "component_id": "MTR_CODEX_AUTHORIZED_MODEL_DISPATCH_R2",
        "authorization_id": "user-authorized-r2",
        "authorized_by": "local-user",
        "issued_at_utc": "2026-07-22T00:00:00Z",
        "expires_at_utc": "2026-08-22T00:00:00Z",
        "experiment_id": "official-candidate-pilot-r2",
        "allowed_repository_roots": [str(repository)],
        "allowed_models": ["gpt-5.6-terra", "gpt-5.6-sol"],
        "control_model": "gpt-5.6-sol",
        "control_reasoning_effort": "high",
        "router_share_basis_points": 8_000,
        "maximum_model_starts": 2,
        "model_selection_authorized": True,
        "new_process_launch_authorized": True,
        "permission_expansion_authorized": False,
        "authorized_write_scope": [],
        "network_access_authorized": False,
        "model_service_data_export_authorized": True,
    }
    value.update(changes)
    return value


def _decision(profile: str = "balanced", **changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "status": "recommended",
        "selected_profile": profile,
        "execution_authorized": False,
        "authorized_write_scope": [],
    }
    value.update(changes)
    return value


def _model_map() -> dict[str, object]:
    return {
        "mapping_version": "fixture-r1",
        "logical_profiles": {
            "balanced": {
                "codex_model": "gpt-5.6-terra",
                "model_reasoning_effort": "medium",
                "next_escalation_profile": "premium",
            },
            "premium": {
                "codex_model": "gpt-5.6-sol",
                "model_reasoning_effort": "high",
                "next_escalation_profile": None,
            },
        },
    }


def _unit_for(experiment: str, *, router: bool, share: int = 8_000) -> str:
    for index in range(100_000):
        value = f"unit-{index}"
        if (_assignment_bucket(experiment, value) < share) is router:
            return value
    raise AssertionError("unable to find deterministic assignment fixture")


class AuthorizedDispatcherTests(unittest.TestCase):
    def test_authorization_is_separate_and_cannot_expand_permissions(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            validated = validate_authorization(
                _authorization(repository), now=NOW
            )
            self.assertTrue(validated["model_selection_authorized"])
            self.assertFalse(validated["permission_expansion_authorized"])
            self.assertEqual(validated["authorized_write_scope"], [])
            self.assertFalse(validated["network_access_authorized"])
            self.assertTrue(validated["model_service_data_export_authorized"])
            for field, value, message in (
                (
                    "permission_expansion_authorized",
                    True,
                    "PERMISSION_EXPANSION_MUST_REMAIN_FALSE",
                ),
                ("authorized_write_scope", ["."], "WRITE_SCOPE_MUST_REMAIN_EMPTY"),
                (
                    "network_access_authorized",
                    True,
                    "NETWORK_ACCESS_MUST_REMAIN_FALSE",
                ),
                (
                    "model_service_data_export_authorized",
                    False,
                    "MODEL_SERVICE_DATA_EXPORT_NOT_AUTHORIZED",
                ),
            ):
                with self.subTest(field=field):
                    with self.assertRaisesRegex(AuthorizedDispatchError, message):
                        validate_authorization(
                            _authorization(repository, **{field: value}), now=NOW
                        )

    def test_expired_or_extra_field_authorization_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            with self.assertRaisesRegex(
                AuthorizedDispatchError, "AUTHORIZATION_NOT_ACTIVE"
            ):
                validate_authorization(
                    _authorization(
                        repository, expires_at_utc="2026-07-22T11:59:59Z"
                    ),
                    now=NOW,
                )
            value = _authorization(repository)
            value["extra"] = True
            with self.assertRaisesRegex(
                AuthorizedDispatchError, "AUTHORIZATION_SCHEMA_INVALID"
            ):
                validate_authorization(value, now=NOW)

    def test_router_and_control_assignments_are_deterministic_and_redacted(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            authorization = _authorization(repository)
            experiment = str(authorization["experiment_id"])
            router_unit = _unit_for(experiment, router=True)
            control_unit = _unit_for(experiment, router=False)
            router_plan = plan_dispatch(
                authorization,
                _decision(),
                _model_map(),
                repository=repository,
                assignment_unit=router_unit,
                model_start_ordinal=1,
                now=NOW,
            )
            control_plan = plan_dispatch(
                authorization,
                _decision(),
                _model_map(),
                repository=repository,
                assignment_unit=control_unit,
                model_start_ordinal=2,
                now=NOW,
            )
            self.assertEqual(router_plan["experiment"]["arm"], "ROUTER_AUTO")
            self.assertEqual(
                router_plan["execution"]["selected_model"], "gpt-5.6-terra"
            )
            self.assertEqual(
                control_plan["experiment"]["arm"], "FIXED_MODEL_CONTROL"
            )
            self.assertEqual(
                control_plan["execution"]["selected_model"], "gpt-5.6-sol"
            )
            self.assertNotIn(
                router_unit, json.dumps(router_plan, ensure_ascii=False)
            )
            self.assertEqual(verify_plan(router_plan), router_plan)

    def test_router_advisory_never_becomes_execution_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            with self.assertRaisesRegex(
                AuthorizedDispatchError, "ROUTER_ADVISORY_INVALID"
            ):
                plan_dispatch(
                    _authorization(repository),
                    _decision(execution_authorized=True),
                    _model_map(),
                    repository=repository,
                    assignment_unit="unit",
                    model_start_ordinal=1,
                    now=NOW,
                )

    def test_model_mapping_and_repository_are_strictly_allowlisted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "allowed"
            repository.mkdir()
            with self.assertRaisesRegex(
                AuthorizedDispatchError, "REPOSITORY_OUTSIDE_AUTHORIZED_ALLOWLIST"
            ):
                plan_dispatch(
                    _authorization(repository),
                    _decision(),
                    _model_map(),
                    repository=root / "other",
                    assignment_unit="unit",
                    model_start_ordinal=1,
                    now=NOW,
                )
            with self.assertRaisesRegex(
                AuthorizedDispatchError, "SELECTED_MODEL_OUTSIDE_AUTHORIZATION"
            ):
                plan_dispatch(
                    _authorization(
                        repository,
                        allowed_models=["gpt-5.6-luna", "gpt-5.6-sol"],
                    ),
                    _decision(),
                    _model_map(),
                    repository=repository,
                    assignment_unit="unit",
                    model_start_ordinal=1,
                    now=NOW,
                )

    @mock.patch(
        "mtr_dogfood.codex_runner.resolve_codex_executable",
        return_value=r"C:\fixture\codex.exe",
    )
    def test_command_uses_exact_assigned_model_and_preserves_sandbox(self, _resolve):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            schema = repository / "schema.json"
            output = repository / "output.json"
            schema.write_text("{}", encoding="utf-8")
            assignment_unit = _unit_for(
                "official-candidate-pilot-r2", router=True
            )
            plan = plan_dispatch(
                _authorization(repository),
                _decision(),
                _model_map(),
                repository=repository,
                assignment_unit=assignment_unit,
                model_start_ordinal=1,
                now=NOW,
            )
            command = build_dispatch_command(
                plan,
                authorization=_authorization(repository),
                router_decision=_decision(),
                model_map=_model_map(),
                assignment_unit=assignment_unit,
                worktree=repository,
                output_schema=schema,
                output_file=output,
                now=NOW,
            )
            self.assertEqual(command[command.index("--model") + 1], "gpt-5.6-terra")
            self.assertIn('approval_policy="never"', command)
            self.assertIn("sandbox_workspace_write.network_access=false", command)
            self.assertEqual(command.count("--model"), 1)
            forged = copy.deepcopy(plan)
            forged["execution"]["selected_model"] = "gpt-5.6-luna"
            forged.pop("plan_sha256")
            forged["plan_sha256"] = json_digest(forged)
            with self.assertRaisesRegex(
                AuthorizedDispatchError, "DISPATCH_PLAN_MODEL_NOT_AUTHORIZED"
            ):
                build_dispatch_command(
                    forged,
                    authorization=_authorization(repository),
                    router_decision=_decision(),
                    model_map=_model_map(),
                    assignment_unit=assignment_unit,
                    worktree=repository,
                    output_schema=schema,
                    output_file=output,
                    now=NOW,
                )
            allowed_forgery = copy.deepcopy(plan)
            allowed_forgery["execution"]["selected_model"] = "gpt-5.6-sol"
            allowed_forgery["execution"]["reasoning_effort"] = "high"
            allowed_forgery.pop("plan_sha256")
            allowed_forgery["plan_sha256"] = json_digest(allowed_forgery)
            with self.assertRaisesRegex(
                AuthorizedDispatchError, "DISPATCH_PLAN_ASSIGNMENT_DRIFT"
            ):
                build_dispatch_command(
                    allowed_forgery,
                    authorization=_authorization(repository),
                    router_decision=_decision(),
                    model_map=_model_map(),
                    assignment_unit=assignment_unit,
                    worktree=repository,
                    output_schema=schema,
                    output_file=output,
                    now=NOW,
                )
            malformed = copy.deepcopy(plan)
            malformed["execution"].pop("repository")
            malformed.pop("plan_sha256")
            malformed["plan_sha256"] = json_digest(malformed)
            with self.assertRaisesRegex(
                AuthorizedDispatchError, "DISPATCH_PLAN_SCHEMA_INVALID"
            ):
                build_dispatch_command(
                    malformed,
                    authorization=_authorization(repository),
                    router_decision=_decision(),
                    model_map=_model_map(),
                    assignment_unit=assignment_unit,
                    worktree=repository,
                    output_schema=schema,
                    output_file=output,
                    now=NOW,
                )


    def test_preflight_is_hash_bound_and_starts_no_model(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            schema = repository / "schema.json"
            schema.write_text("{}", encoding="utf-8")
            output = repository / "output.json"
            executable = root / "codex.exe"
            executable.write_bytes(b"fixture-codex")
            data = root / "data"
            with mock.patch(
                "mtr_dogfood.codex_runner.resolve_codex_executable",
                return_value=str(executable),
            ):
                result = preflight_authorized_dispatch(
                    _authorization(repository),
                    _decision(),
                    _model_map(),
                    repository=repository,
                    assignment_unit="unit-preflight",
                    data_root=data,
                    output_schema=schema,
                    output_file=output,
                    model_start_ordinal=1,
                    now=NOW,
                )
            self.assertEqual(result["status"], "ready")
            self.assertFalse(result["checks"]["model_process_started"])
            self.assertFalse(result["checks"]["network_request_started"])
            self.assertEqual(
                result["checks"]["codex_executable_sha256"],
                hashlib.sha256(b"fixture-codex").hexdigest(),
            )
            view = copy.deepcopy(result)
            recorded = view.pop("preflight_sha256")
            self.assertEqual(recorded, json_digest(view))
            self.assertFalse(data.exists())

    def test_kill_switch_is_irreversible_and_blocks_before_budget(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            schema = repository / "schema.json"
            schema.write_text("{}", encoding="utf-8")
            output = repository / "output.json"
            data = root / "data"
            raw = root / "raw"
            stop = activate_kill_switch(
                data, "user-authorized-r2", reason="operator-request", now=NOW
            )
            original = stop.read_bytes()
            self.assertEqual(
                activate_kill_switch(
                    data,
                    "user-authorized-r2",
                    reason="different-reason",
                    now=NOW,
                ),
                stop,
            )
            self.assertEqual(stop.read_bytes(), original)
            calls: list[str] = []

            def fake_run(*_args, **_values):
                calls.append("started")
                raise AssertionError("kill switch must block before runner")

            with self.assertRaisesRegex(
                AuthorizedDispatchError, "DISPATCH_KILL_SWITCH_ACTIVE"
            ):
                execute_authorized_dispatch(
                    _authorization(repository),
                    _decision(),
                    _model_map(),
                    repository=repository,
                    assignment_unit="unit-stopped",
                    data_root=data,
                    raw_directory=raw,
                    output_schema=schema,
                    output_file=output,
                    prompt="private task",
                    timeout_seconds=60,
                    now=NOW,
                    run_codex_fn=fake_run,
                )
            self.assertEqual(calls, [])
            self.assertEqual(list(data.rglob("slot-*.json")), [])

    @mock.patch(
        "mtr_dogfood.codex_runner.resolve_codex_executable",
        return_value=r"C:\fixture\codex.exe",
    )
    def test_running_dispatch_receives_live_kill_switch(self, _resolve):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            schema = repository / "schema.json"
            schema.write_text("{}", encoding="utf-8")
            output = repository / "output.json"
            data = root / "data"
            raw = root / "raw"
            authorization = _authorization(repository, maximum_model_starts=1)

            def fake_run(_command, _prompt, _raw_directory, **values):
                values["on_process_started"]()
                activate_kill_switch(
                    data, "user-authorized-r2", reason="operator-request", now=NOW
                )
                self.assertTrue(values["should_cancel"]())
                return {
                    "exit_code": 1,
                    "wall_time_seconds": 0.1,
                    "child_process_started": True,
                    "model_execution_observed": False,
                    "model_execution_completed": False,
                    "timed_out": False,
                    "cancelled": True,
                    "command_count": 0,
                    "file_change_event_count": 0,
                    "input_tokens": 0,
                    "cached_input_tokens": 0,
                    "output_tokens": 0,
                    "reasoning_output_tokens": 0,
                    "rate_limit_event_count": 0,
                    "model_unavailable_event_count": 0,
                    "authentication_event_count": 0,
                    "output_schema_error_count": 0,
                    "host_policy_failure_count": 0,
                    "infrastructure_failure_class": "OPERATOR_KILL_SWITCH",
                }

            result = execute_authorized_dispatch(
                authorization,
                _decision(),
                _model_map(),
                repository=repository,
                assignment_unit="unit-live-stop",
                data_root=data,
                raw_directory=raw,
                output_schema=schema,
                output_file=output,
                prompt="private task",
                timeout_seconds=60,
                now=NOW,
                run_codex_fn=fake_run,
            )
            self.assertTrue(result["execution"]["cancelled"])
            self.assertEqual(
                result["execution"]["infrastructure_failure_class"],
                "OPERATOR_KILL_SWITCH",
            )

    @mock.patch(
        "mtr_dogfood.codex_runner.resolve_codex_executable",
        return_value=r"C:\fixture\codex.exe",
    )
    def test_execution_writes_append_only_receipts_and_enforces_budget(self, _resolve):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            schema = repository / "schema.json"
            schema.write_text("{}", encoding="utf-8")
            output = repository / "output.json"
            data = root / "data"
            raw = root / "raw"
            authorization = _authorization(repository, maximum_model_starts=1)
            calls: list[list[str]] = []

            def fake_run(command, prompt, raw_directory, **values):
                self.assertEqual(prompt, "private task text")
                self.assertEqual(Path(raw_directory), raw)
                calls.append(command)
                values["on_process_started"]()
                self.assertFalse(values["should_cancel"]())
                return {
                    "exit_code": 0,
                    "wall_time_seconds": 1.0,
                    "child_process_started": True,
                    "model_execution_observed": True,
                    "model_execution_completed": True,
                    "timed_out": False,
                    "command_count": 0,
                    "file_change_event_count": 0,
                    "input_tokens": 1,
                    "cached_input_tokens": 0,
                    "output_tokens": 1,
                    "reasoning_output_tokens": 0,
                    "rate_limit_event_count": 0,
                    "model_unavailable_event_count": 0,
                    "authentication_event_count": 0,
                    "output_schema_error_count": 0,
                    "host_policy_failure_count": 0,
                    "infrastructure_failure_class": None,
                }

            result = execute_authorized_dispatch(
                authorization,
                _decision(),
                _model_map(),
                repository=repository,
                assignment_unit="unit-1",
                data_root=data,
                raw_directory=raw,
                output_schema=schema,
                output_file=output,
                prompt="private task text",
                timeout_seconds=60,
                now=NOW,
                run_codex_fn=fake_run,
            )
            self.assertEqual(len(calls), 1)
            self.assertTrue(result["execution"]["model_execution_completed"])
            receipt_files = sorted(data.rglob("*.json"))
            self.assertEqual(len(receipt_files), 4)
            receipt_text = "\n".join(
                path.read_text(encoding="utf-8") for path in receipt_files
            )
            self.assertNotIn("private task text", receipt_text)
            with self.assertRaisesRegex(
                AuthorizedDispatchError, "MODEL_START_BUDGET_EXHAUSTED"
            ):
                execute_authorized_dispatch(
                    authorization,
                    _decision(),
                    _model_map(),
                    repository=repository,
                    assignment_unit="unit-2",
                    data_root=data,
                    raw_directory=raw,
                    output_schema=schema,
                    output_file=output,
                    prompt="second private task",
                    timeout_seconds=60,
                    now=NOW,
                    run_codex_fn=fake_run,
                )
            self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
