from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from mtr_dogfood.bounded_writer import (
    POLICY_FILENAME,
    validate_writer_receipts,
)
from mtr_dogfood.external_runner import (
    BOUNDED_WRITER_RELATIVE,
    _child_prompt,
    _run_attempt,
    _scan_child_commands,
    _substantive_lane_content,
    _target_aliases,
)
from mtr_dogfood.config import load_json
from mtr_dogfood.runtime_contract import ProcessAccounting
from mtr_dogfood.validation import freeze_validator_plan


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/r3h-file-change-adapter-events.json"
FINAL_R1_SCANNER_FIXTURE = (
    ROOT / "tests/fixtures/final-r1-scanner-false-positive-events.jsonl"
)
WRITER = ROOT / "src/mtr_dogfood/bounded_writer.py"
ALLOWED = [
    "docs/dogfood-automation.md",
    "tests/integrations/test_dogfood_automation.py",
]
ALIASES = _target_aliases(ALLOWED)
ALIAS_BY_PATH = {path: alias for alias, path in ALIASES.items()}


def encoded(content: bytes) -> str:
    return base64.b64encode(content).decode("ascii")


def install_writer(workspace: Path, allowed: list[str] | None = None) -> Path:
    metadata = workspace / ".mtr-dogfood-r4"
    metadata.mkdir(parents=True)
    writer = metadata / "bounded-writer.py"
    shutil.copyfile(WRITER, writer)
    (metadata / POLICY_FILENAME).write_text(json.dumps({
        "schema_version": "2.0.0",
        "workspace": str(workspace.resolve()),
        "target_aliases": (
            _target_aliases(allowed) if allowed is not None else ALIASES
        ),
        "max_content_bytes": 1_000_000,
    }, sort_keys=True), encoding="utf-8")
    return writer


def run_writer(workspace: Path, slot: str, content: bytes) -> subprocess.CompletedProcess[str]:
    slot = ALIAS_BY_PATH.get(slot, slot)
    return subprocess.run(
        [
            sys.executable,
            "-B",
            BOUNDED_WRITER_RELATIVE,
            "--slot",
            slot,
            "--content-base64",
            encoded(content),
        ],
        cwd=workspace,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )


def command_event(
    command: str, *, output: str = "", exit_code: int = 0,
    status: str = "completed",
) -> dict[str, object]:
    return {
        "type": "item.completed",
        "item": {
            "id": "bounded-write",
            "type": "command_execution",
            "command": f'"powershell.exe" -Command "{command}"',
            "aggregated_output": output,
            "exit_code": exit_code,
            "status": status,
        },
    }


def run_git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=True,
    )
    return completed.stdout.strip()


def initialize_repository(repository: Path) -> str:
    repository.mkdir()
    run_git(repository, "init", "-b", "main")
    (repository / "README.md").write_text("fixture\n", encoding="utf-8")
    run_git(repository, "add", "README.md")
    run_git(
        repository,
        "-c", "user.name=Fixture",
        "-c", "user.email=fixture@example.invalid",
        "commit", "-m", "baseline",
    )
    return run_git(repository, "rev-parse", "HEAD")


class HistoricalFileChangeEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_exact_first_and_second_serialized_requests_and_responses(self):
        for attempt in self.fixture["attempts"]:
            with self.subTest(attempt=attempt["attempt"]):
                for phase in ("started", "completed"):
                    event = {
                        "type": f"item.{phase}",
                        "item": {
                            "id": attempt["item_id"],
                            "type": "file_change",
                            "changes": attempt["changes"],
                            "status": attempt[f"{phase}_status"],
                        },
                    }
                    raw = (
                        json.dumps(event, separators=(",", ":")) + "\n"
                    ).encode("utf-8")
                    self.assertEqual(
                        len(raw), attempt[f"{phase}_length_with_lf"]
                    )
                    self.assertEqual(
                        hashlib.sha256(raw).hexdigest(),
                        attempt[f"{phase}_sha256_with_lf"],
                    )
                self.assertEqual(attempt["completed_status"], "failed")
                self.assertTrue(
                    attempt["exact_error"].startswith("Failed to write file ")
                )

    def test_historical_targets_absent_parents_present_and_patch_body_unavailable(self):
        state = self.fixture["target_state_before_attempts"]
        self.assertFalse(state["targets_existed"])
        self.assertTrue(state["parent_directories_existed"])
        self.assertFalse(state["temporary_files_observed"])
        self.assertFalse(state["partial_files_observed"])
        self.assertFalse(self.fixture["patch_payload_serialized_in_events"])
        for field in (
            "patch_text", "patch_bytes", "patch_sha256",
            "patch_encoding", "patch_line_endings",
        ):
            self.assertIsNone(self.fixture[field])

    def test_shared_adapter_failure_precedes_successful_smoke_shell_write(self):
        smoke = self.fixture["writable_smoke_control"]
        self.assertEqual(smoke["file_change_completed_statuses"], ["failed", "failed"])
        self.assertEqual(smoke["shell_write_completed_statuses"], ["completed", "completed"])
        self.assertEqual(bytes.fromhex(smoke["written_bytes_hex"]), b"WORKSPACE_WRITE_OK\n")

    def test_invalid_patch_syntax_still_fails_in_installed_parser(self):
        appdata = os.environ.get("APPDATA", "")
        cli = Path(appdata) / (
            "npm/node_modules/@openai/codex/node_modules/@openai/"
            "codex-win32-x64/vendor/x86_64-pc-windows-msvc/bin/codex.exe"
        )
        if not cli.is_file():
            self.skipTest("standalone installed Codex patch parser is unavailable")
        with tempfile.TemporaryDirectory() as directory:
            completed = subprocess.run(
                [
                    str(cli),
                    "--codex-run-as-apply-patch",
                    "*** Begin Patch\n*** Add File: bad.txt\nnot-prefixed\n*** End Patch\n",
                ],
                cwd=directory,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                check=False,
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("Invalid patch hunk", completed.stdout + completed.stderr)


class BoundedWriterTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temporary.name).resolve()
        install_writer(self.workspace)

    def tearDown(self):
        self.temporary.cleanup()

    def test_absent_targets_and_parent_directories_are_created_with_exact_bytes(self):
        cases = {
            ALLOWED[0]: b"line one\r\nline two\r\n",
            ALLOWED[1]: b"from unittest import TestCase\n",
        }
        for target, content in cases.items():
            with self.subTest(target=target):
                completed = run_writer(self.workspace, target, content)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual((self.workspace / target).read_bytes(), content)
                receipt = json.loads(completed.stdout)
                self.assertEqual(receipt["target_alias"], ALIAS_BY_PATH[target])
                self.assertEqual(receipt["relative_path"], target)
                self.assertEqual(
                    receipt["content_sha256"], hashlib.sha256(content).hexdigest()
                )
                self.assertEqual(receipt["post_write_file_sha256"], receipt["content_sha256"])

    def test_existing_regular_file_is_atomically_replaced(self):
        target = self.workspace / ALLOWED[0]
        target.parent.mkdir(parents=True)
        target.write_bytes(b"old\n")
        completed = run_writer(self.workspace, ALLOWED[0], b"new UTF-8 \xe2\x9c\x93\n")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(target.read_bytes(), b"new UTF-8 \xe2\x9c\x93\n")
        self.assertEqual(list(target.parent.glob("*.mtr-bounded-*.tmp")), [])

    def test_escape_absolute_unc_source_credential_and_third_paths_are_rejected(self):
        cases = (
            "../escape.txt",
            r"C:\outside\escape.txt",
            r"\\server\share\escape.txt",
            r"C:\Users\sizhe\Documents\model-tier-router\README.md",
            ".codex/auth.json",
            "unauthorized-third.txt",
        )
        for target in cases:
            with self.subTest(target=target):
                completed = run_writer(self.workspace, target, b"blocked\n")
                self.assertEqual(completed.returncode, 2)
                self.assertIn("rejected", completed.stderr)
        self.assertFalse((self.workspace / "unauthorized-third.txt").exists())

    def test_reparse_escape_is_rejected_without_outside_write(self):
        outside = self.workspace.parent / f"{self.workspace.name}-outside"
        outside.mkdir()
        junction = self.workspace / "junction"
        if os.name == "nt":
            completed = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                check=False,
            )
            if completed.returncode != 0:
                self.skipTest("junction creation is unavailable")
        else:
            junction.symlink_to(outside, target_is_directory=True)
        (self.workspace / ".mtr-dogfood-r4" / POLICY_FILENAME).write_text(
            json.dumps({
                "schema_version": "2.0.0",
                "workspace": str(self.workspace),
                "target_aliases": {"junction_escape": "junction/escape.txt"},
                "max_content_bytes": 1_000_000,
            }),
            encoding="utf-8",
        )
        completed = run_writer(self.workspace, "junction_escape", b"blocked\n")
        self.assertEqual(completed.returncode, 2)
        self.assertIn("outside the workspace", completed.stderr)
        self.assertFalse((outside / "escape.txt").exists())
        if os.name == "nt":
            subprocess.run(["cmd", "/c", "rmdir", str(junction)], check=False)
        outside.rmdir()

    def test_policy_workspace_tampering_fails_closed(self):
        policy = self.workspace / ".mtr-dogfood-r4" / POLICY_FILENAME
        value = json.loads(policy.read_text(encoding="utf-8"))
        value["workspace"] = str(self.workspace.parent)
        policy.write_text(json.dumps(value), encoding="utf-8")
        completed = run_writer(self.workspace, ALLOWED[0], b"blocked\n")
        self.assertEqual(completed.returncode, 2)
        self.assertIn("not bound", completed.stderr)


class BoundedWriteScannerAndPromptTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.worktree = self.root / "worktree"
        self.worktree.mkdir()
        self.events = self.root / "events.jsonl"

    def tearDown(self):
        self.temporary.cleanup()

    def scan(self, command: str, *, output: str = "", exit_code: int = 0):
        self.events.write_text(
            json.dumps(command_event(command, output=output, exit_code=exit_code)) + "\n",
            encoding="utf-8",
        )
        metadata = self.worktree / ".mtr-dogfood-r4"
        receipts = []
        if metadata.is_dir():
            helper_hash = hashlib.sha256(
                (metadata / "bounded-writer.py").read_bytes()
            ).hexdigest()
            policy_hash = hashlib.sha256(
                (metadata / POLICY_FILENAME).read_bytes()
            ).hexdigest()
            receipts = validate_writer_receipts(
                workspace=self.worktree,
                helper_sha256=helper_hash,
                policy_sha256=policy_hash,
                target_aliases=ALIASES,
            )["receipts"]
        return _scan_child_commands(
            self.events, [], self.worktree, ALIASES, receipts
        )

    def test_exact_helper_write_is_scanner_visible_and_authorized(self):
        install_writer(self.worktree)
        completed = run_writer(self.worktree, ALLOWED[0], b"bounded\n")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        command = (
            f"python -B {BOUNDED_WRITER_RELATIVE} --slot {ALIAS_BY_PATH[ALLOWED[0]]} "
            f"--content-base64 {encoded(b'bounded\n')}"
        )
        scan = self.scan(command, output=completed.stdout)
        self.assertFalse(scan["bounded_write_violation_detected"])
        self.assertEqual(scan["bounded_write_count"], 1)
        self.assertEqual(scan["bounded_write_targets"], [ALLOWED[0]])
        transport = scan["command_records"][0]["bounded_write_transport"]
        self.assertTrue(transport["recognized"])
        self.assertTrue(transport["authorized"])
        self.assertTrue(transport["receipt_verified"])

    def test_malformed_helper_third_target_and_direct_shell_writes_fail_closed(self):
        commands = (
            f"python -B {BOUNDED_WRITER_RELATIVE} --slot unknown_alias --content-base64 QQ==",
            f"python -B {BOUNDED_WRITER_RELATIVE} --slot {ALIAS_BY_PATH[ALLOWED[0]]} --content-base64 %%%",
            "[System.IO.File]::WriteAllText('docs/direct.txt', 'blocked')",
            "python -c \"from pathlib import Path; Path('docs/direct.txt').write_text('x')\"",
            "python -c \"open('docs/direct.txt', 'w').write('x')\"",
            "git add docs/dogfood-automation.md",
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertTrue(self.scan(command)["bounded_write_violation_detected"])

    def test_exact_final_r1_false_positive_commands_are_semantically_clean(self):
        expected_hashes = [
            "819ab119ab9446dd8ae35353fe91b048c0ecd2f813d2efb9c09867039e3a37a3",
            "c7ecbf2ba631b5cfe81b497a3efa23dac7fd03aa66e605fb7901e7cacaf77e1d",
        ]
        commands = [
            json.loads(line)["item"]["command"]
            for line in FINAL_R1_SCANNER_FIXTURE.read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(
            [hashlib.sha256(command.encode("utf-8")).hexdigest() for command in commands],
            expected_hashes,
        )
        scan = _scan_child_commands(
            FINAL_R1_SCANNER_FIXTURE,
            [],
            self.worktree,
            ALIASES,
            [],
            model_read_only=True,
        )
        for flag in (
            "forbidden_action_detected",
            "external_path_access_detected",
            "credential_access_detected",
            "remote_operation_attempted",
            "unparseable_command_detected",
            "bounded_write_violation_detected",
            "model_direct_write_attempt_detected",
        ):
            self.assertFalse(scan[flag], flag)
        self.assertTrue(
            all(record["executable_paths"] for record in scan["command_records"])
        )
        self.assertTrue(
            all(not record["path_candidates"] for record in scan["command_records"])
        )

    def test_semantic_scanner_still_rejects_real_external_secret_remote_and_write_ops(self):
        cases = (
            (r"Get-Content C:\outside\secret.txt", "external_path_access_detected"),
            (r"Get-Content $env:OPENAI_API_KEY", "credential_access_detected"),
            ("Invoke-WebRequest https://example.invalid", "remote_operation_attempted"),
            (r"Set-Content -LiteralPath C:\outside\result.txt -Value blocked", "bounded_write_violation_detected"),
        )
        for command, flag in cases:
            with self.subTest(command=command, flag=flag):
                self.assertTrue(self.scan(command)[flag])

    def test_parse_failure_is_indeterminate_not_proof_of_external_access(self):
        self.events.write_text(json.dumps({
            "type": "item.completed",
            "item": {
                "type": "command_execution",
                "command": "'powershell.exe -Command Get-Content README.md",
                "exit_code": 0,
            },
        }) + "\n", encoding="utf-8")
        scan = _scan_child_commands(self.events, [], self.worktree)
        self.assertTrue(scan["unparseable_command_detected"])
        self.assertFalse(scan["external_path_access_detected"])
    def test_remote_and_git_ref_mutations_remain_forbidden(self):
        for command in ("git push origin main", "git commit -m blocked"):
            with self.subTest(command=command):
                scan = self.scan(command)
                self.assertTrue(scan["forbidden_action_detected"])
                if "push" in command:
                    self.assertTrue(scan["remote_operation_attempted"])

    def test_prompt_grants_alias_only_read_only_proposal_transport(self):
        case = {
            "title": "bounded",
            "task_text": "create exact files",
            "changed_path_patterns": ALLOWED,
            "validator_plan": {"commands": []},
        }
        prompt = _child_prompt(case, self.worktree)
        self.assertIn("model phase is read-only", prompt.casefold())
        self.assertIn("Do not invoke file_change", prompt)
        self.assertIn("Do not put a filesystem path", prompt)
        self.assertNotIn("--content-base64", prompt)
        self.assertIn("Do not return a", prompt)
        self.assertIn("lane_id", prompt)
        for alias, target in ALIASES.items():
            self.assertIn(alias, prompt)
            self.assertNotIn(target, prompt)


class BoundedTransportIntegrationTests(unittest.TestCase):
    def test_full_attempt_accepts_only_scanned_helper_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            harness = base / "harness"
            repository = base / "repository"
            pool = base / "pool"
            harness.mkdir()
            baseline = initialize_repository(repository)
            (harness / "schemas").mkdir()
            for name in (
                "proposed-files-result.schema.json",
                "bounded-writer-receipt.schema.json",
                "task.schema.json",
                "authority-receipt.schema.json",
            ):
                shutil.copyfile(ROOT / "schemas" / name, harness / "schemas" / name)
            (harness / "config").mkdir()
            shutil.copyfile(ROOT / "config" / "host-materialization-lanes.json", harness / "config" / "host-materialization-lanes.json")
            validator_plan = {
                "commands": [{
                    "name": "bounded-output",
                    "layer": "focused",
                    "command": [
                        "python", "-B", "-c",
                        "from pathlib import Path; assert Path('docs/dogfood-automation.md').is_file(); assert Path('tests/integrations/test_dogfood_automation.py').is_file()",
                    ],
                    "timeout_seconds": 30,
                }]
            }
            case = {
                "schema_version": "1.0.0",
                "case_id": "mtr-docs-private-executor-r1",
                "repository": "model-tier-router",
                "baseline_head": baseline,
                "title": "bounded integration",
                "task_text": "create the two exact synthetic outputs",
                "changed_path_patterns": ALLOWED,
                "risk": "LOW_RISK",
                "change_class": "documentation",
                "validator_plan": validator_plan,
                "validator_plan_digest": freeze_validator_plan(validator_plan),
                "model_timeout_seconds": 30,
            }
            contract = load_json(
                ROOT / "contracts/MODEL_TIER_ROUTER_DOGFOOD_R3_EXTERNAL_RUNTIME.json"
            )
            contract["paths"]["worktree_pool"] = str(pool)
            contract["repositories"] = {
                "model-tier-router": {
                    "path": str(repository),
                    "branch": "main",
                    "baseline_head": baseline,
                },
                "qwen-redaction-standalone": {
                    "path": str(base / "unused-qwen"),
                    "branch": "qwen-redaction-r1",
                    "baseline_head": "b" * 40,
                },
            }
            contract["reporting"]["receipt_root"] = "receipts"
            contract["reporting"]["raw_root"] = "raw"
            contract["commit_identity"] = {
                "name": "Fixture",
                "email": "fixture@example.invalid",
                "persistent_configuration": False,
            }
            descriptor = {
                "branch_prefix": "test/bounded-router",
                "automatic_fast_forward_merge": True,
            }
            decision = {
                "status": "recommended",
                "selected_profile": "balanced",
                "execution_authorized": False,
                "authorized_write_scope": [],
            }
            contents = {
                ALLOWED[0]: (
                    b"The recommended result keeps execution_authorized false and "
                    b"authorized_write_scope empty until separate current authority.\n"
                ),
                ALLOWED[1]: (
                    b"import unittest\n# assess recommended execution_authorized "
                    b"authorized_write_scope\nclass AdvisoryTest(unittest.TestCase):\n"
                    b"    def test_recommended(self): self.assertTrue(True)\n"
                ),
            }

            def launcher(**kwargs):
                kwargs["on_process_started"]()
                proposed = []
                for target, content in contents.items():
                    alias = ALIAS_BY_PATH[target]
                    proposed.append({
                        "target_alias": alias,
                        "content": content.decode("utf-8"),
                    })
                output = Path(
                    kwargs["command"][
                        kwargs["command"].index("--output-last-message") + 1
                    ]
                )
                output.write_text(json.dumps({
                    "schema_version": "1.0.0",
                    "status": "completed",
                    "summary": "read-only proposal completed",
                    "notes": [],
                    "proposed_files": proposed,
                    "validation_expectations": [{
                        "name": "parent validators",
                        "expectation": "frozen validators pass",
                        "required": True,
                    }],
                }), encoding="utf-8")
                raw = Path(kwargs["raw_directory"])
                raw.mkdir(parents=True, exist_ok=True)
                (raw / "codex-events.jsonl").write_text(
                    json.dumps({"type": "turn.completed"}) + "\n",
                    encoding="utf-8",
                )
                return {
                    "exit_code": 0,
                    "wall_time_seconds": 0.01,
                    "child_process_started": True,
                    "model_execution_observed": True,
                    "model_execution_completed": True,
                    "timed_out": False,
                    "host_policy_failure_count": 0,
                    "infrastructure_failure_class": None,
                    "rate_limit_event_count": 0,
                    "model_unavailable_event_count": 0,
                    "authentication_event_count": 0,
                    "output_schema_error_count": 0,
                    "input_tokens": 0,
                    "cached_input_tokens": 0,
                    "output_tokens": 0,
                    "reasoning_output_tokens": 0,
                }

            outcome = _run_attempt(
                contract,
                case,
                descriptor,
                b"{}",
                decision,
                "balanced",
                1,
                0,
                ProcessAccounting(),
                launcher,
                lambda: {},
                lambda: "fake-codex.exe",
                harness,
            )
            self.assertTrue(outcome["accepted"])
            self.assertEqual(outcome["failure_causes"], [])
            self.assertTrue(outcome["automatic_merge"])
            scan = outcome["child_command_scan"]
            self.assertEqual(scan["bounded_write_count"], 0)
            self.assertEqual(scan["bounded_write_targets"], [])
            self.assertFalse(scan["bounded_write_violation_detected"])

            self.assertEqual(
                outcome["bounded_writer_receipt_validation"]["receipt_count"], 2
            )

class SubstantiveContentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.worktree = Path(self.temporary.name)
        (self.worktree / "docs").mkdir()
        (self.worktree / "tests/integrations").mkdir(parents=True)
        self.case = {
            "case_id": "mtr-docs-private-executor-r1",
            "changed_path_patterns": ALLOWED,
        }
        self.documentation = self.worktree / ALLOWED[0]
        self.integration = self.worktree / ALLOWED[1]

    def tearDown(self):
        self.temporary.cleanup()

    def valid_outputs(self):
        self.documentation.write_text(
            "The recommended result keeps execution_authorized false and "
            "authorized_write_scope empty until separate current authority is supplied.\n",
            encoding="utf-8",
        )
        self.integration.write_text(
            "import unittest\n# assess recommended execution_authorized "
            "authorized_write_scope\nclass AdvisoryTest(unittest.TestCase):\n"
            "    def test_recommended(self): self.assertTrue(True)\n",
            encoding="utf-8",
        )

    def test_empty_or_missing_substantive_outputs_fail(self):
        self.documentation.write_text("", encoding="utf-8")
        self.integration.write_text("", encoding="utf-8")
        self.assertFalse(_substantive_lane_content(self.case, self.worktree))
        self.valid_outputs()
        self.integration.write_text("# no substantive test\n", encoding="utf-8")
        self.assertFalse(_substantive_lane_content(self.case, self.worktree))
        self.valid_outputs()
        self.documentation.write_text("# no substantive guide\n", encoding="utf-8")
        self.assertFalse(_substantive_lane_content(self.case, self.worktree))

    def test_both_substantive_outputs_pass(self):
        self.valid_outputs()
        self.assertTrue(_substantive_lane_content(self.case, self.worktree))


if __name__ == "__main__":
    unittest.main()
