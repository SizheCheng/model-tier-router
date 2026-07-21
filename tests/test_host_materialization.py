from __future__ import annotations

import base64
import copy
import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from mtr_dogfood.bounded_writer import (
    POLICY_FILENAME,
    BoundedWriteError,
    write_bounded_file,
)
from mtr_dogfood.config import load_json
from mtr_dogfood.external_runner import (
    _inspect_bounded_write,
    _scan_child_commands,
)
from mtr_dogfood.host_materialization import (
    HostMaterializationError,
    PROTOCOL_CLASSIFICATIONS,
    alias_map,
    lane_contract,
    load_lane_policy,
    materialize_transaction,
    validate_model_phase,
    validate_proposed_result,
    validate_transaction_receipt,
)
from mtr_dogfood.writable_smoke import (
    build_external_codex_command,
    validate_external_command_shape,
)


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "config" / "host-materialization-lanes.json"
SCHEMA_PATH = ROOT / "schemas" / "proposed-files-result.schema.json"
RECEIPT_SCHEMA_PATH = ROOT / "schemas" / "bounded-writer-receipt.schema.json"


def content_for(lane_id: str) -> dict[str, str]:
    if lane_id == "writable_smoke":
        return {"smoke_result": "WORKSPACE_WRITE_OK\n"}
    if lane_id == "mtr-docs-private-executor-r1":
        return {
            "router_documentation": (
                "# Advisory executor\n\nThe recommended result preserves "
                "execution_authorized=false and authorized_write_scope=[] until "
                "separate current authority is supplied. Quotes: \"ok\"; path text: "
                "a\\b; tab:\t; Unicode: 路径.\n"
            ),
            "router_integration_test": (
                "import unittest\n\n"
                "class AdvisoryTest(unittest.TestCase):\n"
                "    def test_assess_is_recommended(self):\n"
                "        assess = {'status': 'recommended', "
                "'execution_authorized': False, 'authorized_write_scope': []}\n"
                "        self.assertEqual(assess['status'], 'recommended')\n"
            ),
        }
    return {
        "qwen_docx_hidden_elements_test": (
            "import unittest\n\n"
            "class HiddenElementTest(unittest.TestCase):\n"
            "    def test_vanish_and_webhidden(self):\n"
            "        self.assertEqual({'vanish', 'webHidden'}, {'vanish', 'webHidden'})\n"
        )
    }


def result_value(
    lane: dict,
    contents: dict[str, str] | None = None,
    *,
    status: str = "completed",
    line_endings: str = "LF",
) -> dict:
    contents = contents or content_for(lane["lane_id"])
    proposed = []
    for policy in lane["aliases"]:
        alias = policy["target_alias"]
        text = contents[alias]
        if line_endings == "CRLF":
            text = text.replace("\r\n", "\n").replace("\n", "\r\n")
        encoded = text.encode("utf-8")
        proposed.append({
            "target_alias": alias,
            "representation": "utf8_text",
            "encoding": "UTF-8",
            "content": text,
            "utf8_byte_count": len(encoded),
            "sha256": hashlib.sha256(encoded).hexdigest(),
            "line_endings": line_endings,
            "media_type": policy["media_type"],
        })
    return {
        "schema_version": "1.0.0",
        "lane_id": lane["lane_id"],
        "status": status,
        "summary": "complete proposed files",
        "notes": [],
        "proposed_files": proposed,
        "validation_expectations": [{
            "name": "parent-validation",
            "expectation": "all frozen parent validators pass",
            "required": True,
        }],
    }


def raw_result(value: dict) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


class ProposedFileProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = load_lane_policy(POLICY_PATH)
        cls.schema = load_json(SCHEMA_PATH)

    def assert_classification(self, expected: str, raw: bytes, lane: dict) -> None:
        with self.assertRaises(HostMaterializationError) as captured:
            validate_proposed_result(raw, lane=lane, schema=self.schema)
        self.assertEqual(captured.exception.classification, expected)
        self.assertIn(expected, PROTOCOL_CLASSIFICATIONS)

    def test_proof_model_and_mechanical_lane_limits(self):
        self.assertFalse(self.policy["model_output_success_guaranteed"])
        self.assertTrue(self.policy["safety_independent_of_model_output_capacity"])
        expected = {
            "writable_smoke": (1, 19, 4096),
            "mtr-docs-private-executor-r1": (2, 24576, 155648),
            "qwen-docx-hidden-elements-r1": (1, 32768, 204800),
        }
        for lane in self.policy["lanes"]:
            with self.subTest(lane=lane["lane_id"]):
                self.assertEqual(
                    (
                        lane["maximum_file_count"],
                        lane["maximum_aggregate_content_bytes"],
                        lane["maximum_serialized_result_bytes"],
                    ),
                    expected[lane["lane_id"]],
                )
                self.assertGreaterEqual(
                    lane["maximum_serialized_result_bytes"],
                    lane["maximum_aggregate_content_bytes"] * 6
                    + (0 if lane["lane_id"] == "writable_smoke" else 8192),
                )

    def test_valid_smoke_markdown_python_unicode_and_lf(self):
        for lane_id in (
            "writable_smoke",
            "mtr-docs-private-executor-r1",
            "qwen-docx-hidden-elements-r1",
        ):
            with self.subTest(lane=lane_id):
                lane = lane_contract(self.policy, lane_id)
                proposal = validate_proposed_result(
                    raw_result(result_value(lane)), lane=lane, schema=self.schema
                )
                self.assertEqual(
                    [item.target_alias for item in proposal.files],
                    [item["target_alias"] for item in lane["aliases"]],
                )
                self.assertTrue(all(item.line_endings == "LF" for item in proposal.files))

    def test_crlf_is_preserved_when_declared(self):
        lane = lane_contract(self.policy, "mtr-docs-private-executor-r1")
        proposal = validate_proposed_result(
            raw_result(result_value(lane, line_endings="CRLF")),
            lane=lane,
            schema=self.schema,
        )
        self.assertTrue(all(b"\r\n" in item.content for item in proposal.files))
        self.assertTrue(all(b"\n" not in item.content.replace(b"\r\n", b"") for item in proposal.files))

    def test_invalid_utf8_malformed_truncated_and_incomplete(self):
        lane = lane_contract(self.policy, "writable_smoke")
        self.assert_classification("PROPOSED_FILE_ENCODING_INVALID", b"\xff", lane)
        self.assert_classification("MODEL_OUTPUT_MALFORMED", b"{not-json", lane)
        self.assert_classification("MODEL_OUTPUT_MALFORMED", b'{"schema_version":"1.0.0"', lane)
        self.assert_classification(
            "MODEL_OUTPUT_INCOMPLETE",
            raw_result(result_value(lane, status="blocked")),
            lane,
        )

    def test_schema_path_representation_encoding_media_and_tests_rejections(self):
        lane = lane_contract(self.policy, "writable_smoke")
        mutations = []
        value = result_value(lane)
        value["proposed_files"][0]["relative_path"] = "smoke/result.txt"
        mutations.append(value)
        for field, bad in (
            ("representation", "base64"),
            ("encoding", "UTF-16"),
            ("media_type", "application/octet-stream"),
        ):
            value = result_value(lane)
            value["proposed_files"][0][field] = bad
            mutations.append(value)
        value = result_value(lane)
        value["validation_expectations"] = []
        mutations.append(value)
        for value in mutations:
            with self.subTest(value=value):
                self.assert_classification(
                    "MODEL_OUTPUT_SCHEMA_INVALID", raw_result(value), lane
                )

    def test_alias_set_lane_and_duplicate_rejections(self):
        lane = lane_contract(self.policy, "mtr-docs-private-executor-r1")
        unknown = result_value(lane)
        unknown["proposed_files"][0]["target_alias"] = "unknown_alias"
        self.assert_classification(
            "PROPOSED_FILE_ALIAS_INVALID", raw_result(unknown), lane
        )
        duplicate = result_value(lane)
        duplicate["proposed_files"][1]["target_alias"] = duplicate["proposed_files"][0]["target_alias"]
        self.assert_classification(
            "PROPOSED_FILE_ALIAS_INVALID", raw_result(duplicate), lane
        )
        missing = result_value(lane)
        missing["proposed_files"].pop()
        self.assert_classification(
            "PROPOSED_FILE_SET_INCOMPLETE", raw_result(missing), lane
        )
        extra = result_value(lane)
        extra["proposed_files"].append(copy.deepcopy(extra["proposed_files"][0]))
        extra["proposed_files"][-1]["target_alias"] = "extra_alias"
        self.assert_classification(
            "PROPOSED_FILE_SET_UNEXPECTED", raw_result(extra), lane
        )
        incorrect_lane = result_value(lane)
        incorrect_lane["lane_id"] = "qwen-docx-hidden-elements-r1"
        self.assert_classification(
            "PROPOSED_FILE_ALIAS_INVALID", raw_result(incorrect_lane), lane
        )

    def test_nul_line_endings_byte_count_and_digest_rejections(self):
        lane = lane_contract(self.policy, "mtr-docs-private-executor-r1")
        cases = []
        nul = result_value(lane)
        nul["proposed_files"][0]["content"] += "\x00"
        nul["proposed_files"][0]["utf8_byte_count"] += 1
        nul["proposed_files"][0]["sha256"] = hashlib.sha256(
            nul["proposed_files"][0]["content"].encode()
        ).hexdigest()
        cases.append(("PROPOSED_FILE_ENCODING_INVALID", nul))
        endings = result_value(lane)
        endings["proposed_files"][0]["line_endings"] = "CRLF"
        cases.append(("PROPOSED_FILE_ENCODING_INVALID", endings))
        count = result_value(lane)
        count["proposed_files"][0]["utf8_byte_count"] += 1
        cases.append(("PROPOSED_FILE_ENCODING_INVALID", count))
        digest = result_value(lane)
        digest["proposed_files"][0]["sha256"] = "0" * 64
        cases.append(("PROPOSED_FILE_DIGEST_MISMATCH", digest))
        for expected, value in cases:
            with self.subTest(expected=expected):
                self.assert_classification(expected, raw_result(value), lane)

    def test_per_alias_aggregate_and_serialized_limits(self):
        lane = lane_contract(self.policy, "mtr-docs-private-executor-r1")
        over = result_value(lane)
        text = "x" * (lane["aliases"][0]["maximum_content_bytes"] + 1)
        encoded = text.encode()
        over["proposed_files"][0].update({
            "content": text,
            "utf8_byte_count": len(encoded),
            "sha256": hashlib.sha256(encoded).hexdigest(),
        })
        self.assert_classification(
            "PROPOSED_FILE_CONTENT_LIMIT_EXCEEDED", raw_result(over), lane
        )
        aggregate_lane = copy.deepcopy(lane)
        aggregate_lane["aliases"][0]["maximum_content_bytes"] = 20000
        aggregate_lane["aliases"][1]["maximum_content_bytes"] = 20000
        contents = {
            "router_documentation": "a" * 13000,
            "router_integration_test": "b" * 13000,
        }
        self.assert_classification(
            "PROPOSED_FILE_AGGREGATE_LIMIT_EXCEEDED",
            raw_result(result_value(aggregate_lane, contents)),
            aggregate_lane,
        )
        serialized_lane = copy.deepcopy(lane)
        serialized_lane["maximum_serialized_result_bytes"] = 32
        self.assert_classification(
            "PROPOSED_FILE_AGGREGATE_LIMIT_EXCEEDED",
            raw_result(result_value(lane)),
            serialized_lane,
        )

        alias_serialized_lane = copy.deepcopy(lane)
        alias_serialized_lane["aliases"][0]["maximum_serialized_bytes"] = 32
        self.assert_classification(
            "PROPOSED_FILE_AGGREGATE_LIMIT_EXCEEDED",
            raw_result(result_value(lane)),
            alias_serialized_lane,
        )

    def test_empty_and_incomplete_substantive_files_fail_before_materialization(self):
        lane = lane_contract(self.policy, "mtr-docs-private-executor-r1")
        empty = result_value(lane)
        empty["proposed_files"][0].update({
            "content": "",
            "utf8_byte_count": 0,
            "sha256": hashlib.sha256(b"").hexdigest(),
        })
        self.assert_classification(
            "PROPOSED_FILE_CONTENT_LIMIT_EXCEEDED", raw_result(empty), lane
        )
        for alias in ("router_documentation", "router_integration_test"):
            with self.subTest(alias=alias):
                incomplete = result_value(lane)
                record = next(
                    item for item in incomplete["proposed_files"]
                    if item["target_alias"] == alias
                )
                record.update({
                    "content": "incomplete\n",
                    "utf8_byte_count": len(b"incomplete\n"),
                    "sha256": hashlib.sha256(b"incomplete\n").hexdigest(),
                })
                self.assert_classification(
                    "LANE_VALIDATION_FAILED", raw_result(incomplete), lane
                )

    def test_r5a_capacity_binding_and_old_argument_protocol_rejection(self):
        payload = b"x" * 1_000_000
        self.assertEqual(len(base64.b64encode(payload)), 1_333_336)
        self.assertEqual((32_766, 32_778), (32_766, 32_778))
        inspected = _inspect_bounded_write(
            "python -B .mtr-dogfood-r4/bounded-writer.py --slot smoke_result "
            "--content-base64 " + base64.b64encode(b"x" * 1_000_001).decode(),
            {"smoke_result": "smoke/result.txt"},
        )
        self.assertFalse(inspected["authorized"])
        self.assertEqual(inspected["reason"], "content_size_limit_exceeded")

    def test_command_is_read_only_and_contains_no_file_content_argument(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            command = build_external_codex_command(
                "fake-codex.exe", root, "fixture-model", "low",
                root / "schema.json", root / "result.json",
            )
            validate_external_command_shape(command, root)
            self.assertEqual(command[command.index("--sandbox") + 1], "read-only")
            self.assertNotIn("--content-base64", command)
            self.assertNotIn("WORKSPACE_WRITE_OK", " ".join(command))


class ModelPhaseGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = load_lane_policy(POLICY_PATH)
        cls.schema = load_json(SCHEMA_PATH)
        cls.lane = lane_contract(cls.policy, "writable_smoke")

    def _process(self, **changes):
        result = {
            "child_process_started": True,
            "exit_code": 0,
            "model_execution_completed": True,
        }
        result.update(changes)
        return result

    def _scan(self, **changes):
        result = {
            "forbidden_action_detected": False,
            "external_path_access_detected": False,
            "credential_access_detected": False,
            "remote_operation_attempted": False,
            "unparseable_command_detected": False,
            "bounded_write_violation_detected": False,
            "model_direct_write_attempt_detected": False,
            "model_file_change_attempt_detected": False,
        }
        result.update(changes)
        return result

    def test_process_output_workspace_and_hash_failures_materialize_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "final.json"
            output.write_bytes(raw_result(result_value(self.lane)))
            cases = [
                (self._process(child_process_started=False), self._scan(), False, True, "MODEL_OUTPUT_INCOMPLETE"),
                (self._process(exit_code=1), self._scan(), False, True, "MODEL_OUTPUT_INCOMPLETE"),
                (self._process(model_execution_completed=False), self._scan(), False, True, "MODEL_OUTPUT_INCOMPLETE"),
                (self._process(), self._scan(), True, True, "MODEL_WORKSPACE_MUTATION_BEFORE_MATERIALIZATION"),
                (self._process(), self._scan(), False, False, "MODEL_WORKSPACE_MUTATION_BEFORE_MATERIALIZATION"),
                (self._process(), self._scan(model_file_change_attempt_detected=True), False, True, "MODEL_FILE_CHANGE_ATTEMPT"),
                (self._process(), self._scan(model_direct_write_attempt_detected=True), False, True, "MODEL_DIRECT_WRITE_ATTEMPT"),
            ]
            for process, scan, mutated, hashes, expected in cases:
                with self.subTest(expected=expected):
                    with self.assertRaises(HostMaterializationError) as captured:
                        validate_model_phase(
                            process_result=process,
                            output_path=output,
                            lane=self.lane,
                            schema=self.schema,
                            command_scan=scan,
                            workspace_mutated=mutated,
                            immutable_hashes_match=hashes,
                        )
                    self.assertEqual(captured.exception.classification, expected)
                    self.assertFalse((root / "smoke" / "result.txt").exists())
            output.unlink()
            with self.assertRaises(HostMaterializationError) as captured:
                validate_model_phase(
                    process_result=self._process(),
                    output_path=output,
                    lane=self.lane,
                    schema=self.schema,
                    command_scan=self._scan(),
                    workspace_mutated=False,
                    immutable_hashes_match=True,
                )
            self.assertEqual(captured.exception.classification, "MODEL_OUTPUT_INCOMPLETE")

    def test_scanner_rejects_file_change_apply_patch_shell_python_and_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands = [
                {"type": "file_change"},
                {"type": "command_execution", "command": "apply_patch patch.txt", "exit_code": 0},
                {"type": "command_execution", "command": "powershell -Command Set-Content x hi", "exit_code": 0},
                {"type": "command_execution", "command": "python -c \"open('x','w').write('x')\"", "exit_code": 0},
                {"type": "command_execution", "command": "python -B .mtr-dogfood-r4/bounded-writer.py --slot smoke_result --content-base64 eA==", "exit_code": 0},
            ]
            for index, item in enumerate(commands):
                path = root / f"events-{index}.jsonl"
                path.write_text(json.dumps({"type": "item.completed", "item": item}) + "\n")
                scan = _scan_child_commands(
                    path, [], root, {"smoke_result": "smoke/result.txt"}, [],
                    model_read_only=True,
                )
                with self.subTest(item=item):
                    self.assertTrue(
                        scan["model_file_change_attempt_detected"]
                        or scan["model_direct_write_attempt_detected"]
                    )


class TransactionalMaterializationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temporary.name) / "workspace"
        self.workspace.mkdir()
        self.metadata = self.workspace / ".mtr-dogfood-r4"
        self.metadata.mkdir()
        self.policy = load_lane_policy(POLICY_PATH)
        self.schema = load_json(SCHEMA_PATH)
        self.lane = lane_contract(self.policy, "mtr-docs-private-executor-r1")
        self.proposal = validate_proposed_result(
            raw_result(result_value(self.lane)), lane=self.lane, schema=self.schema
        )
        self.helper = self.metadata / "bounded-writer.py"
        shutil.copyfile(ROOT / "src" / "mtr_dogfood" / "bounded_writer.py", self.helper)
        self.policy_path = self.metadata / POLICY_FILENAME
        self.policy_path.write_text(json.dumps({
            "schema_version": "2.0.0",
            "workspace": str(self.workspace.resolve()),
            "target_aliases": alias_map(self.lane),
            "max_content_bytes": 16384,
        }), encoding="utf-8")
        self.helper_sha = hashlib.sha256(self.helper.read_bytes()).hexdigest()
        self.policy_sha = hashlib.sha256(self.policy_path.read_bytes()).hexdigest()
        self.receipt_schema_sha = hashlib.sha256(RECEIPT_SCHEMA_PATH.read_bytes()).hexdigest()

    def tearDown(self):
        self.temporary.cleanup()

    def materialize(self, **kwargs):
        return materialize_transaction(
            workspace=self.workspace,
            metadata=self.metadata,
            proposal=self.proposal,
            lane=self.lane,
            helper_sha256=self.helper_sha,
            policy_sha256=self.policy_sha,
            receipt_schema_path=RECEIPT_SCHEMA_PATH,
            receipt_schema_sha256=self.receipt_schema_sha,
            **kwargs,
        )

    def test_parent_controlled_in_process_transaction_success(self):
        calls = []

        def trusted(**kwargs):
            calls.append(sorted(kwargs))
            return write_bounded_file(**kwargs)

        receipt = self.materialize(writer=trusted)
        validate_transaction_receipt(receipt)
        self.assertEqual(receipt["final_status"], "committed")
        self.assertEqual(receipt["expected_aliases"], receipt["staged_aliases"])
        self.assertEqual(receipt["expected_aliases"], receipt["committed_aliases"])
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(call == ["content_base64", "script_path", "slot"] for call in calls))
        for item in self.proposal.files:
            self.assertEqual(
                (self.workspace / item.relative_path).read_bytes(), item.content
            )

    def test_second_file_failure_rolls_back_every_file_and_receipts(self):
        first_path = self.workspace / self.proposal.files[0].relative_path
        first_path.parent.mkdir(parents=True)
        first_path.write_bytes(b"preexisting\n")
        calls = 0

        def fail_second(**kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise BoundedWriteError("injected second-file failure")
            return write_bounded_file(**kwargs)

        with self.assertRaises(HostMaterializationError) as captured:
            self.materialize(writer=fail_second)
        self.assertEqual(captured.exception.classification, "HOST_MATERIALIZATION_ROLLED_BACK")
        self.assertEqual(first_path.read_bytes(), b"preexisting\n")
        self.assertFalse((self.workspace / self.proposal.files[1].relative_path).exists())
        self.assertFalse((self.metadata / "writer-receipts").exists())
        receipt = captured.exception.transaction_receipt
        self.assertEqual(receipt["rollback_status"], "completed")
        self.assertEqual(receipt["final_status"], "rolled_back")

    def test_first_write_receipt_failure_also_rolls_back(self):
        def write_then_fail(**kwargs):
            write_bounded_file(**kwargs)
            raise BoundedWriteError("receipt handoff failed")

        with self.assertRaises(HostMaterializationError) as captured:
            self.materialize(writer=write_then_fail)
        self.assertEqual(captured.exception.classification, "HOST_MATERIALIZATION_ROLLED_BACK")
        self.assertTrue(all(
            not (self.workspace / item.relative_path).exists()
            for item in self.proposal.files
        ))

    def test_helper_policy_receipt_schema_and_protected_target_gates_precede_writes(self):
        cases = [
            {"helper_sha256": "0" * 64},
            {"policy_sha256": "0" * 64},
            {"receipt_schema_sha256": "0" * 64},
            {"protected_roots": (self.workspace,)},
        ]
        for changes in cases:
            with self.subTest(changes=changes):
                arguments = {
                    "workspace": self.workspace,
                    "metadata": self.metadata,
                    "proposal": self.proposal,
                    "lane": self.lane,
                    "helper_sha256": self.helper_sha,
                    "policy_sha256": self.policy_sha,
                    "receipt_schema_path": RECEIPT_SCHEMA_PATH,
                    "receipt_schema_sha256": self.receipt_schema_sha,
                }
                arguments.update(changes)
                with self.assertRaises(HostMaterializationError):
                    materialize_transaction(**arguments)
                self.assertTrue(all(
                    not (self.workspace / item.relative_path).exists()
                    for item in self.proposal.files
                ))

    def test_missing_receipt_and_actual_digest_mismatch_roll_back(self):
        def no_receipt(**kwargs):
            alias = kwargs["slot"]
            target = self.workspace / alias_map(self.lane)[alias]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(base64.b64decode(kwargs["content_base64"]))
            return {"invocation_id": "0" * 32}

        with self.assertRaises(HostMaterializationError) as captured:
            self.materialize(writer=no_receipt)
        self.assertEqual(captured.exception.classification, "HOST_MATERIALIZATION_ROLLED_BACK")
        self.assertTrue(all(
            not (self.workspace / item.relative_path).exists()
            for item in self.proposal.files
        ))

        def tamper(**kwargs):
            receipt = write_bounded_file(**kwargs)
            target = self.workspace / receipt["relative_path"]
            target.write_bytes(b"tampered\n")
            return receipt

        with self.assertRaises(HostMaterializationError) as captured:
            self.materialize(writer=tamper)
        self.assertEqual(captured.exception.classification, "HOST_MATERIALIZATION_ROLLED_BACK")
        self.assertTrue(all(
            not (self.workspace / item.relative_path).exists()
            for item in self.proposal.files
        ))


if __name__ == "__main__":
    unittest.main()
