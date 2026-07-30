from __future__ import annotations

import hashlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mtr_dogfood.codex_app_enforcement import (
    CodexAppEnforcementError,
    SECRET_PATTERNS,
    _canonical_json_bytes,
    _redact_text,
    _strict_json,
    classify_development,
    data_status,
    export_data,
    process_hook_event,
)


def _assessment(event: dict[str, object], prompt: str) -> dict[str, object]:
    return {
        "request": {"request_id": "fixture"},
        "decision": {
            "status": "recommended",
            "selected_profile": "balanced",
            "execution_authorized": False,
            "authorized_write_scope": [],
        },
        "recommended_model": "gpt-5.6-terra",
        "active_model": event.get("model"),
        "active_model_matches_recommendation": True,
    }


def _event(name: str, root: Path, **values: object) -> dict[str, object]:
    event: dict[str, object] = {
        "session_id": "session-1",
        "turn_id": "turn-1",
        "cwd": str(root),
        "hook_event_name": name,
        "model": "gpt-5.6-terra",
        "permission_mode": "default",
        "transcript_path": None,
    }
    event.update(values)
    return event


class CodexAppEnforcementTests(unittest.TestCase):
    def test_redaction_is_idempotent_and_markers_do_not_retrigger(self):
        secret = "sk-abcdefghijklmnopqrstuvwxyz123456"
        redacted, changed = _redact_text(
            f"secret={secret} api_key={secret} password={secret}"
        )
        second, changed_again = _redact_text(redacted)
        self.assertTrue(changed)
        self.assertFalse(changed_again)
        self.assertEqual(second, redacted)
        self.assertNotIn(secret, redacted)
        self.assertNotIn("[REDACTED]]", redacted)
        for pattern in SECRET_PATTERNS:
            self.assertIsNone(pattern.search(redacted))

    def test_development_prompt_calls_router_and_redacts_secrets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            secret = "sk-abcdefghijklmnopqrstuvwxyz123456"
            event = _event(
                "UserPromptSubmit",
                root,
                prompt=f"Implement the component with api_key={secret}",
            )
            with mock.patch(
                "mtr_dogfood.codex_app_enforcement._router_assessment",
                side_effect=_assessment,
            ) as assess:
                response, receipt = process_hook_event(event, root / "data")
            self.assertEqual(assess.call_count, 1)
            self.assertTrue(receipt["development"])
            self.assertIn("profile=balanced", json.dumps(response))
            record_path = Path(str(receipt["record_path"]))
            raw = record_path.read_text(encoding="utf-8")
            self.assertNotIn(secret, raw)
            self.assertIn("[REDACTED]", raw)
            self.assertTrue(json.loads(raw)["redacted_or_truncated"])

    def test_full_turn_produces_complete_integrity_checked_dataset(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = root / "data"
            with mock.patch(
                "mtr_dogfood.codex_app_enforcement._router_assessment",
                side_effect=_assessment,
            ):
                process_hook_event(
                    _event("UserPromptSubmit", root, prompt="Fix and test the code."),
                    data,
                )
            process_hook_event(
                _event(
                    "PreToolUse",
                    root,
                    tool_name="Bash",
                    tool_use_id="tool-1",
                    tool_input={"command": "python -m unittest"},
                ),
                data,
            )
            process_hook_event(
                _event(
                    "PostToolUse",
                    root,
                    tool_name="Bash",
                    tool_use_id="tool-1",
                    tool_input={"command": "python -m unittest"},
                    tool_response={"exit_code": 0, "output": "OK"},
                ),
                data,
            )
            response, receipt = process_hook_event(
                _event(
                    "Stop",
                    root,
                    stop_hook_active=False,
                    last_assistant_message="Implemented and verified.",
                ),
                data,
            )
            self.assertEqual(response, {"continue": True})
            stop_record = json.loads(Path(str(receipt["record_path"])).read_text(encoding="utf-8"))
            self.assertTrue(stop_record["coverage"]["sufficient_for_router_dogfood"])
            status = data_status(data)
            self.assertEqual(status["status"], "passed")
            self.assertEqual(status["development_turn_count"], 1)
            self.assertEqual(status["complete_development_turn_count"], 1)
            self.assertEqual(status["event_counts"]["PreToolUse"], 1)
            self.assertEqual(status["event_counts"]["PostToolUse"], 1)
            self.assertEqual(status["network_requests_created"], 0)
            self.assertEqual(status["model_requests_created"], 0)

    def test_tampered_record_fails_status_and_export(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = root / "data"
            with mock.patch(
                "mtr_dogfood.codex_app_enforcement._router_assessment",
                side_effect=_assessment,
            ):
                _response, receipt = process_hook_event(
                    _event("UserPromptSubmit", root, prompt="Build the product."),
                    data,
                )
            path = Path(str(receipt["record_path"]))
            value = json.loads(path.read_text(encoding="utf-8"))
            value["model"] = "tampered"
            path.write_text(json.dumps(value), encoding="utf-8")
            status = data_status(data)
            self.assertEqual(status["status"], "failed")
            self.assertEqual(status["record_count"], 0)
            with self.assertRaisesRegex(
                CodexAppEnforcementError, "EXPORT_RECORD_INTEGRITY_INVALID"
            ):
                export_data(data, root / "export.jsonl")

    def test_schema_invalid_but_rehashed_record_fails_status_and_export(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = root / "data"
            _response, receipt = process_hook_event(
                _event("SessionStart", root, source="startup", turn_id=None),
                data,
            )
            path = Path(str(receipt["record_path"]))
            value = json.loads(path.read_text(encoding="utf-8"))
            value["unexpected_field"] = "schema drift"
            view = dict(value)
            view.pop("record_sha256")
            value["record_sha256"] = hashlib.sha256(
                _canonical_json_bytes(view)
            ).hexdigest()
            path.write_bytes(_canonical_json_bytes(value))
            status = data_status(data)
            self.assertEqual(status["status"], "failed")
            self.assertEqual(status["record_count"], 0)
            with self.assertRaisesRegex(
                CodexAppEnforcementError, "EXPORT_RECORD_INTEGRITY_INVALID"
            ):
                export_data(data, root / "export.jsonl")

    def test_export_is_append_only_and_integrity_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = root / "data"
            process_hook_event(
                _event("SessionStart", root, source="startup", turn_id=None),
                data,
            )
            output = root / "export.jsonl"
            receipt = export_data(data, output)
            self.assertEqual(receipt["record_count"], 1)
            self.assertEqual(len(receipt["sha256"]), 64)
            with self.assertRaisesRegex(
                CodexAppEnforcementError, "EXPORT_TARGET_EXISTS"
            ):
                export_data(data, output)

    def test_strict_json_and_classification_fail_closed(self):
        with self.assertRaisesRegex(
            CodexAppEnforcementError, "HOOK_INPUT_DUPLICATE_KEY"
        ):
            _strict_json(b'{"a":1,"a":2}')
        with self.assertRaisesRegex(
            CodexAppEnforcementError, "HOOK_INPUT_NON_FINITE"
        ):
            _strict_json(b'{"a":NaN}')
        self.assertTrue(classify_development("请修复这个组件", "C:\\outside"))
        self.assertTrue(classify_development("implement tests", "C:\\outside"))
        self.assertFalse(classify_development("translate this sentence", "C:\\outside"))

    def test_large_tool_result_is_compacted_without_losing_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            response = {
                f"field-{index}": "x" * 20_000 for index in range(64)
            }
            _output, receipt = process_hook_event(
                _event(
                    "PostToolUse",
                    root,
                    tool_name="Bash",
                    tool_use_id="tool-large",
                    tool_input={"command": "run a verbose test"},
                    tool_response=response,
                ),
                root / "data",
            )
            value = json.loads(
                Path(str(receipt["record_path"])).read_text(encoding="utf-8")
            )
            self.assertTrue(value["redacted_or_truncated"])
            self.assertTrue(value["details"]["details_compacted"])
            self.assertEqual(value["details"]["tool_name"], "Bash")
            self.assertEqual(value["details"]["tool_use_id"], "tool-large")
            self.assertLess(
                Path(str(receipt["record_path"])).stat().st_size, 512 * 1024
            )


if __name__ == "__main__":
    unittest.main()
