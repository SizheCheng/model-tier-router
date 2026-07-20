from __future__ import annotations

import json
import re
import sys


EXPECTED_LENGTH = 20
EXPECTED_LITERALS = {
    0: "--ask-for-approval",
    1: "never",
    2: "exec",
    3: "-C",
    5: "--ephemeral",
    6: "--model",
    8: "-c",
    10: "-c",
    11: "memories.generate_memories=false",
    12: "--sandbox",
    13: "workspace-write",
    14: "--json",
    15: "--output-schema",
    17: "--output-last-message",
    19: "-",
}


def reject(message: str) -> int:
    sys.stderr.buffer.write(f"error: {message}\n".encode("utf-8"))
    return 2


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "exec" and "--ask-for-approval" in arguments[1:]:
        return reject("unexpected argument '--ask-for-approval' found")
    if len(arguments) != EXPECTED_LENGTH:
        return reject("external command argument count mismatch")
    for index, expected in EXPECTED_LITERALS.items():
        if arguments[index] != expected:
            token = arguments[index]
            if token.startswith("--") and token != expected:
                return reject(f"unexpected argument '{token}' found")
            return reject(f"argument {index} must be '{expected}'")
    if not arguments[4] or not arguments[7] or not arguments[16] or not arguments[18]:
        return reject("required argument value is missing")
    if not re.fullmatch(
        r'model_reasoning_effort="(?:low|medium|high)"', arguments[9]
    ):
        return reject("unsupported reasoning effort")
    payload = {
        "accepted": True,
        "api_or_model_request_count": 0,
        "argv": arguments,
        "attempts_consumed": 0,
        "model_execution_count": 0,
        "prompt_bytes_read": 0,
    }
    encoded = (
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    sys.stdout.buffer.write(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
