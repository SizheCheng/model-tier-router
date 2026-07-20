# External dogfood runner R3

R3 separates preparation from real model execution. This repository is
prepared and tested from Codex with fake launchers only. The real writable
smoke and the two product lanes must be started later from an ordinary
PowerShell process whose ancestor chain contains no Codex CLI, Codex App,
Codex-managed shell, or harness child.

## Required invocation

Close every Codex-owned terminal that could be an ancestor of the new shell.
Open a new ordinary Windows PowerShell window, change to this repository, and
run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\RUN_MODEL_TIER_ROUTER_DOGFOOD_R3_EXTERNAL.ps1 -ContractPath .\contracts\MODEL_TIER_ROUTER_DOGFOOD_R3_EXTERNAL_RUNTIME.json -CloseoutPath .\reports\pilot-r3-closeout.json
```

The script passes its own PowerShell PID to the Python runner. The runner walks
only that process's ancestor chain and retains only PID, parent PID, executable
name, and sanitized executable identity. Unrelated Codex processes elsewhere
on the machine are irrelevant. A nested Codex identity produces the hard stop
`NESTED_CODEX_ANCESTOR_DETECTED` before a fixture or product worktree exists.

The final stdout line is one strict JSON closeout object. Exit codes are:

- `0`: fixture and both real lanes passed.
- `2`: blocked before fixture smoke.
- `3`: writable fixture smoke failed.
- `4`: blocked after smoke and before a product lane completed.
- `5`: partial real-lane completion.
- `6`: runtime-contract or final-invariant violation.

## Safety and accounting

The writable smoke consumes exactly one of the five allowed child-process
starts and cannot retry or escalate. Each product task gets one initial
Router-selected profile and, only for an eligible capability failure, one
fresh-baseline next-profile attempt. Host-policy, schema, authentication,
rate-limit, unavailable-model, command, environment, baseline, concurrency,
confidentiality, and unauthorized-action failures never escalate.

Every child receives only a prompt, output schema, and final-result path inside
its assigned fixture or worktree. The harness and primary repositories are not
additional writable directories. The model-tier-router result may be
fast-forward merged only after the frozen validators and low-risk gate pass.
The qwen-redaction result is committed to a retained local branch for review
and is never merged automatically. The immutable fixed-premium control is read
for comparison only.

Raw JSONL and subprocess logs stay below ignored `runs/raw/r3`. Sanitized
receipts and the three aggregate reports are validated and committed once.
The final closeout is ignored so it can truthfully include that report commit
without creating a second self-referential report commit.
