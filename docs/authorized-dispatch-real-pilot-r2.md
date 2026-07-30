# Authorized dispatch R2 real pilot protocol

## Purpose

This protocol turns the source candidate into real but bounded evidence. It is
more aggressive than observational mismatch counting: the Router arm actually
selects the model for a newly launched Codex run, while a fixed-model arm
provides a causal control.

Engineering smoke results and causal experiment results remain separate.

## Authority packet

Before any real start, freeze these inputs:

- one time-bounded authorization conforming to the authorization schema;
- one exact repository copy or isolated worktree;
- one exact model map from the available Codex model catalog;
- one Router advisory with no execution authority;
- one output schema and validator plan;
- one experiment ID, assignment-unit list, start budget, and stopping policy;
- one unique pilot data root outside the managed R1 formal ledger.
- explicit consent to export this repository content to the model service.

The authorization must state tool-network access false, an empty permission
expansion scope, and model_service_data_export_authorized=true. Normal Codex
service transport is an execution dependency, not child tool-network authority.
Broad permission to select a model or start a process is not sufficient consent
to transmit private repository content.

## Phase 0: offline arming

Run preflight before every new authorization and after any executable, model
map, schema, repository, dispatcher source, or configuration change. Preflight
hashes the dispatcher source, resolved Codex executable, output schema, command,
plan, and STOP location. It records model_process_started=false and
network_request_started=false.

Example:

    mtr-dogfood-authorized-dispatch [common arguments] preflight --data-root C:\tmp\mtr-pilot-UNIQUE --output-schema C:\tmp\worktree\result.schema.json --output-file C:\tmp\worktree\result.json --model-start-ordinal 1

A preflight result is invalid after any bound input changes. Preflight consumes
no process-start slot.

## Phase 1: two-start engineering canary

Use exactly two non-confidential, repository-native tasks in fresh isolated
worktrees. Freeze one Router-arm assignment unit and one control-arm assignment
unit before execution. These two runs test transport, receipts, STOP behavior,
validator compatibility, privacy, and rollback. They are excluded from causal
quality estimates because the arm balance is intentionally selected.

Stop after either start if any fail-closed condition occurs.

## Phase 2: randomized pilot

After both canaries pass, freeze at least 20 eligible real development tasks
before revealing arm assignments. Use the authorization ratio, defaulting to
80 percent Router and 20 percent fixed-model control. Do not replace tasks,
retry failed infrastructure under a new label, or alter assignment units after
bucket calculation.

Twenty tasks are operational evidence, not enough for a broad routing-policy
claim. No default policy change is considered until at least 100 complete,
eligible turns exist with at least 20 complete control turns and no unresolved
privacy or integrity failure.

## Eligible tasks

Tasks must be genuine development work with repository-owned validation,
bounded writable paths, no credentials, no customer confidential data, no
remote mutation, and no deployment or publication authority. Synthetic tasks
may test transport but must be labeled engineering smoke and excluded from
outcome analysis.

## Outcomes

Primary outcomes are repository-owned validator pass, changed-path compliance,
human acceptance, complete model execution, and absence of privacy or authority
violations. Secondary outcomes are input, cached-input, output, and reasoning
tokens plus failure class. Wall time is descriptive only when concurrency may
exist.

Prompt text, command lines, stdout, stderr, and large tool output are never part
of the aggregate report.

## Immediate stopping rules

Activate STOP and preserve evidence immediately on:

- credential or prompt leakage outside the approved raw root;
- SHA-256, schema, append-only, or assignment-integrity failure;
- a model outside the authorization or more than one model argument;
- approval escalation, unexpected child tool network, app, browser, plugin,
  computer-use, memory, or subagent access;
- write outside the isolated worktree or main-workspace drift;
- installed managed-hook drift or loss of R1 collection;
- budget overrun, duplicate start, untracked retry, or lost process ancestry;
- an unexpected real model start during unit or integration tests;
- an active STOP receipt;
- a test or validator failure that cannot be classified without changing the
  frozen packet.

The stop command is deliberately independent of a still-valid authorization:

    mtr-dogfood-authorized-dispatch-stop --data-root C:\tmp\mtr-pilot-UNIQUE --authorization-id AUTHORIZATION_ID --reason operator-request

STOP.json is never removed or overwritten. Resumption requires a new
authorization ID and a new preflight.

## Run boundary

The run command reads the private prompt from stdin and performs a real Codex
model invocation. Unit tests and preflight must never call it. A successful
preflight does not itself authorize installation, ProgramData changes, restart,
commit, push, publication, or deployment.

## Closeout

Closeout reports the analysis window, eligible and complete turns, arm and model
distribution, validator and acceptance outcomes, mismatches, token aggregates,
privacy and integrity status, STOP status, executable and plan digests, and an
explicit terminal class. Raw prompt and model output remain excluded.
