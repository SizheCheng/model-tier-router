# Authorized dispatch R2 threat model and retention contract

## Status and scope

This document covers MTR_CODEX_AUTHORIZED_MODEL_DISPATCH_R2. It is a
pilot-ready source candidate, not a managed installation. It selects a model
only for a newly launched Codex CLI process.

The security objective is narrow: explicit user authority may permit model
selection and a bounded process start without allowing the Router, the child
model, or a local race to expand repository, approval, tool-network,
publication, installation, or deployment authority.

The Codex service transport needed for a real model invocation is distinct from
tool network access inside the child sandbox. The authorization field
network_access_authorized=false means the child receives no general network
tool capability. It does not claim that the Codex client can reach a model
without its normal service transport.
Sending repository content through that service is a distinct data-export
authority. A real run requires model_service_data_export_authorized=true for the
exact allowlisted repository; generic model-selection or process-launch consent
is insufficient.

## Protected assets

- the explicit authorization and its expiry, repository, model, and start budget;
- private prompt bytes transported on stdin;
- target repository contents and changed-path boundary;
- Router decision and model-map integrity;
- append-only budget, assignment, start, completion, and STOP receipts;
- raw child events and tool output;
- credentials, user memories, app sessions, and repositories outside the allowlist.

## Trust boundaries

The user or host is the sole authority issuer. The Router is untrusted advisory
input. The dispatcher is a policy-enforcement point. Codex CLI is an execution
dependency. The child model and every tool call are untrusted relative to the
host. The local filesystem is concurrently mutable by other processes.

A digest proves byte identity, not who authorized those bytes. For an upstream
product, authorization should be issued and authenticated by the Codex host.
The local JSON authorization is a test seam, not a replacement for product
identity or consent UI.

## Threats and mitigations

| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| Router claims execution authority | Strict Router schema requires execution_authorized=false and empty write scope | A compromised host could bypass this component |
| Authorization is edited after planning | Normalized authorization SHA-256 is bound into the plan and revalidated immediately before command construction | Local SHA-256 is not a user signature |
| Model is replaced in a self-rehashed plan | Plan is checked again against the live authorization model allowlist | Host-controlled authorization remains authoritative |
| Repository path is swapped | Exact normalized repository allowlist and worktree equality checks | Reparse behavior depends on the platform path implementation |
| Extra model flag is injected | Generated command must contain exactly one model option with the assigned value | A replaced Codex executable is outside the Python process boundary |
| Start budget races | Each slot uses exclusive create and is never reclaimed | A crash can conservatively consume a slot |
| Old work resumes after operator stop | Authorization-scoped STOP.json is append-only and irreversible; a new authorization ID is required to resume | A hostile process can ignore the dispatcher entirely |
| STOP occurs during a run | The runner polls the STOP path and kills the child, then records OPERATOR_KILL_SWITCH | Cancellation is cooperative at polling granularity |
| Child requests approval or network tools | approval_policy=never, strict config, web disabled, and sandbox tool network disabled | Codex service transport still exists |
| Private repository is sent without explicit export consent | Authorization must separately assert model-service data export for the exact repository | The host must authenticate that consent |
| Prompt or output leaks into receipts | Receipts allow only aggregate execution fields and never include prompt, command, stdout, or stderr | Raw child events can remain sensitive |
| Raw data is committed or displayed | Raw directories are ignored and excluded from safe receipts and aggregate reports | Operator filesystem backups can retain raw data |
| Model unavailability is mistaken for Router failure | Infrastructure failures are classified separately and are not eligible for routing-quality conclusions | Provider-side details may remain opaque |
| Wall time is treated as causal | Wall time is descriptive when concurrency exists; outcome and token metrics are primary | Unobserved host load can still affect results |

## Data classes and retention

Class A consists of authorization digests, plans, budget slots, STOP receipts,
sanitized lifecycle receipts, aggregate outcomes, token counts, and validator
results. Class A is append-only and may be retained for the experiment audit.

Class B consists of raw Codex JSONL, stdout, stderr, tool details, and local
diagnostics. Class B stays in an ignored, access-controlled pilot root. It must
not be copied into the managed R1 formal ledger, committed, pasted into reports,
or uploaded. This component never automatically deletes or rewrites Class B;
retention or destruction requires a separate operator policy.

Class C consists of prompt bytes. Prompts travel on stdin and are absent from
plans and receipts. Production adoption should avoid durable prompt retention
unless a separate user-visible policy explicitly enables it.

Class D consists of worktree source and generated changes. Real pilots must use
a unique isolated worktree or copy. Main-workspace mutation, staging, commit,
push, installation, deployment, and restart are independent authorities.

## Fail-closed conditions

No new model process may start after any of these conditions is observed:
expired or malformed authorization, active STOP receipt, budget exhaustion,
repository or model drift, multiple model arguments, output path escape,
schema failure, managed-hook or installed-runtime drift, credential exposure,
unexpected tool network, main-workspace drift, or an unclassified integrity
failure.

## Productization requirements

An upstream implementation should replace local authorization JSON with a
host-authenticated capability, expose STOP through product UI, store aggregate
telemetry under documented retention controls, use a catalog of eligible model
IDs supplied by the host, and run cross-platform race and path tests.
