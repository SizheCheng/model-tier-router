# R6: portable OpenAI Codex App Server host conformance

## Status

Source-only, synthetic conformance candidate. It does not start Codex App
Server, launch a product model, sign a capability, provide a fallback issuer,
open a network path, install a hook, or certify any production host.

R6 turns the portable requirements listed in the R5 atomic-launch document
into an executable host-driver contract and a strict, privacy-safe report. A
report is evidence about the exact implementation and protocol-schema digests
named in that report. It is not execution authority, deployment approval, or
permission to expand sandbox, network, approval, or write scope.

## Current protocol binding

The current official Codex App Server manual documents:

- the required `initialize` request followed by `initialized`;
- `model/list`, including picker-visible models and effort options;
- `turn/start`, which adds input to a thread, returns the initial turn, and
  streams later events;
- per-turn model and effort selection in the App Server request surface.

Reference:

- <https://learn.chatgpt.com/docs/app-server>

The preserved R3-R5 reference cohort recorded raw consolidated App Server v2
SHA-256
`e46416109fae90974f571117d40d8480328bffdec7c6e3a8672d34067f57fdac`.
R7 proved that generated JSON object-key order is not stable. For R7-verified
R6 reports, `protocol_schema_sha256` is the strict canonical JSON digest,
currently
`66ab7534f29e1ee7c065eb15c799d5f6e93fdd1d0ba86c262c3842a6a8f3d0c8`
for the preserved 0.144.5 semantic schema. An adopting host must independently
bind its exact native build and regenerated canonical schema. Passing R6
against a different or self-declared binding is not valid evidence.

## Host-owned conformance driver

`MTR_CODEX_APP_SERVER_HOST_CONFORMANCE_R1` accepts two injected values:

1. a public, hash-bound subject description; and
2. a host-owned `HostConformanceDriver`.

The subject binds the implementation ID, implementation version,
implementation SHA-256, `clientInfo.name`, protocol-schema SHA-256, and the
required `synthetic_no_product_model` mode.

The driver supplies three operations:

- `prepare(case_id)` returns a fresh one-use synthetic capability, its exact
  R5 request and intent, and the host's `HostAtomicTurnLauncher`;
- `snapshot(case_id)` returns only monotonic synthetic transport, turn, and
  product-model-start counters;
- `build_terminal_outcome(...)` returns the privacy-safe R3 outcome for the
  successfully launched synthetic turn.

The suite re-derives every supplied request and intent before calling the host.
Capabilities, requests, responses, prompts, paths, raw thread and turn IDs,
and host error text remain ephemeral.

## Required cases

A host is `conformant` only when all eight cases pass.

### Post-capability mutation rejection

After capability issuance, R6 changes a non-selection request field while
retaining the original intent and keyed request binding. The host must reject
the request before a synthetic transport send or turn start. This detects a
host that merely repeats the old binding in its result without recomputing it
over the exact request.

### Capability replay rejection

R6 performs one valid synthetic start, then reuses the same capability. The
first call must consume exactly one send and one turn. The second call must
produce neither a send nor a turn and must not create a success receipt.

### Integer start-budget enforcement

R6 wraps a valid synthetic host result and changes `starts_consumed` from the
integer `1` to the boolean `true`. Python booleans are integer subclasses, so
the runtime deliberately uses an exact type check. The invalid result must be
rejected and cannot produce a durable launch receipt.

### Durable failure redaction

The driver supplies private test markers for prompt, path, capability, and host
failure detail. R6 scans every durable receipt, outcome, join, and the final
report. Any marker makes this case fail closed. Exception details are reduced
to stable local codes and never copied into the report.

### Selection-only request mutation

R6 re-derives the R5 request from the proposal and caller's base turn
parameters. The selected `model` and `effort` must match the assignment, and
every non-selection parameter must be byte-for-byte equivalent at the JSON
value boundary.

### Initial response identity binding

One valid synthetic launch must increment exactly one send and one turn while
starting zero product models. The redacted receipt must bind the request ID,
thread hash, proposal, assignment, selected model and effort, launch intent,
and returned turn hash.

### Terminal outcome identity join

The R3 terminal outcome must validate against the proposal and join to the
exact R5 launch receipt. Proposal, assignment, requested selection, and hashed
turn identity must all agree.

### Host-only action boundary

The local R6 component contains no signer, fallback capability issuer, App
Server transport, implicit network path, or product-model launcher. Every
driver observation must keep `product_model_start_count` at zero. The suite
cannot authorize execution, product-model starts, permission expansion,
approval changes, sandbox changes, network expansion, or writes.

## Report contract

The output schema is
`schemas/codex-app-server-host-conformance-r1-report.schema.json`.
The runtime additionally enforces exact case order, assertions, summary
arithmetic, status/result consistency, immutable authority and privacy
boundaries, UTC time, strict integer counters, and a canonical SHA-256 over the
whole report.

Each case persists only:

- the stable case ID;
- `passed` or `failed`;
- `PASS` or `FAIL_CLOSED`;
- fixed assertion IDs; and
- a SHA-256 of redacted evidence.

The evidence hash does not make an untrusted host self-attestation sufficient.
Production adoption must bind the driver and observations to the host build and
test transport named by `implementation_sha256`.

Independent consumers must call `validate_host_conformance_report` with the
caller-owned expected subject. Structural self-consistency is not an identity
proof: replacing the implementation or protocol digest and recomputing an
ordinary report SHA-256 must fail the expected-subject binding.

## Local verification

The repository test uses an in-memory synthetic host with a test-only HMAC
request binding. It deliberately includes mutation-blind, replay-blind,
boolean-counter, and product-model-start negative variants.

```powershell
$env:PYTHONPATH = "src"
python -B -m unittest tests.test_app_server_host_conformance -v
```

The test must run with a host-approved writable `%TEMP%`/`%TMP%` outside every
real source repository. Managed Windows hosts must also preserve usable ACL
inheritance for Python-created temporary directories. It opens no network
connection and starts no App Server or product model.

## Production adoption gate

OpenAI host integration remains necessary. Before a production claim, the host
owner must:

1. register and bind the production `clientInfo.name`;
2. bind the exact shipped App Server schemas and host implementation digest;
3. provide a host-authenticated capability issuer and keyed request binding;
4. run the R6 driver against an isolated host test transport that exercises the
   real atomic nonce and budget transaction;
5. independently review the driver, counter provenance, report, and negative
   cases; and
6. separately authorize enrollment, budgets, kill switch, rollback, and any
   live experiment.

Until those gates are satisfied, R6 is a portable adoption test candidate, not
evidence that automatic production model dispatch is available.
