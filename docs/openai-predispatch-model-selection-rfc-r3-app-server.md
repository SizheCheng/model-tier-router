# RFC R3: Codex App Server model experiment contract

## Status

Source-only reference candidate. It does not install a hook, start App Server,
launch a model, alter an active thread, or grant execution authority.

R3 narrows the earlier R2 request around protocol surfaces that are now
documented and emitted by the installed Codex App Server:

- `model/list` exposes the host model catalog and supported reasoning efforts;
- `thread/start` and `turn/start` accept model selection, with `turn/start`
  also accepting effort;
- `turn/completed` supplies the terminal turn status;
- `thread/tokenUsage/updated` supplies per-turn and cumulative token usage;
- `model/rerouted` records a service-side model change;
- `initialize.params.capabilities.requestAttestation` allows a desktop host to
  respond to an opaque attestation request.

Official references:

- <https://learn.chatgpt.com/docs/app-server>
- <https://learn.chatgpt.com/docs/models>
- <https://learn.chatgpt.com/docs/hooks>

## Verified local protocol binding

The reference was checked against `codex-cli 0.144.5` by running the offline
command:

```text
codex app-server generate-json-schema --out <unique C:\tmp directory>
```

The generated v2 schema bundle had raw-file SHA-256
`e46416109fae90974f571117d40d8480328bffdec7c6e3a8672d34067f57fdac`.
R7 later proved that repeated generation can reorder JSON object keys, so this
is a historical serialization observation rather than a stable protocol
identity. The strict canonical JSON digest for that semantic schema is
`66ab7534f29e1ee7c065eb15c799d5f6e93fdd1d0ba86c262c3842a6a8f3d0c8`.
Integrations must independently bind the exact Codex build and canonical schema
for the version they actually run.

No model process or network request was needed to generate the schema.

## Problem clarified by dogfood data

The managed hook produces a recommendation after the active model is already
present in `UserPromptSubmit`. Therefore active-model mismatch measures whether
an advisory happened to match an existing selection; it does not measure
Router lift.

The 2026-07-27 daily window also showed:

- 3,197 assessments but no randomized Router/control assignments joined to
  outcomes;
- only 94 structurally complete turns;
- zero explicit structured success/failure outcomes in 3,265 `PostToolUse`
  records;
- 50 test-shaped `mock-model` records whose origin could not be proven because
  the ledger had no host-attested provenance.

The next useful unit is therefore a host-bound experiment proposal and a
privacy-safe App Server outcome, not another post-selection hook override.

## Reference component

`MTR_CODEX_APP_SERVER_MODEL_EXPERIMENT_R1` implements two pure, offline
operations.

### Build a host-review proposal

The component consumes:

- a hash-bound R2 Router/control assignment;
- a complete App Server `model/list` response;
- the current Codex CLI version and generated protocol-schema SHA-256;
- `clientInfo.name`;
- host-asserted origin metadata and a SHA-256 evidence binding.

It verifies that the assigned model is picker-visible and the assigned effort
is supported. It emits only:

- the exact `thread/start` model override;
- the exact `turn/start` model and effort override;
- assignment, catalog, protocol, and provenance digests;
- immutable authority and privacy boundaries.

The proposal status is always `host_review_required`, and
`execution_authorized` is always `false`. The Codex host must still validate
catalog availability, entitlement, experiment assignment, user/workspace
policy, and any actual launch.

### Summarize an observed outcome

The component accepts only a prefiltered sequence of:

- `model/rerouted`;
- `thread/tokenUsage/updated`;
- `turn/completed`.

It emits:

- requested and resolved model;
- validated reroute chain and reason;
- completed/interrupted/failed outcome class;
- duration and token counts;
- aggregate item type/status counts;
- SHA-256 identities for thread and turn.

It deliberately does not persist prompt text, agent messages, tool output,
error messages, raw thread/turn identifiers, or an opaque attestation token.
Unknown notification methods fail closed so an unfiltered App Server stream
cannot be accidentally serialized as experiment telemetry.

## Attestation boundary

App Server attestation returns an opaque token. R3 does not accept or persist
that token. It accepts only a host-supplied evidence digest and records that
attestation was requested.

An attestation token is not treated as model-selection authorization. OpenAI
host integration must define the issuer, audience, expiry, replay protection,
catalog/entitlement binding, and launch scope of any production capability.

## Permission boundary

Model selection is independent of:

- approval policy;
- sandbox mode or writable roots;
- network access;
- tool permissions;
- repository export consent;
- install, deployment, restart, or remote-write authority.

The proposal contains no approval, sandbox, network, write-scope, prompt, or
tool-output override. A host must apply model selection without changing those
independent settings.

## Causal pilot

The recommended first live experiment is bounded to eligible new turns:

- deterministic 50/50 `ROUTER_AUTO` versus `FIXED_MODEL_CONTROL`;
- the same permission, sandbox, network, and repository constraints in both
  arms;
- stop after 100 complete eligible turns or seven days, whichever comes first;
- predeclared primary outcomes from `turn/completed`, with token usage, duration,
  reroute, interruption, and structured tool-status metrics as secondary
  outcomes;
- fail closed on incomplete catalog pages, unsupported effort, identity drift,
  invalid reroute chains, absent provenance, or privacy-boundary drift.

Active-model mismatch is a launch-compliance diagnostic, not an experiment
success metric.

## Narrow upstream adoption request

The local reference can prove deterministic assignment, catalog validation,
privacy-safe outcome reduction, and non-expansion of authority. Product
adoption still requires the Codex host to own:

1. experiment enrollment and assignment validation;
2. catalog and entitlement freshness;
3. trusted origin and launch identity;
4. application of the model/effort override at `thread/start` or `turn/start`;
5. durable association of App Server outcome events with the assignment;
6. consent, budget, administrative policy, and rollback controls.

That host seam is the upstream request. The Router remains a recommendation
provider and cannot self-issue it.
