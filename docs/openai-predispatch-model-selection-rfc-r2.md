# RFC: host-authorized pre-dispatch model selection for Codex

## Status

Proposal informed by the local MTR_CODEX_AUTHORIZED_MODEL_DISPATCH_R2 reference
implementation. This document requests a product capability; it does not claim
that the capability exists today.

Current documented Codex surfaces select a model before execution through the
App composer, interactive CLI model control, or the CLI model option. Lifecycle
hook output does not provide a supported field that replaces the active model
for the current turn.

Official references:

- <https://learn.chatgpt.com/docs/models>
- <https://learn.chatgpt.com/docs/hooks>
- <https://learn.chatgpt.com/docs/config-file/config-basic>

## Problem

Teams can build local advisory Routers, but there is no documented host-owned
pre-dispatch seam that lets an administrator combine a recommendation with
explicit user policy before a turn is scheduled. Launching a separate Codex CLI
process proves the experiment but fragments the product experience and forces
third-party code to reproduce host policy checks.

Adding a model override to a lifecycle hook would mix advisory and authority.
The safer product abstraction is a host-authorized pre-dispatch decision.

## Proposal

Before scheduling a turn, Codex may ask one or more configured advisory
providers for a model profile recommendation. The Codex host, not the provider,
then decides whether the recommendation is eligible under account entitlement,
workspace policy, user consent, model availability, experiment budget, and
safety policy.

The provider never launches a process and never receives permission authority.

Conceptual input:

- opaque request ID and hashed assignment unit;
- current surface and active/default model;
- host-supplied eligible model/profile catalog;
- coarse task features approved for routing;
- experiment identifier and remaining host-owned budget;
- no prompt text by default.

Conceptual advisory output:

- schema version and provider ID;
- recommended profile or eligible model ID;
- reasoning-effort class;
- confidence or abstain state;
- advisory evidence digest;
- execution_authorized=false;
- authorized_write_scope=[].

Host decision record:

- accepted, rejected, or defaulted;
- final model and reasoning effort;
- user/workspace policy capability ID;
- explicit model-service data-export grant for the authorized repository;
- assignment arm and budget ordinal;
- advisory, catalog, and decision digests;
- no expansion of approvals, tools, sandbox, network, or write scope.

## Required invariants

- Only the Codex host can turn a recommendation into execution.
- Eligible models come from a host catalog, not arbitrary provider strings.
- Model choice is orthogonal to tool, filesystem, network, approval, and
  deployment authority.
- Model-service data export is a separate host-authenticated capability; model
  selection, process launch, or tool-network policy cannot imply it.
- A user- or admin-visible kill switch can revoke future starts and cancel an
  active experimental run.
- Assignment and start budgets are atomic and append-only.
- Prompt and raw model output are excluded from routing telemetry by default.
- Provider failure, timeout, invalid output, or abstention falls back to the
  existing host-selected model.
- Experiment control assignment is host-owned and auditable.
- Hooks continue to observe lifecycle events but do not silently mutate the
  already scheduled model.

## Suggested lifecycle

1. Host computes privacy-approved coarse task features.
2. Host obtains advisory output under a short deadline.
3. Host validates the output against the eligible catalog and active grant.
4. Host performs or verifies experiment assignment.
5. Host writes a decision receipt and consumes one start budget slot.
6. Host schedules the turn with the final model.
7. Existing lifecycle hooks collect redacted aggregate outcomes.
8. Host evaluates STOP continuously and records the terminal result.

## Privacy and telemetry

The minimal routing record contains profiles, model IDs, assignment arm,
timestamps, completion and validator classes, token aggregates, and digests.
Prompt, command, stdout, stderr, diffs, credentials, and large tool output are
not required for routing evaluation.

Workspace administrators should be able to set retention, export aggregate
records, inspect decision reasons, disable the provider, and revoke an
experiment without deleting prior audit receipts.

## Reference implementation evidence

The local R2 candidate demonstrates strict authority separation, deterministic
Router/control assignment, exact model argument construction, atomic start
budget, hash-bound preflight, append-only receipts, no-approval and no-tool-
network child configuration, and an irreversible authorization STOP with
running-process cancellation.

The reference implementation intentionally leaves host identity, entitlement,
catalog freshness, consent UI, and managed deployment to the product. Those
cannot be securely simulated by a local JSON file.

## Rollout proposal

Start behind a developer experiment flag with aggregate-only telemetry and a
small host-enforced start budget. Require a fixed-model control arm and published
stopping rules. Expand only after cross-platform path/race tests, privacy review,
model-catalog integration, and evidence that fallback behavior is reliable.

## Open questions

- Which task features are both useful and privacy-safe?
- Should model selection occur once per task, per turn, or only at task creation?
- How should a workspace administrator constrain cost and model families?
- Which outcomes can be measured without storing source or prompt content?
- How should active-run cancellation interact with tool transactions?
