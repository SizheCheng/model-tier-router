# Architecture

Model Tier Router has three boundaries.

## Pure advisory core

`model_tier_router.core` validates closed request, policy, and capability
profile data. It filters profiles with hard constraints, ranks survivors with
stable preference tuples, and returns a digest-bound trace. The core is
deterministic, side-effect-free, offline, and provider-agnostic.

Policy is data, not code. Imports, templates, expressions, callbacks, and
environment expansion are unsupported. Class orders are explicit, integer
weights are unnecessary in the default policy, and lexical `profile_id` is
the final tie-break.

Missing required evidence produces `needs_input`. No surviving candidate
produces `policy_blocked`. Neither status authorizes execution.

## Governed compatibility

`model_tier_router.governed` preserves approval, validation, canonical route,
and receipt verification for historical callers. Ports verify facts but do not
dispatch a provider. Missing or contradictory evidence fails closed.

## Integrations

The CLI handles strict JSON transport and explicit local files. The Codex
integration is an explicit-only wrapper around that CLI. Integrations may
perform transport I/O; the pure core does not.
