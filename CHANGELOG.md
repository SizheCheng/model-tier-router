# Changelog

All notable changes use Semantic Versioning.

## 0.3.1 - Codex App Server response compatibility

- Accept the current App Server `Turn.itemsView` enum in authenticated
  `turn/start` responses.
- Accept the schema-defined nullable `Turn.startedAt` field while continuing to
  reject invalid view values, negative timestamps, and boolean timestamps.

## 0.3.0 - Host-controlled Codex dispatch contracts

- Added a fail-closed SDK that binds advisory decisions and `model/list`
  evidence to selection-only standard `turn/start` requests.
- Added out-of-band `HostAtomicTurnLauncher` capability, nonce, entitlement,
  consent, budget, transport, and attestation obligations.
- Added closed proposal, intent, and receipt schemas with prompt, raw request,
  capability, credential, and raw turn-ID exclusion.
- Preserved the Router's non-authorizing contract and shipped no provider,
  network, credential, or built-in host implementation.

## 0.2.0 - Managed Codex data integration

- Added an optional local Codex lifecycle collector with bounded redaction,
  per-record integrity binding, status, and explicit export.
- Added deterministic managed-hook bundle generation from a clean committed
  repository without automatic installation or deployment.
- Added public schemas, documentation, and regression tests for the integration.
- Preserved advisory-only routing and zero model/network behavior.

## 0.1.0 - Release candidate

- Added the advisory-first `assess` API.
- Added logical capability profiles and a closed declarative policy.
- Added deterministic filtering, ranking, traces, evidence status, escalation
  bounds, and canonical SHA-256 digests.
- Added a strict JSON CLI and explicit Codex integration.
- Preserved historical advisory and governed API names as compatibility
  surfaces.
- Added Apache-2.0 licensing, public documentation, community files, schemas,
  examples, and CI.
