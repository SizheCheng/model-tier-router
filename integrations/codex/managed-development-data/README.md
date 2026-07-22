# Codex managed development-data integration

This directory contains the thin public build entry for the managed Codex lifecycle collector. Runtime implementation lives in `model_tier_router.codex_app`; deterministic packaging lives in `model_tier_router.codex_bundle`.

No installation or system mutation occurs when importing or testing these modules. See [`docs/codex-development-data.md`](../../../docs/codex-development-data.md) for the build, validation, installation boundary, and rollback contract.
