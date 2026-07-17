# Compatibility

Version 0.1.0 preserves:

- `assess_mapping(envelope)`
- `route_mapping(envelope, ports=None)`
- `GovernedRouter`
- historical imports from `model_tier_router.router` and
  `model_tier_router.contracts`

These are compatibility or governed surfaces. New integrations should call
`assess(request, *, policy=None, profiles=None)`.

The six documented historical sample envelopes retain their task class, risk
class, tier, reasoning budget, mutation-scope projection, approval obligation,
validation obligation, and fail-closed verifier behavior. Compatibility
assessment output never authorizes execution or writes.

Before 1.0, a breaking alpha-schema change receives a new immutable schema
identifier. Public Python deprecations remain available for at least one minor
release and are recorded in `CHANGELOG.md`.
