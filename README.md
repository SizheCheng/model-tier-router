# Model Tier Router

Model Tier Router is a deterministic, offline policy engine that recommends a
logical LLM capability profile. It evaluates hard constraints before stable
soft-preference ranking and returns a machine-verifiable decision trace.

Canonical repository: https://github.com/SizheCheng/model-tier-router

The package does not call model providers, hold credentials, execute the
recommendation, authorize writes, switch an active model, or automatically
escalate.

## What it is

The primary API selects among logical profiles such as `economy`,
`balanced`, and `premium`. A profile describes reasoning, context,
modalities, tool use, structured output, latency class, cost class, privacy,
and deployment boundaries.

Every advisory decision fixes:

- `execution_authorized` to `false`
- `authorized_write_scope` to `[]`

## Why logical capability profiles instead of model names

Provider catalogs, prices, and benchmarks change. Logical profiles let a
caller map a stable requirement to its own deployment catalog without putting
provider names or unstable commercial data into policy. Profile IDs do not
imply current provider pricing or benchmark superiority.

## Non-goals

This project is not a provider gateway, hosted service, model executor,
credential manager, telemetry system, billing layer, account system, web UI,
or automatic model switcher.

## Installation

Python 3.11 syntax is required. The offline validation recorded for this
release candidate uses the local Python version reported in the release
closeout.

```powershell
python -B -m pip install --no-deps .
```

The runtime dependency list is empty.

## Thirty-second quick start

```python
from model_tier_router import assess

decision = assess({
    "schema_version": "model_tier_router_advisory_request_v1alpha1",
    "request_id": "quick-start",
    "requirements": {
        "modalities": ["text"],
        "tool_support": True,
        "maximum_cost_class": "medium",
    },
    "preferences": ["higher_reasoning"],
    "evidence": {"modalities": True, "tool_support": True},
})

print(decision["selected_profile"])
print(decision["execution_authorized"])  # always False
```

## Python API

```python
model_tier_router.assess(request, *, policy=None, profiles=None)
```

`policy` and `profiles` may be caller-supplied strict JSON-compatible
objects. They are validated as closed data contracts. Policy imports,
templates, expressions, environment expansion, and arbitrary code execution
are unsupported.

The package also preserves three v0.1 compatibility surfaces:

- `model_tier_router.assess_mapping(envelope)`
- `model_tier_router.route_mapping(envelope, ports=None)`
- `model_tier_router.GovernedRouter`

See [Compatibility](docs/compatibility.md).

## JSON CLI

Read one strict JSON request from stdin:

```powershell
Get-Content -Raw -Encoding UTF8 examples/requests/text-tools.json |
  model-tier-router assess
```

Or name a local file:

```powershell
model-tier-router assess --input examples/requests/text-tools.json
```

The CLI writes exactly one canonical JSON object to stdout. Diagnostics go to
stderr. Exit codes are:

- `0`: recommended, needs_input, or policy_blocked
- `2`: invalid JSON or request
- `3`: invalid policy or profile catalog
- `4`: unexpected integration failure

Strict input rejects duplicate keys, non-finite numbers, malformed UTF-8,
documents over 1 MiB, and nesting deeper than 64 levels.

## Decision contract

The v1alpha1 decision records:

- `recommended`, `needs_input`, `policy_blocked`, `invalid_request`, or
  `integration_failure`
- selected, initial, and maximum logical profiles
- hard-constraint results and rejected alternatives
- deterministic ranking order
- required, observed, and missing evidence
- bounded escalation condition codes and maximum attempts
- policy, request, catalog, and decision digests

Schemas are in [schemas](schemas/). Objects are closed: unknown fields are
rejected.

## Determinism and digests

Profiles are normalized and sorted by `profile_id`. Hard constraints filter
candidates first. Soft preferences produce an ordered integer tuple, followed
by a lexical `profile_id` tie-break. Dictionary, input-catalog, and filesystem
enumeration order do not affect the decision.

SHA-256 digests are computed over canonical JSON bytes for the normalized
request, validated policy, normalized profile catalog, and final decision
content. Explanations use stable rule IDs and traces; no model generates them.

## Advisory versus governed mode

`assess` is the public advisory core. Governed mode is an optional
compatibility layer under `model_tier_router.governed`. It verifies approval,
validation, route binding, and one-shot receipt evidence and fails closed when
required verifier ports are missing or reject. It does not dispatch providers.

See [Governed mode](docs/governed-mode.md).

## Codex integration

An explicit-only integration is available at
`integrations/codex/model-tier-route/`. It invokes the supported CLI and
returns one advisory decision. It never invokes itself implicitly or promotes
an assessment into execution authority.

### Managed development-data collection

An optional managed lifecycle collector is documented in
[`docs/codex-development-data.md`](docs/codex-development-data.md). It records
bounded, locally redacted route, tool, approval, compaction, subagent, and
outcome receipts for supported Codex hooks. The deterministic builder prepares
but does not install system configuration, start a model, contact a network, or
change Router's non-authorizing contract.

## Security and privacy

The core imports no provider, network, credential, subprocess, or file-writing
module. It performs no telemetry. Requests may contain sensitive workload
descriptions, so callers should minimize data and control local file access.
Security vulnerabilities must be submitted through GitHub Private Vulnerability
Reporting as described in [SECURITY.md](SECURITY.md).

## Compatibility

The package follows Semantic Versioning before 1.0: minor releases may evolve
alpha schemas, while patch releases preserve them. Deprecations are documented
and retained for at least one minor release. Schema identifiers are immutable;
new contracts receive new identifiers.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Tests use the Python standard library:

```powershell
$env:PYTHONPATH = "src"
python -B -m unittest discover -s tests -v
```

## License

Copyright 2026 Sizhe Cheng. Licensed under Apache License 2.0. See
[LICENSE](LICENSE). [PROVENANCE.md](PROVENANCE.md) describes the release
boundary without asserting legal certainty about excluded historical material.
