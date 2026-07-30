# Model Tier Router Dogfood Harness

Private, local-only automation for exercising the advisory
`model-tier-router` against real development tasks in isolated Git worktrees.
The Router recommends a logical capability profile; the current user contract
remains the only execution authority.

The harness never pushes, publishes, deploys, delivers customer artifacts, or
contacts model providers other than the explicitly requested `codex exec`
invocation. Raw JSONL, command output, diffs, and process diagnostics stay under
the ignored `runs/raw/` tree. Sanitized receipts and aggregate reports are safe
to commit locally.

## Commands

```powershell
$env:PYTHONPATH = "src"
python -B -m mtr_dogfood.cli preflight
python -B -m mtr_dogfood.cli run --case-id <case-id> --arm router_auto
python -B -m mtr_dogfood.cli batch
python -B -m mtr_dogfood.cli report
python -B -m mtr_dogfood.cli record-outcome --case-id <case-id> --state accepted
```

The installed console equivalents are `mtr-dogfood preflight`,
`mtr-dogfood run`, `mtr-dogfood batch`, `mtr-dogfood report`, and
`mtr-dogfood record-outcome`.

R2 runs only the two authorized Router lanes. The fixed-premium R1 control is
read-only evidence and cannot be selected by the CLI. Each attempt copies the
final-output schema into .mtr-dogfood-r2 inside a fresh target worktree,
launches Codex with that worktree as its sole writable project directory, and
removes the route metadata before computing the target diff. Payload rejection,
process start, observable model execution, model completion, and validator
completion are recorded separately. An eligible implementation or validator
failure can trigger one fresh-baseline escalation; infrastructure failures
cannot.

User configuration, memories, web search, network access, apps, browser tools,
plugins, computer use, and child subagents are disabled for the non-interactive
child. The child prompt and command contain no harness or primary-repository
source path.

## Safety model

- exact target-repository allowlist and external-repository denylist;
- clean HEAD, lock, operation, and porcelain checks before mutation;
- one fresh worktree per attempt, bound to an immutable baseline;
- strict JSON with duplicate-key rejection;
- frozen validator plans and changed-path boundaries;
- at most one capability escalation for eligible implementation failures;
- transient commit identity and `--ff-only` automatic merges;
- no remote mutation commands;
- concurrency-contaminated wall-time labels while external sessions exist.

Run the harness self-test with:

```powershell
$env:PYTHONPATH = "src"
python -B -m unittest discover -s tests -v
```

## Generic product component

Schema-v2 product contracts can build a one-lane, no-retry packet for any clean Git
repository whose bounded change and trusted repository-owned validators fit the
published authority. Qualification uses a frozen synthetic candidate and starts no
model. Three heterogeneous qualification packets must pass the release evaluator
before any separately authorized real canaries are created; three accepted low-risk
real canaries on one runtime release must then pass the readiness evaluator before
default product-development use.

```powershell
python -B scripts/run_product_release_matrix.py --matrix <matrix.json> --router-repository <router> --release-root <release> --workspace-root <external-workspaces>
python -B scripts/evaluate_product_release.py --packet-root <qualification-packet> ...
python -B scripts/evaluate_product_readiness.py --packet-root <real-canary-packet> ...
```

See `docs/generic-product-execution.md` for the contract, evidence, and promotion
gates. Networked validators, secrets, confidential inputs, binary execution, and
cross-repository atomic writes remain outside this component's current authority.
## Managed Codex App data collection

The component can be installed as Windows managed lifecycle hooks so every future
local Codex App, CLI, and IDE development turn calls the same committed Router and
collector runtime. The installation covers session, prompt, subagent, tool,
permission, compaction, and stop events; records remain local, append-only,
redacted, and SHA-256 bound. It neither launches another model nor sends network
traffic.

```powershell
python -B scripts/build_codex_app_enforcement.py `
  --output-directory <clean-bundle-directory> `
  --dogfood-repository <this-repository> `
  --router-repository <model-tier-router-repository> `
  --install-root C:\ProgramData\OpenAI\Codex\managed-hooks\mtr-dogfood-r1 `
  --data-root $env:USERPROFILE\.codex\mtr-dogfood-data
```

The generated `requirements.toml` pins hooks on through the supported managed
configuration layer without disabling unrelated user hooks. See
`docs/codex-app-enforcement.md` for installation, validation, privacy, export, and
rollback details.

## Authorized model dispatch candidate

R2 adds an explicit, separately versioned dispatcher for real model assignments
on newly launched Codex CLI runs. A non-authorizing Router advisory is combined
with a time-bounded user authorization, exact repository and model allowlists, a
deterministic Router/control assignment, an atomic process-start budget, and
append-only lifecycle receipts.

The dispatcher never treats Router output as authority and cannot expand
permissions, write scope, or child tool-network access. Offline preflight binds
the authorization, assignment, installed Codex executable, output schema, and
generated command without starting a model or consuming the start budget.
A real run additionally requires explicit model-service data-export consent for
the exact repository; model selection and child process authority cannot imply
that consent.

An append-only authorization STOP blocks future starts and is polled while the
child is running. STOP is irreversible for that authorization ID. The candidate
is not installed or deployed by this repository change.

See `docs/authorized-model-dispatch-r2.md` for the interface,
`docs/authorized-dispatch-threat-model-r2.md` for the security and retention
contract, `docs/authorized-dispatch-real-pilot-r2.md` for the real experiment
protocol, and `docs/openai-predispatch-model-selection-rfc-r2.md` for the
proposed first-class Codex product seam.

## Portable App Server host conformance

R6 exercises the R5 atomic host-launch seam through an injected synthetic host
test transport. It starts no product model and persists only a strict,
redacted, SHA-256-bound conformance report. Independent verification requires
the caller-owned expected implementation, client, and protocol subject; a
self-rehashed subject cannot substitute for that binding. The eight required
cases cover
post-capability request mutation, replay, integer start budgets, failure
redaction, selection-only request changes, initial-response identity, terminal
outcome joining, and the host-only action boundary.

See `docs/openai-app-server-host-conformance-r6.md` for the driver contract,
negative cases, report schema, and the remaining production adoption gates.

## Deterministic App Server upstream verification

R7 fixes a reproducible schema-binding defect: repeated generation by the same
Codex build can serialize JSON object keys in different orders and therefore
produce different raw-file SHA-256 values for the same protocol. R7 binds the
strict canonical JSON instead; the preserved semantic schema digest is
`66ab7534f29e1ee7c065eb15c799d5f6e93fdd1d0ba86c262c3842a6a8f3d0c8`.
It requires independently measured Codex version and native-build identity and
verifies an R6 report against a caller-owned subject without starting App
Server or a product model.

See `docs/openai-app-server-upstream-verifier-r7.md` for the empirical drift,
canonicalization contract, CLI, schemas, and remaining OpenAI-owned host gate.

## Fail-closed experimental schema binding

R8 fixes a claim-binding defect in R7: the verifier previously recorded the
caller's `experimental_api_included` boolean without proving that the generated
schema used the same generator mode. It now requires the official stable
experimental-gating mock field, request, and response markers to be either all
present or all absent and rejects both crossed declarations and partial marker
sets. The correct default binding remains compatible.

See `docs/openai-app-server-experimental-schema-binding-r8.md` for the live
0.144.5 comparison, stable marker contract, attestation boundary, regression
results, and unchanged OpenAI-owned host gate.
