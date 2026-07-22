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
python -B scripts/evaluate_product_release.py --packet-root <qualification-packet> ...
python -B scripts/evaluate_product_readiness.py --packet-root <real-canary-packet> ...
```

See `docs/generic-product-execution.md` for the contract, evidence, and promotion
gates. Networked validators, secrets, confidential inputs, binary execution, and
cross-repository atomic writes remain outside this component's current authority.
