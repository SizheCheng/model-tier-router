# Generic product execution component

`MTR_GENERIC_SINGLE_PRODUCT_EXECUTION` is the reusable, fail-closed product lane
runtime. Product identity, repository binding, branch prefix, route identity, frozen
task, frozen Router decision, and historical accounting come from the packet. The
runtime contains no product-lane dispatch table.

## Safety contract

- One packet contains exactly one product lane and permits at most one new start.
- Retry is disabled and the first execution failure is terminal.
- Qualification stops at `START_RESERVATION_REQUESTED`; it starts no child process
  and sends no model request.
- A real execution is rejected unless the runtime was built from a clean committed
  source tree and launched from a verified ordinary PowerShell ancestry.
- A component qualification packet built with `--qualification-release-only`
  permanently rejects real execution. A product campaign must be built separately
  without that flag and with its own explicit authority and historical accounting.
- The source packet, runtime, task, decision, source repositories, result root, and
  bounded write aliases are hash- or path-bound before reservation.
- The model returns proposed UTF-8 content only. The host owns `lane_id`, validates
  the declarative lane policy, materializes exact aliases transactionally, runs the
  frozen validators, and records all post-exec failure causes.

## Onboard a product

1. Add a lane to `config/host-materialization-lanes.json`. Declare only exact target
   aliases, repository-relative paths, byte ceilings, media types, line endings,
   and optional `content_requirements`. Do not add product-specific Python logic.
2. Produce an immutable source packet containing the task and Router decision. Its
   `PACKET_SHA256SUMS.txt` must bind `EXECUTION_MANIFEST.json` and every referenced
   snapshot.
3. Build a candidate without launching a model:

```powershell
python -B scripts/build_product_lane_packet.py `
  --output-directory C:\path\to\candidate `
  --router-repository C:\path\to\model-tier-router `
  --source-repository C:\path\to\product `
  --source-packet C:\path\to\frozen-source-packet `
  --source-lane-id inventory-api-product-r1 `
  --route-id INVENTORY_API_PRODUCT_EXECUTION_R1 `
  --historical-accounting-json '{}' `
  --branch-prefix mtr-product/inventory
```

4. Run the artifact with `--qualification-only` and assert campaign start, process
   start, and model-request counts are all zero.
5. Commit the component changes, rebuild the same packet from `source_dirty=false`,
   compare the deterministic artifact hash, and repeat qualification.
6. Only then run `RUN_PRODUCT_LANE.ps1` from Explorer-launched ordinary PowerShell.
   Real execution requires separate campaign authority.

## Promotion gates

A component release is eligible for controlled use when the complete suite passes,
two independent builds have identical runtime bytes, and at least one exact packet
reaches the fake reservation boundary with zero model activity. It becomes the
default for product development only after the same committed runtime succeeds on
at least three heterogeneous real product lanes without scanner false positives,
contract drift, source mutation, retry, or accounting ambiguity.

Legacy Qwen- and two-lane-named entrypoints remain compatibility adapters. New
campaigns must use `product-lane`, `mtr-dogfood-product-lane.pyz`, and
`RUN_PRODUCT_LANE.ps1`.

## Declarative product contract

New products do not need a predecessor packet or a Python source edit. Copy
`examples/product-lane-contract.example.json`, bind the task to the clean product
repository HEAD, enumerate exact target paths and aliases in the lane policy, and
provide the Router advisory request. Build a qualification-only packet with:

~~~powershell
python -B scripts/build_product_lane_packet.py `
  --output-directory C:\path\to\packet `
  --router-repository C:\path\to\model-tier-router `
  --source-repository C:\path\to\product `
  --product-contract C:\path\to\product-contract.json
~~~

The builder obtains and freezes the live Router decision, freezes a single-lane
host materialization policy inside the packet, verifies that policy aliases match
the task's exact bounded paths, binds all inputs by SHA-256, and builds the
reproducible product artifact. A contract with
`qualification_release_only: true` can never be used for real execution.

The schema is `schemas/product-lane-contract.schema.json`. The legacy
`--source-packet` path remains supported only for historical compatibility.

## Default-use promotion gate

The component is eligible for controlled single-product canaries after a
qualification-only packet reaches `START_RESERVATION_REQUESTED` with zero process
starts and zero model requests. It becomes eligible for default product
development only after three accepted, separately authorized real canaries:

- three distinct product repositories;
- at least two media families;
- the same runtime source HEAD and artifact SHA-256;
- exactly one consumed start per canary, no retry, and stop-on-first-failure;
- clean source repositories unchanged by the campaign.

Evaluate completed packets without starting a model:

~~~powershell
python -B scripts/evaluate_product_readiness.py `
  --packet-root C:\path\to\canary-1 `
  --packet-root C:\path\to\canary-2 `
  --packet-root C:\path\to\canary-3 `
  --output C:\path\to\product-readiness.json
~~~

The evaluator fails closed and reports
`eligible_for_default_product_development: false` until every gate is satisfied.
It never launches a model or mutates a product repository.

## Packet-lifetime start consumption

`maximum_new_starts: 1` applies to the complete lifetime of a packet, not only
to one result directory. Immediately before the real launcher is called, the
runtime atomically creates `results/campaign-state.json` with
`starts_consumed: 1`. The file is never created during qualification.

If the launcher, model, validator, or product result fails after reservation,
the packet remains consumed. Every later invocation of that packet fails with
`PACKET_CAMPAIGN_ALREADY_CONSUMED`; changing the result-directory name cannot
create another start. Removing or rewriting the campaign-state receipt is not
an authorized retry mechanism.
