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
