# Generic product execution component

`MTR_GENERIC_SINGLE_PRODUCT_EXECUTION` is the reusable fail-closed runtime for one
bounded product lane. Product identity, repository binding, branch prefix, frozen
task, Router decision, write policy, qualification candidate, validator authority,
and historical accounting are packet data. The runtime contains no product dispatch
table.

## Safety contract

- One packet contains exactly one lane, permits at most one real start, disables
  retry, and stops on its first real failure.
- Every supported product packet comes from an explicit schema-v2 product contract.
  There is no implicit historical packet or ignored `runs/raw` dependency.
- Qualification performs the complete host path in a disposable clone: strict
  candidate validation, transactional materialization, receipt and exact-diff
  checks, confidentiality and substantive-content gates, every frozen validator,
  and the disposable commit gate. Success is
  `POST_MATERIALIZATION_VALIDATED`.
- Qualification starts no Codex/model process and sends no model request. Validator
  commands are real subprocesses and are counted separately; zero model starts does
  not mean zero validator processes.
- A real invocation repeats the same frozen-candidate qualification in a fresh clone.
  After it passes, the runtime rechecks the packet checksum, exact manifest, Router
  repository, product repository, HEADs, branches, and clean states both before and
  immediately at atomic start reservation.
- A pre-reservation failure consumes zero starts and creates no
  `results/campaign-state.json`. Once real reservation succeeds, that packet remains
  consumed even if launch, model output, materialization, or validation later fails.
- Real execution requires a runtime built from a clean committed source tree. The
  embedded release metadata and packet both require
  `source_materialization: git_object_database_head`; checkout line-ending filters cannot
  change the bytes used to build the release.
- A packet built with `qualification_release_only: true` permanently rejects real
  execution. A real campaign is a separately built and separately authorized packet.
- The model proposes only target aliases and UTF-8 content. The host owns lane and
  file metadata, validates the closed output schema, and writes only exact aliases.

## Validator trust boundary

Product-contract v2 accepts only structured test runners: Python `pytest` or
`unittest`, package-manager `test`, and compiled-language `test` commands. Shells,
inline code, response files, URLs, traversal, absolute external operands, arbitrary
package scripts, sensitive environment variables, and external absolute environment
paths are rejected before packet creation.

Validators run with a scrubbed environment instead of inheriting host credentials.
The v2 authority explicitly records
`execution_model: trusted_repository_test_process_v1` and
`os_sandbox_enforced: false`. This is deliberately truthful: repository-owned test
code must already be trusted and must not require network, secrets, or external host
paths. Products that require untrusted validator code, network access, confidential
payloads, binary artifact execution, or cross-repository atomic writes need a
separately reviewed sandbox adapter; this packet must not silently broaden authority.

## Onboard a product

Create a contract from
`examples/product-lane-contract.example.json`. It must include:

- schema version `2.0.0` and an explicit route/repository/branch binding;
- a task bound to the clean product repository HEAD;
- a Router advisory request for the same lane ID;
- a closed single-lane write policy with exact aliases and target paths;
- a frozen synthetic `qualification_candidate` that exercises every target alias;
- the exact `validator_authority` object published by the schema;
- explicit historical accounting and `qualification_release_only` mode.

Build without launching a model:

~~~powershell
python -B scripts/build_product_lane_packet.py `
  --output-directory C:\path\to\packet `
  --router-repository C:\path\to\model-tier-router `
  --source-repository C:\path\to\product `
  --product-contract C:\path\to\product-contract.json
~~~

The builder strictly rejects duplicate JSON keys, non-finite numbers, unknown
top-level fields, invalid task/Router/lane bindings, unsafe validator commands, and
invalid candidate aliases or content. It freezes and hash-binds the original
contract, canonical candidate, task, decision, policy, runtime, and wrapper.

Run zero-model qualification:

~~~powershell
python -B C:\path\to\packet\mtr-dogfood-product-lane.pyz `
  --qualification-only `
  --packet-root C:\path\to\packet `
  --router-repository C:\path\to\model-tier-router `
  --source-repository C:\path\to\product `
  --workspace-parent C:\path\to\disposable-workspaces `
  --result-root C:\path\to\packet\results\qualification
~~~

Require all of the following before a real campaign is even considered:

- `status: passed` and `POST_MATERIALIZATION_VALIDATED`;
- campaign started false and starts consumed zero;
- model process starts, observations, completions, and requests all zero;
- every validator result passed and the validator stage changed no extra path;
- original Router and product repositories unchanged;
- no packet campaign latch exists.

The legacy `--source-packet` option is explicit and retained only for historical
regression translation. It has no implicit default, and a packet without the v2
candidate/authority binding cannot qualify or execute as a supported product lane.

## Release qualification

A release candidate is accepted only after:

1. the complete repository suite passes;
2. two independent builds are byte-identical;
3. the same commit passes from a fresh `core.autocrlf=true` worktree containing only
   tracked files;
4. the clean build reports `source_dirty: false` and
   `source_materialization: git_object_database_head` in both outer and embedded metadata;
5. representative product contracts reach `POST_MATERIALIZATION_VALIDATED` with
   zero model activity;
6. negative fixtures prove candidate/manifest/repository drift, validator failure,
   unsafe commands, and duplicate/non-finite JSON fail before reservation.

A frozen candidate proves that the harness, product contract, materialization path,
and validators are compatible. It does not predict model quality and is never used
as the accepted result of a real campaign.

Run a complete three-or-more-product matrix with one command. The matrix preflights
all contracts and clean baselines before creating its release root, processes products
in declaration order, and stops on the first build or qualification failure:

~~~powershell
python -B scripts/run_product_release_matrix.py `
  --matrix C:\path\to\product-release-matrix.json `
  --router-repository C:\path\to\model-tier-router `
  --release-root C:\path\to\zero-model-release
~~~

Paths inside the matrix are resolved relative to the matrix file. Packet names,
route IDs, lane IDs, repository IDs, and repository paths must all be distinct. The
matrix writes a frozen input snapshot and `product-release-closeout.json`; every
success and failure report declares zero model starts and zero model requests.

After at least three heterogeneous qualification packets have completed, evaluate
the release without launching a model:

~~~powershell
python -B scripts/evaluate_product_release.py `
  --packet-root C:\path\to\qualification-1 `
  --packet-root C:\path\to\qualification-2 `
  --packet-root C:\path\to\qualification-3 `
  --output C:\path\to\product-release-qualification.json
~~~

This gate re-verifies each packet and every internal task, decision, policy,
candidate, product-contract, runtime, closeout, exact changed path, and validator
binding. It requires three distinct repositories, three distinct route/lane
identities, at least two media families, one clean runtime source HEAD, and one
artifact SHA-256. Validator accounting is the exact number of completed commands,
not merely a boolean validation-stage marker. Passing this gate authorizes only the
creation of separately approved real-canary packets; it does not authorize a model
start and does not make the component a default executor.

## Default-use promotion gate

Controlled single-product use begins after clean release qualification. Default use
across product development additionally requires three separately authorized,
accepted real canaries on three repositories and at least two media families, all on
the same runtime source HEAD and artifact SHA-256. Each canary must consume exactly
one start, perform no retry, leave source repositories unchanged, and have no scanner,
contract, or accounting ambiguity.

Evaluate completed real packets without starting a model:

~~~powershell
python -B scripts/evaluate_product_readiness.py `
  --packet-root C:\path\to\canary-1 `
  --packet-root C:\path\to\canary-2 `
  --packet-root C:\path\to\canary-3 `
  --output C:\path\to\product-readiness.json
~~~

The evaluator remains fail-closed until every gate is satisfied. Each accepted
canary must be low risk, carry the exact zero-model pre-reservation qualification,
show exactly one reserved and completed model process, bind its packet/runtime
hashes, complete every declared validator command, and retain a terminal one-start
latch. The evaluator never launches a model or mutates a product repository.

## Packet-lifetime consumption

Immediately before the real launcher is called, the runtime atomically creates
`results/campaign-state.json` with `starts_consumed: 1`. Every later invocation of
that packet fails with `PACKET_CAMPAIGN_ALREADY_CONSUMED`; changing the result root
cannot create another start. Removing or rewriting that receipt is not an authorized
retry mechanism.