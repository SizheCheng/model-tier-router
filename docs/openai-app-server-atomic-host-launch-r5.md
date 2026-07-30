# R5: atomic OpenAI Codex App Server model launch seam

## Status

Source-only reference candidate. No production signer, verifier, nonce store,
budget store, App Server transport, or model launcher is included.

R5 closes the remaining time-of-check/time-of-use gap between the R4
`compiled_not_sent` request and the host's actual `turn/start` send. It does
not allow the Router, a hook, a plugin, or a local JSON document to authorize
execution.

## Why R4 was not yet the final host shape

R4 proved that a verified capability could replace only `model` and `effort`
while preserving every other `TurnStartParams` field. It then consumed the
one-use nonce and returned an unsent request.

That leaves two production risks:

1. the request can be changed after nonce consumption but before transport;
2. the capability is not directly bound to the host instance, App Server
   connection, consent grant, and reserved experiment budget that perform the
   launch.

R5 makes verification, keyed request-binding validation, nonce consumption,
budget consumption, and the exact App Server send one host-owned atomic
operation.

## Official protocol binding

The current official manual requires `initialize` followed by `initialized`,
documents `model/list`, and permits `model` and `effort` overrides on
`turn/start`. It also states that `clientInfo.name` identifies an integration
in the OpenAI Compliance Logs Platform and that enterprise integrations should
contact OpenAI to join the known-clients list.

References:

- <https://learn.chatgpt.com/docs/app-server>
- <https://learn.chatgpt.com/docs/models>
- <https://learn.chatgpt.com/docs/hooks>

The local contract was checked against schemas generated offline by
`codex-cli 0.144.5`. R7 later proved that raw JSON serialization order is not
stable. The authoritative consolidated semantic binding is the strict
canonical JSON SHA-256
`66ab7534f29e1ee7c065eb15c799d5f6e93fdd1d0ba86c262c3842a6a8f3d0c8`.
The following values are retained as historical raw-file observations:

- consolidated App Server v2 bundle:
  `e46416109fae90974f571117d40d8480328bffdec7c6e3a8672d34067f57fdac`;
- `TurnStartParams.json`:
  `5957acbf8d5c53a9a1aa42d99883a43af8d00a780c7ee8632974a343361edd2a`;
- `TurnStartResponse.json`:
  `7cfae42a4652fe38119d6a0a625910357c869c448c985513a4cd5966031e18bc`;
- `TurnStartedNotification.json`:
  `8fa9297e89172a4430b8a023dc6fe6f4b5764578fb64df0d41886be25e64e669`.

Integrations must regenerate and bind schemas for the Codex version they
actually ship.

## Reference flow

### 1. Build a non-authorizing launch intent

`build_atomic_launch_intent` compiles the R3-selected model and effort into an
otherwise unchanged `turn/start` request. The durable intent contains only:

- the R3 proposal, plan, assignment, audience, and selection bindings;
- the request ID and SHA-256 of the opaque thread ID;
- host-provided opaque bindings for the exact request, invocation context,
  host instance, App Server connection, consent grant, and budget lease;
- immutable authority and privacy boundaries.

The intent status is `host_capability_required`. It cannot launch anything.

`host_request_binding_sha256` must be a host-keyed MAC or an equivalent
unguessable host binding. A plain hash of the request is not sufficient because
the request contains prompt and path material whose equality or low-entropy
content should not be exposed through durable telemetry.

### 2. Issue a host capability bound to the intent

The host-owned R2 capability claims bind `launch_intent_sha256`, the keyed
request binding, host instance, connection, consent grant, budget lease,
audience, expiry, nonce, exact method, and one-start ceiling.

The capability also asserts current catalog, entitlement, assignment,
attestation, context, transport identity, and budget validation. It forbids
approval, sandbox, network, permission, and write-scope expansion.

The local package deliberately has no implementation that can sign these
claims.

### 3. Perform one atomic host launch

`HostAtomicTurnLauncher` is an injected host interface. Its production
implementation must, in one host transaction:

1. authenticate capability issuer, signature, audience, and expiry;
2. compare every capability binding with the supplied launch intent;
3. recompute and verify the keyed binding over the exact request;
4. validate the live host instance and App Server connection;
5. consume the capability nonce and one reserved budget slot;
6. send that exact request once through the host-owned App Server transport;
7. return the initial `TurnStartResponse` and an authenticated host result.

The reference validates an initial `inProgress` turn with no response items,
then emits a redacted `host_started` receipt. Raw prompt, path, capability,
thread ID, turn ID, App Server response, model output, tool output, and error
text are excluded.

If the interface is absent, raises, reports replay, drifts from any binding, or
does not attest every required host validation, no success receipt is created.

### 4. Join launch to outcome

`build_launch_outcome_join` binds the R5 host launch receipt to the R3
privacy-safe outcome using proposal, assignment, turn identity, requested
model, and requested effort. The joined record includes only digests, arm,
requested/resolved model, and aggregate outcome class.

This closes the causal chain:

`assignment -> host capability -> exact atomic launch -> observed outcome`.

Active-model mismatch remains a diagnostic and is not treated as model-quality
evidence.

## Portable host conformance requirements

An OpenAI host implementation passes only if all of these are true:

- mutation after capability issuance is rejected before any send;
- replay cannot consume a second start or produce a second turn;
- booleans cannot satisfy integer start-budget fields;
- failure details are not copied into durable receipts;
- only `model` and `effort` differ from the caller's base turn parameters;
- the initial response is bound to the same request, thread, and assignment;
- the terminal R3 outcome joins to the exact launched turn;
- no local signer, fallback issuer, transport, or implicit network path exists.

The included tests use a synthetic in-memory host implementation and a
test-only keyed binding. They never start App Server or a product model.

## Exact upstream adoption request

OpenAI integration work is now narrow and host-specific:

1. register the production `clientInfo.name`;
2. define the host-keyed request/context binding mechanism;
3. issue R2 atomic capabilities from signed-in account, workspace, consent,
   catalog, entitlement, assignment, attestation, and budget state;
4. implement `HostAtomicTurnLauncher` inside the Codex host transaction that
   owns the App Server connection;
5. persist only the redacted launch receipt and R3 outcome join;
6. expose enrollment, fixed-model control, budget, kill switch, rollback, and
   administrative policy in the product.

The local Router remains advisory. The new interface is the host-owned action
boundary that can make automatic model switching real without turning advisory
output into authority.
