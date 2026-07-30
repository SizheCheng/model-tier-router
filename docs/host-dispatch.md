# Host-controlled Codex dispatch

`model_tier_router.host_dispatch` is an optional integration SDK for a trusted
Codex App Server host. It converts a non-authorizing Router recommendation into
one model-selection proposal, one redacted launch intent, and—only after a
trusted host has completed an atomic launch—one redacted receipt.

It is not a provider gateway or a Codex host implementation. This repository
does not issue capabilities, inspect credentials, discover account
entitlements, or send App Server requests by itself.

## Public protocol boundary

The integration uses two public Codex App Server surfaces:

- `model/list` supplies the host's current model catalog and supported reasoning
  efforts. The proposal binds the exact catalog snapshot and selected entry by
  SHA-256.
- `turn/start` accepts per-turn `model` and `effort` overrides. The SDK changes
  only those two fields and binds the complete standard request before launch.

A host capability is deliberately out of band. It is not inserted into the
`turn/start` payload and is not represented as an undocumented App Server wire
field. The trusted host driver receives the opaque capability separately.

Official protocol references:

- [Codex App Server](https://learn.chatgpt.com/docs/app-server)
- [Codex models](https://learn.chatgpt.com/docs/models)

## Trust sequence

1. The caller obtains an advisory decision. It must still contain
   `execution_authorized=false` and `authorized_write_scope=[]`.
2. `build_dispatch_proposal` binds the decision, a caller-owned logical-profile
   map, a `model/list` snapshot, the selected catalog entry, the source origin,
   and the protocol schema.
3. `build_atomic_launch_intent` produces a standard `turn/start` request and a
   durable intent containing hashes instead of the prompt, raw request, thread
   ID, or capability.
4. `launch_atomic_turn_start` validates every local input and delegates exactly
   one transaction to a caller-supplied `HostAtomicTurnLauncher`.
5. The host authenticates and consumes the capability, sends the exact bound
   request, and returns a launch response plus a complete attestation.
6. The SDK verifies the response and attestation before returning a redacted,
   SHA-256-bound receipt.

The first three steps do not authorize or start a model. The `now` argument is a
trusted, timezone-aware prelaunch timestamp; the attested launch must occur
within 60 seconds of it and before capability expiry.

## HostAtomicTurnLauncher obligations

A conforming host implementation must perform these actions as one atomic
transaction:

- authenticate issuer, audience, expiry, transport identity, and the capability
  envelope;
- bind the capability to the proposal, intent, exact request, host instance,
  connection, request context, user consent grant, and budget lease;
- revalidate current catalog membership, supported effort, account entitlement,
  user consent, and the existing permission boundary;
- reject reused nonces and any start budget other than exactly one;
- consume the nonce and one-start budget before sending the request;
- send the exact standard `turn/start` request once, without adding permissions
  or changing non-selection fields;
- return hashes and boolean attestations, never raw credentials or capability
  material.

The host must fail closed. A false, missing, duplicated, expired, malformed, or
unbound field produces no successful receipt. Because dispatch itself is a host
side effect, production hosts must make consume-and-send atomic; a local Python
exception cannot undo a request already sent by a broken host driver.

## Privacy boundary

Proposal, intent, and receipt schemas are closed. Durable objects exclude:

- prompt and input content;
- raw `turn/start` request and raw thread ID;
- raw capability bytes, tokens, and credentials;
- raw returned turn ID.

The caller may persist the versioned documents in
`schemas/host-dispatch-*.schema.json`. The raw request and capability should
remain inside the trusted host transaction and follow the host's own retention
policy.

## Minimal integration shape

```python
from datetime import datetime, timezone

from model_tier_router import (
    build_atomic_launch_intent,
    build_dispatch_proposal,
    launch_atomic_turn_start,
)

proposal = build_dispatch_proposal(
    advisory_decision,
    profile_to_model_map,
    model_list_result,
    origin_sha256=origin_sha256,
    protocol_schema_sha256=protocol_schema_sha256,
)
request, intent = build_atomic_launch_intent(
    proposal,
    existing_turn_start_params,
    host_binding_hashes,
    request_id=request_id,
)
response, receipt = launch_atomic_turn_start(
    proposal,
    intent,
    request,
    opaque_capability_bytes,
    trusted_host_launcher,
    now=datetime.now(timezone.utc),
)
```

`trusted_host_launcher` is intentionally not supplied by this package. An
official Codex integration would implement it inside the authenticated host,
where catalog, entitlement, consent, nonce, budget, transport, and launch
identity can be verified together.
