# Authorized model dispatch R2

## Status

MTR_CODEX_AUTHORIZED_MODEL_DISPATCH_R2 is a pilot-ready, local-only source
candidate. It is not installed, deployed, or enabled by the managed R1 Codex
hooks. Offline preflight and an authorization-scoped kill switch are implemented.

The component exists to test one product hypothesis: a Router recommendation can
be converted into a real model assignment for a newly launched Codex CLI run
when, and only when, a separate user authorization explicitly permits model
selection and process launch.

## Codex product boundary

The current Codex product surfaces choose models before execution:

- the ChatGPT desktop Codex composer exposes model and reasoning controls;
- interactive Codex CLI sessions expose /model;
- new CLI and non-interactive runs accept --model or -m.

Lifecycle hooks receive the active model as input, but their documented output
shape has no field that changes the model for the current turn. R2 therefore
does not pretend that a UserPromptSubmit hook can switch an already-running
turn. It dispatches a new codex exec --model ASSIGNED_MODEL process.

Official references:

- <https://learn.chatgpt.com/docs/models>
- <https://learn.chatgpt.com/docs/hooks>
- <https://learn.chatgpt.com/docs/config-file/config-basic>

## Authority separation

Three decisions remain distinct:

1. The Router produces a non-authorizing advisory. Its
   execution_authorized field must remain false and its
   authorized_write_scope must remain empty.
2. A user authorization separately permits model selection, a new local Codex
   process, and export of the authorized repository content to the normal model
   service. It is time bounded, repository allowlisted, model allowlisted, and
   process-count bounded. Broad execution permission is not data-export consent.
3. The child command retains the existing no-approval and workspace sandbox.
   General child tool network is disabled. The normal Codex service transport
   required for a real model invocation is a separate execution dependency;
   network_access_authorized=false does not pretend the model service is local.
   Model selection never grants additional file, tool, deployment, or publication
   authority.

R2 rejects any authorization that enables permission expansion, contains a
write scope, enables child tool network, omits explicit model-service data-export
consent, is expired, adds unknown fields, names a relative repository path, or
selects a model outside the allowlist.

The authorization schema is
schemas/authorized-model-dispatch-r2-authorization.schema.json.

## Causal assignment

Each authorization defines an experiment ID and a Router share in basis points.
The dispatcher hashes the experiment ID, a NUL separator, and the assignment
unit.

The first eight digest bytes map to a stable bucket from 0 through 9,999.
Buckets below router_share_basis_points use ROUTER_AUTO; the rest use
FIXED_MODEL_CONTROL.

The default recommended pilot is 8,000 basis points Router and 2,000 basis
points fixed-model control. The control arm is necessary: mismatch counts and
observational outcomes alone cannot establish that routing caused an
improvement.

The raw assignment unit is never written to receipts. Only its SHA-256 is
retained.

## Fail-closed lifecycle

The execution order is:

1. strictly validate the authorization and reject an existing STOP receipt;
2. run hash-bound offline preflight without starting a model;
3. reserve one append-only model-start budget slot using exclusive create;
4. strictly validate and digest the Router advisory;
5. compute and SHA-256 bind the assignment plan;
6. build a command with exactly one --model argument;
7. recheck authorization and STOP, then write planned.json;
8. start the child and write started.json from the process-start callback;
9. poll STOP during execution and kill the child if it becomes active;
10. write a sanitized completed.json receipt.

A budget slot is consumed before process launch. This is conservative by
design: prelaunch failures cannot be retried outside the explicit maximum.

Receipts never contain the prompt, command line, stdout, or stderr. Raw child
events remain in the existing ignored raw directory. The command transports the
prompt on stdin.

## CLI

Install the project in the normal development environment or set
PYTHONPATH=src. Planning starts no model:

    mtr-dogfood-authorized-dispatch \
      --authorization /path/authorization.json \
      --router-decision /path/router-decision.json \
      --model-map /path/model-map.json \
      --repository /path/authorized-worktree \
      --assignment-unit opaque-task-id \
      plan --model-start-ordinal 1

Preflight starts no model and consumes no budget slot:

    mtr-dogfood-authorized-dispatch \
      --authorization /path/authorization.json \
      --router-decision /path/router-decision.json \
      --model-map /path/model-map.json \
      --repository /path/authorized-worktree \
      --assignment-unit opaque-task-id \
      preflight \
      --data-root /local/mtr-data \
      --output-schema /path/authorized-worktree/result.schema.json \
      --output-file /path/authorized-worktree/result.json \
      --model-start-ordinal 1

Execution reads the private prompt from stdin:

    mtr-dogfood-authorized-dispatch \
      --authorization /path/authorization.json \
      --router-decision /path/router-decision.json \
      --model-map /path/model-map.json \
      --repository /path/authorized-worktree \
      --assignment-unit opaque-task-id \
      run \
      --data-root /local/mtr-data \
      --raw-directory /local/mtr-raw \
      --output-schema /path/authorized-worktree/result.schema.json \
      --output-file /path/authorized-worktree/result.json

The run command is a real model invocation. It must not be used in unit tests or
without a live authorization.

STOP is independent of a still-active authorization:

    mtr-dogfood-authorized-dispatch-stop \
      --data-root /local/mtr-data \
      --authorization-id AUTHORIZATION_ID \
      --reason operator-request

STOP.json is never removed or overwritten. Resuming requires a new authorization
ID and a new preflight.

## R1 integrity hardening included with R2

This change also closes two evidence-quality gaps in the managed R1 collector:

- redaction markers no longer retrigger the credential-assignment pattern, so
  secret=[REDACTED] is stable and does not become secret=[REDACTED]];
- status and export now validate the published record shape before accepting a
  correctly re-hashed record, including required fields, types, enums, digest
  formats, and unknown-field rejection.

These repairs are source changes only. The installed ProgramData artifact is not
modified by this candidate.

## Test boundary

Unit tests use dependency injection around the child runner. They prove:

- explicit authorization is required and expires;
- Router advice never becomes authority;
- permissions, write scope, and tool network access cannot expand;
- Router and control assignments are deterministic;
- the selected model is the only --model argument;
- prompt text is absent from receipts;
- append-only budget and lifecycle receipts are created;
- preflight hashes the executable, schema, command, and plan without a start;
- an existing STOP blocks before budget consumption;
- a STOP created during execution reaches the runner cancellation callback;
- a local non-model subprocess is killed by the polling implementation.

Tests do not start Codex, contact model providers, or access the network.

## Upstream-readiness gates

Completed in this source candidate:

- threat model and explicit data-retention classes;
- outcome labels, phased pilot sizes, and immediate stopping rules;
- irreversible authorization STOP and active-child cancellation;
- draft RFC for a host-authorized pre-dispatch model-selection API.

Remaining upstream gates:

- macOS and Linux path, polling, and exclusive-create coverage;
- host-supplied model catalog fixtures instead of private model slugs;
- integration against an official fake Codex transport;
- host-authenticated user consent and entitlement enforcement;
- bounded real Router/control pilot with no privacy failures;
- managed uninstall proof that preserves append-only evidence.

The upstream pitch should be the separation of advisory, authorization,
assignment, and execution evidence. It should not depend on private repository
history or host-specific managed installation details.
