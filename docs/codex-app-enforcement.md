# Managed Codex App development-data enforcement

## Outcome

This integration makes the model-tier-router dogfood component a managed lifecycle
dependency for future local Codex development turns. It is intended for the
ChatGPT desktop Codex App, Codex CLI, and the IDE extension on the same Windows
host. It does not apply to hosted Codex cloud execution or ChatGPT web sessions.

The runtime executes locally at these lifecycle points:

- session and subagent start;
- user prompt submission;
- every supported pre-tool, permission-request, and post-tool event;
- pre- and post-compaction;
- subagent and turn stop.

At prompt submission it calls the bundled, committed `model-tier-router` advisory
API. The resulting profile and current Codex model are recorded separately. Router
output is non-authorizing: `execution_authorized` must remain false and
`authorized_write_scope` must remain empty.

## Enforcement layer

The system requirements file is:

```text
C:\ProgramData\OpenAI\Codex\requirements.toml
```

It pins `[features].hooks = true` and defines ten managed hooks. Managed hooks are
trusted by policy and cannot be disabled in the ordinary `/hooks` browser. The
configuration deliberately omits `allow_managed_hooks_only`, so existing user hooks
such as notifications continue to run.

The committed-source builder emits:

```text
mtr-dogfood-codex-hook.pyz
requirements.toml
codex-app-enforcement-manifest.json
```

Both component and Router bytes are read from their clean Git `HEAD` object
databases, not from dirty worktree files. ZIP timestamps, ordering, permissions,
and compression are deterministic. The manifest binds both source HEADs, runtime
SHA-256, requirements SHA-256, event set, and zero model/network accounting.

Codex clients must be fully restarted after installing or changing system managed
requirements. A running process keeps the requirements resolved at startup.

## Local data contract

The default data root is:

```text
C:\Users\<user>\.codex\mtr-dogfood-data
```

Each hook call creates one exclusive JSON file under a safe session/turn path. No
central append operation is shared by concurrent hooks. Every record includes:

- session and turn IDs, timestamp, cwd, model, and permission mode;
- development classification and hook event;
- redacted, bounded event-specific input;
- Router request, decision, recommended model, active model, and alignment for
  development prompts;
- prompt/tool/permission/compaction/subagent/final-response coverage;
- a SHA-256 over the canonical record without its digest field.

Secrets matching private-key, OpenAI-style key, GitHub-token, bearer-token,
credential-assignment, or URL-userinfo patterns are replaced before disk write.
Strings, containers, nesting, input size, and event-record size are bounded. Raw
unredacted hook payloads are never written, and the collector opens no network
connection and starts no model.

The JSON schema is `schemas/codex-app-development-event.schema.json`.

## Status and export

After installation:

```powershell
py -3 C:\ProgramData\OpenAI\Codex\managed-hooks\mtr-dogfood-r1\mtr-dogfood-codex-hook.pyz `
  --data-root $env:USERPROFILE\.codex\mtr-dogfood-data `
  --status
```

Status re-hashes every event and reports sessions, turns, complete development
turns, hook counts, Router profiles, and active/recommended model mismatches.
Any malformed or digest-invalid event makes status fail.

Export is explicit and refuses to overwrite an existing file:

```powershell
py -3 C:\ProgramData\OpenAI\Codex\managed-hooks\mtr-dogfood-r1\mtr-dogfood-codex-hook.pyz `
  --data-root $env:USERPROFILE\.codex\mtr-dogfood-data `
  --export C:\path\to\new-export.jsonl
```

The export contains only already-redacted, integrity-verified records and returns
its record count and SHA-256.

## Fail-closed behavior and limits

A development prompt is blocked if the local record or Router advisory cannot be
created. Supported tool calls are denied when their enforcement hook fails.
Post-tool failures replace the model-visible result with enforcement feedback.
Stop hooks request continuation on the first failure and avoid an infinite loop if
Codex reports that the stop hook is already active.

Codex documents lifecycle hooks as a guardrail rather than a complete OS boundary:
some specialized or hosted tool paths can opt out of pre/post tool coverage. The
global prompt and stop events still collect the turn-level task and outcome. For an
organization-wide security boundary, combine this integration with lower-level
sandbox, endpoint-management, and data-governance controls.

## Rollback

Rollback is intentionally separate from normal operation:

1. close every Codex App, CLI, and IDE process;
2. preserve or export the local data root if required;
3. remove only the component-owned managed hook entries or, when the file contains
   only this component, the component-created system `requirements.toml`;
4. remove only the versioned managed runtime directory;
5. restart Codex and verify the unrelated user notification hooks remain present.

Do not delete the local dataset as part of runtime rollback. Evidence retention is
a separate decision.