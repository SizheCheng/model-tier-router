# Managed Codex development-data collection

This optional Windows integration records local, redacted Codex lifecycle events and evaluates development prompts with Model Tier Router. It is designed for Codex App, CLI, and IDE clients that support lifecycle hooks. It does not instrument hosted execution or provide an operating-system security boundary.

## Safety contract

- Router output is advisory only. It never grants execution or write authority.
- Hook payloads are bounded and sanitized before disk write.
- Each event is stored as a separate exclusive JSON file with a canonical SHA-256 binding.
- Collection opens no network connection and starts no model.
- Existing user hooks remain enabled because generated requirements do not set `allow_managed_hooks_only`.
- Installation, deployment, and removal are explicit operator actions; the repository does not modify system configuration by itself.

The event schema is [`schemas/codex-app-development-event.schema.json`](../schemas/codex-app-development-event.schema.json).

## Build a deterministic bundle

Run from a clean committed checkout:

```powershell
$installRoot = 'C:\ProgramData\OpenAI\Codex\managed-hooks\model-tier-router-r1'
$dataRoot = Join-Path $env:USERPROFILE '.codex\model-tier-router-data'

python -B -m model_tier_router.codex_bundle `
  --output-directory C:\path\to\empty-output `
  --repository . `
  --install-root $installRoot `
  --data-root $dataRoot
```

The builder reads Python sources from the committed Git object database and emits:

- `model-tier-router-codex-hook.pyz`
- `requirements.toml`
- `codex-app-data-collection-manifest.json`

The manifest binds the source commit, artifact hashes, managed event set, and zero-model/network accounting. The output directory must be empty.

## Validate without installing

```powershell
py -3 C:\path\to\model-tier-router-codex-hook.pyz --self-test
```

The self-test uses a temporary local dataset and does not create a model or network request.

## Status and export

```powershell
py -3 C:\path\to\model-tier-router-codex-hook.pyz `
  --data-root $dataRoot `
  --status

py -3 C:\path\to\model-tier-router-codex-hook.pyz `
  --data-root $dataRoot `
  --export C:\path\to\new-export.jsonl
```

Status revalidates record digests. Export refuses to overwrite an existing file and contains only stored, sanitized records.

## Installation boundary

The builder prepares but does not install managed requirements. Review the generated files and the current Codex hook documentation before copying anything to the system-managed configuration location. Fully restart local Codex clients after an approved configuration change.

Rollback must preserve datasets unless evidence retention is separately revoked. Remove only component-owned configuration and runtime files; do not remove unrelated user hooks.

## Limits

Lifecycle hooks are a guardrail rather than complete endpoint monitoring. Some specialized or hosted paths may not emit pre/post tool events. Combine managed hooks with sandboxing and endpoint governance when a stronger boundary is required.
