# R7: deterministic App Server binding and upstream verifier

## Status

Source-only, offline adoption candidate. R7 starts no App Server or product
model, opens no transport or network path, issues no capability, and cannot
authorize automatic dispatch.

R7 removes a reproducible ambiguity from the R3-R6 protocol binding and gives
an independent reviewer a command-line entry point for validating a host-owned
R6 report against caller-owned build, schema, and subject inputs.

## Reproducible raw-schema defect

`codex app-server generate-json-schema` does not promise stable JSON object-key
ordering. Two consecutive offline generations from the active
`codex-cli 0.144.5` native build
`efdb3540ef74b9909408c8d38da79483454797b36f471e3e004fc2bf2b70e22a`
produced consolidated v2 files with identical semantic JSON and identical
471,114-byte lengths but different raw SHA-256 values:

- `2fdf0ab9dde01ddd5c42aa154cd5e8e6b88e48cc8c19228d64ed364f4d304155`;
- `df1a0f02b2510dd9f8667757ad11d7bcbcf24128fbbaabb92a6784a8b92f4321`.

The historical R3-R6 observation
`e46416109fae90974f571117d40d8480328bffdec7c6e3a8672d34067f57fdac`
is a third raw serialization of the same semantic JSON. It is retained as
historical evidence, but a raw-file digest is not a stable protocol identity.

All three files produce the same repository-canonical JSON digest:

`66ab7534f29e1ee7c065eb15c799d5f6e93fdd1d0ba86c262c3842a6a8f3d0c8`.

## Canonical protocol binding

`MTR_CODEX_APP_SERVER_SCHEMA_BINDING_R1`:

1. requires the consolidated
   `codex_app_server_protocol.v2.schemas.json` file;
2. decodes strict UTF-8 JSON;
3. rejects duplicate keys and non-finite numbers;
4. requires the exact `CodexAppServerProtocolV2` root;
5. verifies the required initialize, model-list, and turn-start definitions and
   the `model` and `effort` turn fields;
6. serializes with sorted object keys, compact separators, UTF-8, and one final
   line feed using the repository's `canonical_json_bytes`; and
7. publishes that canonical SHA-256 as `protocol_schema_sha256`.

Array order remains significant. Any semantic field, enum, reference, array,
or value change therefore changes the digest, while object-key order does not.

The binding also includes caller-supplied Codex version, native build SHA-256,
and experimental-API mode. The binding does not attest those values. An
independent host or reviewer must obtain them from the exact build under test.

## Independent report verification

`MTR_CODEX_APP_SERVER_UPSTREAM_VERIFIER_R1` accepts:

- the generated consolidated v2 schema;
- its deterministic R7 binding;
- independently owned expected Codex version and native build SHA-256;
- an independently owned R6 expected subject; and
- the host-produced R6 conformance report.

Verification fails closed unless:

- the schema re-creates the exact binding;
- the caller-owned version, native build digest, and experimental mode match;
- the R6 subject's `protocol_schema_sha256` equals the R7 canonical digest;
- the R6 report binds exactly to that expected subject; and
- the report's strict case, summary, privacy, authority, and report-digest
  checks pass.

The verification receipt persists only build/schema/subject/report digests and
the conformant or non-conformant result. It does not persist the raw schema,
subject, report, capability, prompt, paths, transport messages, model output,
tool output, or error detail.

## CLI

The CLI has no implicit App Server or schema-generation step. The host owner
generates schemas and independently determines the active native build digest.

Build a deterministic schema binding:

```powershell
mtr-dogfood-verify-app-server-conformance bind-schema `
  --schema C:\path\to\codex_app_server_protocol.v2.schemas.json `
  --codex-version "codex-cli 0.144.5" `
  --codex-build-sha256 <independently-measured-native-build-sha256> `
  --output C:\new\schema-binding.json
```

Add `--experimental-api-included` only when the schemas were generated with
the matching experimental mode.

Verify a host report:

```powershell
mtr-dogfood-verify-app-server-conformance verify-report `
  --schema C:\path\to\codex_app_server_protocol.v2.schemas.json `
  --binding C:\path\to\schema-binding.json `
  --expected-subject C:\path\to\caller-owned-r6-subject.json `
  --report C:\path\to\host-r6-report.json `
  --codex-version "codex-cli 0.144.5" `
  --codex-build-sha256 <independently-measured-native-build-sha256> `
  --output C:\new\verification-receipt.json
```

Output files use create-new semantics and are never overwritten.

## Schemas

- `schemas/codex-app-server-schema-binding-r1.schema.json`
- `schemas/codex-app-server-upstream-verification-r1-receipt.schema.json`

## Remaining OpenAI-owned gate

R7 makes the schema and report verification portable, deterministic, and
command-line accessible. It still cannot create the production evidence.

The remaining gate is for the Codex host owner to:

1. independently bind the exact shipped native build and generated schema;
2. implement the R5 atomic capability, nonce, budget, and send transaction;
3. run the R6 cases through the real isolated host test transport while keeping
   product-model starts at zero;
4. export the redacted R6 report; and
5. run R7 with caller-owned expected values.

Only that host-owned run can support a production conformance claim.

## R8 correction

R7 originally bound the caller's `experimental_api_included` boolean but did
not prove that the schema was generated with the same mode. R8 now verifies
the stable test-only experimental marker set supplied by the Codex schema
generator and rejects crossed or partial declarations before emitting a
binding. Correct default R7 bindings remain compatible. See
`openai-app-server-experimental-schema-binding-r8.md` for the reproduction and
boundary analysis.
