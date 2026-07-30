# R8: fail-closed App Server experimental-schema binding

## Status

Source-only, offline verifier hardening. R8 starts no App Server or product
model, opens no transport or network path, and grants no routing, execution,
attestation, sandbox, approval, or write authority.

R8 fixes a reproducible claim-binding defect in R7. The R7 binding recorded
`experimental_api_included`, but the verifier trusted the caller-supplied
boolean without proving that the generated schema actually used the matching
`codex app-server generate-json-schema` mode.

## Reproducible defect

The active `codex-cli 0.144.5` native build
`efdb3540ef74b9909408c8d38da79483454797b36f471e3e004fc2bf2b70e22a`
produced two offline schema cohorts:

| generator mode | files | consolidated v2 definitions | canonical digest |
| --- | ---: | ---: | --- |
| default | 267 | 516 | `66ab7534f29e1ee7c065eb15c799d5f6e93fdd1d0ba86c262c3842a6a8f3d0c8` |
| `--experimental` | 337 | 586 | `f9a8ef7d74f6dd20ddb54484104e64188fde8589790e5f585d5098dd846ee744` |

Before R8, all four schema/declaration combinations returned success:

- default schema declared default;
- default schema declared experimental;
- experimental schema declared default; and
- experimental schema declared experimental.

The schema digest still distinguished the two semantic documents, but a
binding could make a false generator-mode claim. An upstream reviewer could
therefore verify the wrong policy surface while seeing a self-consistent
binding hash.

## Stable generator marker

The generated schema deliberately supplies test-only fields and methods for
stable experimental-gating validation. R8 structurally checks all of these
markers:

- `ThreadStartParams.properties.mockExperimentalField`;
- `MockExperimentalMethodParams` with its exact title;
- `MockExperimentalMethodResponse` with its exact title; and
- the exact `mock/experimentalMethod` value inside `ClientRequest`.

All markers must be present when `experimental_api_included` is true and all
must be absent when it is false. A partial marker set fails closed as
`APP_SERVER_SCHEMA_EXPERIMENTAL_SURFACE_INVALID`. A complete surface paired
with the wrong declaration fails as
`APP_SERVER_SCHEMA_EXPERIMENTAL_MODE_MISMATCH`.

The markers are inspected as parsed JSON values. Text search, definition
counts, file counts, and descriptions are not used as authority.

## Attestation is not dispatch authority

The default schema also contains `requestAttestation` and the server request
`attestation/generate`, described as producing an opaque client attestation
for upstream `x-oai-attestation`. Those fields are not experimental-mode
markers and R8 does not reinterpret them as any of the following:

- a model-selection capability;
- authorization to start a turn;
- host-build attestation;
- a nonce or budget transaction;
- permission to expand network, sandbox, approval, or write scope.

A future OpenAI host may bind independently verified provenance to the R6/R7
artifacts, but this local component cannot mint or validate that provenance by
relabeling the existing client-attestation token.

## Verified behavior

After the fix:

- default schema declared default succeeds;
- experimental schema declared experimental succeeds;
- both crossed declarations exit with code 2 and create no binding output;
- the correct default R7 binding remains byte-for-byte compatible; and
- canonical JSON still ignores object-key order while preserving every
  semantic schema difference.

The regression suite also mutates a complete experimental surface into a
partial one and requires the distinct fail-closed surface error.

## Remaining OpenAI-owned gate

R8 makes the R7 build/schema claim precise; it does not manufacture the
host-owned evidence that R6 requires. Production adoption still requires the
Codex host owner to implement the R5 atomic capability, nonce, budget, and
send transaction, exercise it through an isolated zero-product-model test
transport, bind the exact shipped build, and export an R6 report for R7/R8
verification.
