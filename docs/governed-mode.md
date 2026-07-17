# Governed Mode

Governed mode is optional compatibility functionality. It accepts the
historical envelope schema at
`schemas/governed/task-envelope.schema.json` and returns the decision schema
at `schemas/governed/router-decision.schema.json`.

The caller may provide four verifier ports:

- approval
- validation
- canonical dispatch binding
- authority receipt

Each required port is fail-closed. Verifier exceptions, malformed results,
rejections, validation downgrades, noncanonical routes, mismatched receipts,
and consumed receipts return hard-stop decisions.

The package does not implement provider dispatch, receipt consumption,
validation execution, or approval issuance. A clear governed decision is still
data returned to the caller; this package does not execute it.

The advisory `assess` API never constructs these ports. Compatibility
`assess_mapping` reports verifier obligations but fixes execution authority
to false.
