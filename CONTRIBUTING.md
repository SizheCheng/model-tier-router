# Contributing

Contributions should preserve deterministic offline behavior and the
non-authority constants.

1. Create a focused change.
2. Add or update standard-library `unittest` coverage.
3. Run `python -B -m unittest discover -s tests -v` with `PYTHONPATH=src`.
4. Do not add provider SDKs, network access, telemetry, credentials, dynamic
   prices, model names, executable policy expressions, or generated artifacts.
5. Document schema and compatibility changes in `CHANGELOG.md`.

By submitting a contribution, you agree that it is licensed under Apache-2.0
and that you have the right to submit it.
