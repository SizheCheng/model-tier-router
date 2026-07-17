# Security Policy

## Supported version

Security fixes are applied to the latest 0.1.x release candidate until a
published release policy supersedes this file.

## Reporting

Security vulnerabilities must be submitted through GitHub Private Vulnerability
Reporting using Security -> Advisories -> Report a vulnerability. Undisclosed
vulnerabilities must not be posted as public issues.

Do not include credentials, customer payloads, or private deployment data in a
report unless they are strictly necessary to reproduce the vulnerability.

## Boundaries

The advisory core is offline and non-authorizing. It does not call providers,
read credentials, execute recommendations, or write files. The CLI can read
only stdin or paths explicitly supplied by its caller. Governed verifier ports
are caller-provided and remain outside the pure core.
