# Security policy

## Reporting a vulnerability

**Do not open a public issue or pull request for a suspected vulnerability.** Use GitHub's [private vulnerability reporting form](https://github.com/ryltsevmikhail/Runne/security/advisories/new) for this repository (Security → Report a vulnerability). A GitHub account is required.

Include the affected commit or version, platform, reproducible steps, expected security boundary, and potential impact. Share only the minimum information needed: redact credentials, personal data, and unrelated logs. Do not test against other people's systems or data without authorization.

Private reporting must be enabled by the repository owner. If GitHub does not offer the form, **do not post sensitive details publicly**. Ask [the maintainer](https://github.com/ryltsevmikhail) in a non-sensitive issue to enable private reporting. No alternate private email address is advertised by this project.

## Handling reports

Maintainers assess reports and coordinate fixes and disclosure through the private report. Response and resolution times are not guaranteed. Please coordinate public disclosure so users have an opportunity to update.

## Supported versions and limitations

Runne is under active development. Security work targets the current development code; there is no promised long-term support or backport schedule for older versions. Linux is the active execution-node target; macOS (Apple Silicon) is under active qualification. The presence of sandboxing, credential storage, or platform code is not a claim of independently audited security or production readiness.

Never include API keys or runtime credentials in a public bug report. If a credential has been exposed, revoke or rotate it with its issuer; removing a public message alone is insufficient.
