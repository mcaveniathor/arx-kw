# Security policy

## Reporting a vulnerability

Email **mcaveniathor@gmail.com** with the subject **ARX-KW security report**.
Include the affected crate version and features, a minimal reproduction or test
vector, expected and observed behavior, and the potential impact. Use synthetic
keys and data; do not send production secrets. Please keep exploitable details
out of public issues while a fix is being coordinated.

GitHub private vulnerability reporting is currently disabled for this repository.
The email above is the private reporting channel. There is no guaranteed response
time; this project is maintained on a best-effort basis.

## Supported versions

Security fixes target the latest stable version published on crates.io. Older
release lines do not have a guaranteed backport policy. An unreleased version in
the repository is not a supported published release. See the
[release history](https://github.com/mcaveniathor/arx-kw/releases) and
[changelog](CHANGELOG.md) for updates and migration requirements.

## Scope and assurance

Reports about authentication bypasses, incorrect wrapping or unwrapping,
secret exposure, panics on untrusted input, and violations of documented resource
limits are welcome. Dependency vulnerabilities should include an explanation of
how the affected code is reachable through this crate when possible.

The implementation and envelope protocol have not received an established
independent cryptographic audit. Test vectors, property testing, fuzzing, dependency
scans, and release provenance provide different kinds of evidence; none establishes
cryptographic security. The implementation review is recorded in
[CODE_REVIEW.md](CODE_REVIEW.md).

ARX-KW is deterministic and intended for high-entropy key material. Equal inputs
under the same key and context are recognizable. It does not provide replay or
rollback protection; applications must enforce freshness and key lifecycle rules.
The envelope context is authenticated through key derivation but is not stored.
See [README.md](README.md) for limits, format details, and the boundaries of secret
zeroization and constant-time behavior.
