# Changelog

## 0.4.0 (2026-10-21)

- Update every direct runtime and development dependency to the latest stable
  release available during the maintenance review.
- Require Rust 1.88 or newer and update CI, security audits, and Criterion benches.
- Replace private-layout casts and the legacy cipher provider with RustCrypto
  `chacha20`, preserving the 64-bit counter layout. Forbid unsafe code in this crate.
- Reject blobs shorter than 16 bytes with `InvalidBlobLength(usize)` instead of
  panicking.
- Replace `BadTags(AuthTag, AuthTag)` with `BadTags` to keep computed authentication
  tags out of returned errors and logs. This changes exhaustive error matches.
- Remove the obsolete upstream `nightly` SIMD feature. Use stable Rust.
- Remove coverage-only compilation guards that removed required methods when
  coverage instrumentation was enabled.
- Add malformed-input, wrong-key, tag/ciphertext tampering, message-boundary,
  chunked stream, low-word counter carry, and counter-exhaustion regressions.
- Fix feature-specific doctests and benchmark selection, assertion-macro trait
  lookup, error formatting, and unnecessary tag allocation.
- Share the README with crate documentation; document key lengths, stream limits,
  blob encoding, migration, and secret-memory limitations.

The four published paper test vectors retain their original outputs. Release
availability is recorded on crates.io and the GitHub Releases page.

### Additional hardening

- Zeroize owned cipher and SipHash state, subkeys, KDF chaining buffers, and
  plaintext on failed authentication. Add `SecretKey` and `SecretBytes` with
  drop-time erasure and redacted debug output; retain legacy return types.
- Enforce a one-MiB EX/GX input limit before processing and return allocation
  failures rather than relying on infallible output allocation.
- Add versioned envelopes that bind a context with RFC 5869 HKDF-SHA-256 and
  identify the variant. Reject altered headers, wrong contexts, unsupported
  versions, oversized contexts, and truncation without legacy fallback.
- Replace runtime SipHash state with an erasable implementation validated
  against the independent reference. Keep legacy cipher and SipHash providers
  exclusively as development compatibility oracles.

Independent cryptographic audit and formal whole-program timing/memory-erasure
assurance are not supplied by this release preparation.

### Documentation and automation

- Replace the Jekyll landing page with a static site generated using Stucco 0.5:
  responsive layouts, system light/dark themes, shared Markdown sources,
  anchored navigation, and a generated API reference at the existing URL.
- Add Linux/macOS/Windows CI for stable Rust and Rust 1.88, locked site builds,
  workflow validation, dependency audits, and read-only pull-request checks.
- Pin third-party actions to verified commit SHAs and remove legacy Travis
  and coverage-uploader configuration.
- Add a version-tagged release pipeline with package provenance, SHA-256 and
  byte-for-byte rebuild checks, temporary crates.io OIDC credentials, safe
  registry retries, and GitHub release assets after publication succeeds.
- Add isolated SLSA Build Level 3 provenance generation, mandatory signature,
  source/tag/builder/digest verification before publication, and signed provenance
  as a release asset with consumer verification instructions.
