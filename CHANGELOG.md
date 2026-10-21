# Changelog

## 0.4.0 (release candidate)

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

The four published paper test vectors retain their original outputs. This
release has not been published by the maintenance task.

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
