# Implementation review — 2026-10-21

Reviewed baseline `28ccfd8c705782d7b138edbd94730b41d7c1ba4d` and the resulting
0.4.0 release preparation on `release/0.4.0`. Scope: source, tests, benchmarks,
dependency resolution, documentation, and CI. This is an implementation review;
it is not an independent cryptographic audit.

## Findings addressed

| Severity | Baseline finding | Release disposition |
| --- | --- | --- |
| High | Unrelated Rust structures were transmuted into a dependency's private cipher layout. | Removed both casts. LQB uses RustCrypto's public ChaCha8 core API, mapping the high counter word to the first IETF nonce word for each block. The crate forbids unsafe code. |
| High | Authentication errors exposed the computed, key-dependent tag through fields and logging. | Authentication failure is a unit error; computed candidate tags are held in zeroizing guards. Display/Debug regression tests verify no tag payload. |
| Medium | Short input blobs panicked before validating the authentication-tag length. | Validate lengths and return `InvalidBlobLength`. All short lengths and variants have regressions. |
| Medium | Owned cipher/MAC state, derived subkeys, and rejected plaintext were not wiped. | Add drop-time zeroization for owned state and buffers, an erasable SipHash implementation, and redacted `SecretKey`/`SecretBytes` ownership types. Guard error paths and return authenticated plaintext only after checking tags. |
| Medium | EX/GX allocated proportional to unbounded unauthenticated input. | Enforce a one-MiB input limit before processing. Output buffers use `try_reserve_exact`, checked length addition, and `AllocationFailed`. E/G keep the 64-byte limit. |
| Medium | Legacy blobs lacked an application context, variant, or format version. | Add envelope v1 with HKDF-SHA-256 domain separation. Header and context affect key derivation; reject altered/unsupported headers without legacy fallback. Contexts are bounded at 4096 bytes. Preserve legacy blobs explicitly for compatibility. |
| Medium | Legacy cipher provider, obsolete nightly SIMD, and coverage guards depended on unsupported interfaces. | Remove the runtime legacy provider and destructive cfg guards; use RustCrypto public APIs with zeroization enabled. Legacy providers remain development-only compatibility oracles. Remove the unsupported nightly feature. |
| Medium | CI used obsolete actions and executed an unpinned downloaded coverage uploader. | Update CI, MSRV/variant/benchmark checks, strict linting, scheduled advisory scans; remove the uploader. Hosted CI still must run after pushing. |
| Low | Inconsistent documentation, disabled-feature imports, benchmark selection, error formatting, and macro trait lookup. | Consolidate and correct documentation, gate feature-specific examples/benches, fix error text and macro hygiene. |

## Cryptographic compatibility and protocol review

- Preserve all four paper vectors and verify 232 additional key/length cases
  against independent legacy cipher and SipHash providers. Cases cover empty
  inputs, message tails, block boundaries, and multiple blocks.
- Compare the zeroizing SipHash implementation to `siphasher` for four keys
  and every length 0–1024 (4100 comparisons).
- Check RFC 5869 HKDF test case 1 and the independent HKDF provider. PRK and
  chaining blocks are guarded/wiped; enable upstream HMAC/SHA-256 zeroization.
- Envelope v1 derives a key of the original length with salt
  `ARX-KW/context/v1`, original key as IKM, and the fixed eight-byte header
  followed by context as info. The fixed header prevents ambiguous framing.
  Variant/version changes are bound through the derived key. There is no
  format negotiation or fallback that could silently downgrade an envelope.
- Reject changed contexts, each changed header/tag/ciphertext byte, every
  truncation of a representative envelope, oversized contexts, and wrong
  variants. Test one-MiB acceptance and oversized-input rejection.
- Cipher/MAC rounds operate on fixed-width words. Tag comparison uses
  `subtle::ConstantTimeEq`; header/length/allocation checks depend on public
  metadata. This inspection is not a formal whole-program timing proof.

## Validation evidence

- Rust 1.99.1 and the declared MSRV, Rust 1.88.0: 49 tests pass with all
  features (28 unit, 13 integration, 8 documentation tests).
- Each variant and no-default-feature configurations pass their suites.
- Strict Clippy for all targets with all/no default features, formatting, and
  rustdoc with warnings denied pass.
- All eight Criterion encryption/decryption smoke checks pass in release mode;
  these checks do not measure performance regressions.
- `cargo-audit` 0.22.2 reports zero known vulnerabilities and no advisory
  warnings for the 101-package resolution, against RustSec commit
  `4b587f00996ebe5c05a73eaef105ef241e876414` (2026-10-21).
- The release procedure includes package verification and a registry publish
  dry run. No package upload, remote push, or release tag is part of preparation.

## Assurance boundary

The implementation limitations above have concrete fixes and tests. Independent
expert audit of the ARX-KW construction, new envelope protocol, and implementation
remains external work and is not claimed. The construction is deterministic;
repeated keys within the same wrapping key/context remain recognizable.

Zeroization covers storage owned by these types, not every compiler-created
copy, CPU register, provider-internal temporary, swap page, or crash dump. The
library cannot erase borrowed caller inputs. Callers must avoid copying secrets
and manage the lifetime of raw arrays and legacy returned vectors; prefer the
new secret ownership and envelope APIs. These are explicit ownership and
assurance boundaries, not guarantees that can be established by unit tests.

## Documentation and automation follow-up

The Stucco site is a separate, locked build crate, excluded from the published
library and its runtime dependency graph. Local validation covers nine
rendered pages, 130 internal links/assets, both root and project URL prefixes,
and 36 desktop/mobile/light/dark browser cases. Automated WCAG A/AA checks
report no violations in those cases; keyboard navigation also works with
JavaScript disabled. This is not a full accessibility certification.

The updated workflows are validated with checksum-verified actionlint 1.7.12.
Six release-helper tests exercise wrong tags/crate names, missing changelog
entries, dirty/wrong source archives, registry mismatches, and non-404 network
failures. Both library and website dependency audits pass locally. Hosted
Linux/macOS/Windows CI, Pages deployment, and crates.io OIDC authorization
remain unexecuted here; their required service settings are in RELEASE.md.

## 0.5.0 examples and feature selection

The follow-up change keeps the existing cipher, SipHash, KDF, and envelope
formats intact. Blob parsing copies the bounded tag directly so the shared
trait no longer needs `arrayref` without a built-in variant. Cipher and array
helpers follow variant features; HMAC/SHA-256 and envelope methods/constants
follow default-enabled `envelope`. Zeroization and constant-time comparison
remain mandatory. Explicitly reduced-feature consumers must opt into envelope
APIs, so this change uses a new breaking version.

The three runnable examples obtain wrapping and data keys from OS randomness,
propagate entropy errors, retain plaintext in zeroizing storage, and avoid
printing secrets. They verify context rejection, key rotation, and detached-tag
tampering. The examples demonstrate wrapping operations, not durable key
storage or transactional rotation.

Checks cover raw and envelope variants, envelope-only and no-feature builds,
actual runtime dependency graphs, MSRV, documentation, and example execution
across the CI platforms. This implementation review does not constitute an
independent cryptographic audit.

## 0.5.0 compatibility and malformed-input hardening

Sixteen frozen envelope v1 vectors were obtained from the checksum-verified
published 0.4.0 crate. They cover each variant, empty and binary contexts, and
0/1/32/64-byte plaintexts. The new release reproduces every byte and opens each
old envelope. Provenance and fixture construction are in tests/vectors/README.md.
These fixtures preserve compatibility; they are not an independent cryptographic
oracle for the envelope construction.

Proptest exercises arbitrary keys, messages, contexts, wrong keys/contexts,
single-bit mutations, truncations, determinism, and malformed blobs/envelopes.
Separate deterministic checks cover maximum and oversized EX/GX payloads.
The full suite now has 59 tests (28 unit, 23 integration, 8 documentation),
passing on Rust 1.99.1 and 1.88.0. A further run with 2048 generated cases per
variant (seed 20261021) passed. Raw/envelope variants, envelope-only and
no-feature builds, strict Clippy, ten dependency graphs, six release-helper
checks, and the nine-page/136-link site check pass.

Two libFuzzer targets share the property assertions and use the frozen vectors
as seeds. Local runs with cargo-fuzz 0.13.2 and Rust nightly 2026-10-21, coverage
instrumentation, and AddressSanitizer completed without findings: 623974
malformed-input executions and 129759 round-trip executions, each in 46 seconds.
CI runs bounded 30-second smoke checks per target. These short runs are not an
exhaustive fuzz campaign or a timing/cryptographic proof. The separate fuzz
workspace and Proptest are absent from library runtime dependency graphs.
Root and fuzz lockfile advisory scans reported no known vulnerabilities.

SECURITY.md records the private reporting channel, latest-stable support policy,
and replay/rollback and audit limitations. No primitive or format changed.
