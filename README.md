# ARX-KW

Rust implementations of the ARX-KW-8-2-4 key-wrap constructions from
[Satō Shinichi's paper](https://ia.cr/2020/059). These combine SipHash-2-4
with 128-bit output and ChaCha8 or XChaCha8 to wrap secret key material.

[Project website](https://mcaveniathor.github.io/arx-kw/) ·
[API reference](https://docs.rs/arx-kw) · [Changelog](https://github.com/mcaveniathor/arx-kw/blob/main/CHANGELOG.md)

Version 0.5.0 requires Rust 1.88 or newer. See the
[changelog](https://github.com/mcaveniathor/arx-kw/blob/main/CHANGELOG.md) for
migration notes and [crates.io](https://crates.io/crates/arx-kw) for published versions.

## Security and input limits

ARX-KW is deterministic: the same key and plaintext produce the same output.
Use it for high-entropy secret keys. Repeated inputs remain recognizable;
this is not a general-purpose encryption API for passwords, messages, or
other predictable data. For new integrations use the versioned envelope API,
which binds an application context through HKDF-SHA-256 and identifies the
format version and variant. Legacy blobs remain available for compatibility;
they require applications to manage protocol separation themselves.

| Feature / type | Wrapping key | Maximum plaintext | Cipher |
| --- | --- | --- | --- |
| `e` / `E` | 48 bytes | 64 bytes | ChaCha8 |
| `g` / `G` | 32 bytes | 64 bytes | ChaCha8 |
| `ex` / `EX` | 48 bytes | 1 MiB | XChaCha8 |
| `gx` / `GX` | 32 bytes | 1 MiB | XChaCha8 |

All four variant features and `envelope` are enabled by default. EX/GX enforce a one-MiB input limit
before hashing, key derivation, or output allocation. Output allocations use fallible reservation and return
`AllocationFailed` on failure. E/G bounds exclude the authentication tag.
Empty plaintexts are accepted. Every authentication tag is 16 bytes; blobs are `tag || ciphertext`,
so a wrapped 32-byte key occupies 48 bytes. Blobs shorter than 16 bytes return
an error. Decryption releases plaintext only after checking the tag with
`subtle::ConstantTimeEq`.

This implementation has not been established by this review to have an
independent cryptographic audit. Owned stream state, SipHash state, derived
subkeys, KDF chaining buffers,
and rejected plaintext buffers are wiped with `zeroize`. Use `SecretKey`
for owned wrapping keys and `decrypt_envelope` or `decrypt_secret` for
plaintext with drop-time erasure and redacted debug output. Legacy `decrypt`
and `decrypt_blob` return ordinary vectors whose erasure is the caller's
responsibility, as is the erasure of borrowed input or copied keys. Wiping
owned storage cannot guarantee erasure of compiler-created copies, CPU
registers, provider-internal scratch, swap, or crash dumps. Constant-time tag
comparison does not establish whole-program constant-time behavior.

Report vulnerabilities privately using [SECURITY.md](https://github.com/mcaveniathor/arx-kw/blob/main/SECURITY.md).

## Installation

Requires Rust 1.88 or later (including benchmark dependencies).

```toml
[dependencies]
arx-kw = "0.5"
```

To enable only GX:

```toml
[dependencies]
arx-kw = { version = "0.5", default-features = false, features = ["gx"] }
```

## Optional dependencies

Version 0.5 makes the context KDF optional; 0.4.0 included it unconditionally.
Default builds keep the same API and byte formats.

| Feature | Optional runtime dependencies / capabilities |
| --- | --- |
| `e`, `g` | `chacha20` and `arrayref`; ChaCha8 only |
| `ex`, `gx` | `chacha20` and `arrayref`, including XChaCha support |
| `envelope` | `hmac` and `sha2`; context-bound envelope methods and constants |

For a minimal raw GX build, disable default features and enable only `gx`.
For context-bound wrapping, enable both features:

```toml
[dependencies]
arx-kw = { version = "0.5", default-features = false, features = ["gx", "envelope"] }
```

**Migration for reduced-feature builds:** unlike 0.4.0, enabling a variant alone
no longer provides `encrypt_envelope`, `decrypt_envelope`,
`ENVELOPE_HEADER_LENGTH`, or `MAX_CONTEXT_LENGTH`. Add `envelope` when using
those APIs when migrating to 0.5. The default feature set keeps those APIs
available.

Without any features, the crate provides shared types and the `ArxKW` trait,
with no built-in cipher variant. `zeroize`, `subtle`, and `thiserror` remain
required by those public types, constant-time comparison, and error handling.
Example randomness uses a development-only `getrandom` dependency; it does not
add a runtime dependency for library consumers.

## Example

The following uses the GX test vector from the paper. Generate wrapping keys
with a cryptographically secure random source in applications; the fixed key
here is for demonstration only.

```rust
# #[cfg(feature = "gx")]
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use arx_kw::{gx::GX, ArxKW};
use hex::FromHex;

let key = <[u8; 32]>::from_hex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
)?;
let plaintext = <[u8; 32]>::from_hex(
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
)?;
let expected = hex::decode(
    "016325cf6a3c4b2e3b039675e1ccbc652f83f391c97f3606ccd5709c6ee15d66cd7e65a2aeb7dc3066636e8f6b0d39c3",
)?;
let blob = GX::encrypt_blob(&key, &plaintext)?;
assert_eq!(blob, expected);
assert_eq!(GX::decrypt_blob(&key, &blob)?, plaintext);
# Ok(())
# }
# #[cfg(not(feature = "gx"))] fn main() {}
```

Add `hex = "0.4.3"` to run this example. Import `ArxKW` to call the methods.
Use `encrypt` and `decrypt` when storing ciphertext and `AuthTag` separately.
Treat every decryption error as a failure; do not use unauthenticated data.

## Versioned envelopes and secret ownership

For new applications, enable `envelope` and use a stable, protocol-specific
context with the envelope methods. The fixed key in this example is a test fixture; applications must
supply cryptographically random wrapping keys.

```rust
# #[cfg(all(feature = "gx", feature = "envelope"))]
# fn main() -> Result<(), arx_kw::ArxKwError> {
use arx_kw::{gx::GX, ArxKW, SecretKey};
let key = SecretKey::new([0x42; 32]); // Test fixture only.
let context = b"example.com/key-storage/v1";
let envelope = GX::encrypt_envelope(&key, b"example key material", context)?;
let plaintext = GX::decrypt_envelope(&key, &envelope, context)?;
assert_eq!(plaintext.as_ref(), b"example key material");
// `key` and `plaintext` are wiped when they leave scope.
# Ok(())
# }
# #[cfg(not(all(feature = "gx", feature = "envelope")))] fn main() {}
```

Envelope v1 is `ARXK || 01 || variant || 0000 || tag || ciphertext`:
the first eight bytes contain magic, version, variant (E=1, G=2, EX=3, GX=4),
and two reserved zero bytes. Context bytes are not stored; callers must
supply exactly the same context (at most 4096 bytes) when opening an envelope.
The per-context wrapping key is derived using RFC 5869 HKDF-SHA-256, with
salt `ARX-KW/context/v1`, the original wrapping key as input key material,
and `header || context` as info. Its length matches the original key length.
This binds the header and context while preserving the paper's primitive
for legacy blobs. Envelopes add 24 bytes in total. Unknown versions, variants,
or reserved flags fail closed; the API never falls back to legacy decryption.
Use one format explicitly at each storage boundary. Determinism still reveals
repeated inputs within the same key and context.

## Runnable programs

Run these examples from a checkout of this release. Each uses OS randomness,
checks recovery and rejection cases, and prints only sizes or status messages.
They do not persist keys or write secret material to disk.

| Program | Use case | Required features |
| --- | --- | --- |
| `wrap_key` | Bind a generated data key to a tenant context | `gx,envelope` |
| `rotate_key` | Rewrap a data key under a new wrapping key | `gx,envelope` |
| `detached_tag` | Store ciphertext and authentication tag separately | `g` |

```sh
cargo run --example wrap_key --no-default-features --features gx,envelope
cargo run --example rotate_key --no-default-features --features gx,envelope
cargo run --example detached_tag --no-default-features --features g
```

The programs demonstrate the wrapping step, not complete key-management
systems. Production applications must protect and retain wrapping keys, choose
stable contexts, and commit rotations transactionally. Detached storage needs
a dedicated key for protocol separation because it has no context field.
See the [example source programs](https://github.com/mcaveniathor/arx-kw/tree/v0.5.0/examples).

## Release-specific recipes and tooling

[Symposiast guidance for 0.5.0](https://github.com/mcaveniathor/arx-kw/blob/main/guidance/README.md)
provides compiled consumer recipes for tenant-bound wrapping, key rotation, and
detached-tag storage, with minimal features and frozen source citations. It includes
a portable Symposium skill and a full bundle for MCP retrieval and version checks.
Generation and validation tooling is development-only and excluded from the crate.

## Development

```sh
cargo build
cargo test
cargo test --no-default-features --features gx
cargo test --no-default-features --features gx,envelope
python dev/check-features.py
cargo doc --no-deps
cargo bench
```

The unit tests include the paper's vectors for all four variants, plus
malformed-input, authentication, boundary, and stream-counter regressions.
Frozen envelope v1 vectors preserve compatibility with the published 0.4.0 crate.
Property tests generate keys, messages, contexts, and mutations; failures are
shrunk and saved by Proptest for reproduction. Instrumented fuzz targets and
local commands are documented in [fuzz/README.md](https://github.com/mcaveniathor/arx-kw/blob/main/fuzz/README.md).
Documentation examples run as doctests. Benchmarks use Criterion; use
`cargo bench --bench gx` for one variant. No service or credentials are needed.
`Cargo.lock` is intentionally ignored for this library; after initial resolution,
use `--locked` to retain the local resolution.

## Migrating from 0.3

Version 0.4 updates all direct dependencies, including RustCrypto `chacha20`
0.10, `thiserror` 2, and Criterion 0.8. The legacy `chacha`, `byteorder`, and
`siphasher` runtime dependencies have been removed. SipHash-2-4-128 uses
zeroizing state and is checked against the independent `siphasher` oracle.
Published paper-vector outputs are unchanged. EX/GX now reject inputs above
one MiB, including legacy ciphertexts previously accepted at larger sizes;
plan migration of such records using the earlier release before upgrading.

`ArxKwError::BadTags` is now a unit variant: authentication errors no longer
expose a computed tag in their fields, display text, or debug output.
`InvalidBlobLength(usize)` reports blobs missing a complete tag. Update
exhaustive error matches accordingly. Custom `ArxKW` implementations must
provide `VARIANT_ID` and key types supporting `Copy`, `Zeroize`, `AsRef`, and
`AsMut`. New errors cover allocation, context, and envelope validation failures. The old `nightly` SIMD feature has been
removed because the upstream implementation relies on obsolete compiler SIMD
interfaces; the supported workflow uses stable Rust.

For the Stucco website build and deployment, see [Website development](https://github.com/mcaveniathor/arx-kw/blob/main/site/README.md).
See the [Release guide](https://github.com/mcaveniathor/arx-kw/blob/main/RELEASE.md) for automated verification and publishing.

## References and license

- [ARX-KW paper and test vectors](https://ia.cr/2020/059)
- [API documentation](https://docs.rs/arx-kw)
- [MIT license](https://github.com/mcaveniathor/arx-kw/blob/main/LICENSE)
