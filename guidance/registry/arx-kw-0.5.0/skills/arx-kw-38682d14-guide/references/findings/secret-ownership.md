# Keep owned keys and recovered plaintext in erasing guards

Use SecretKey for owned wrapping keys and prefer decrypt_envelope or decrypt_secret for drop-time erasure. Raw decrypt and decrypt_blob return Vec<u8>; immediately guard recovered plaintext with Zeroizing when using them. Do not print secret material. Drop-time wiping cannot erase borrowed inputs or guarantee removal of copied keys, registers, swap, or crash dumps.

Basis: Documented.

Features: No additional features stated.

## Evidence

- [e0003 lines 39–49](../evidence/e0003.txt) ([source](https://docs.rs/crate/arx-kw/0.5.0/source/README.md))
- [e0027 lines 1–117](../evidence/e0027.txt) ([source](https://docs.rs/crate/arx-kw/0.5.0/source/src/memory.rs))
- [e0006 lines 1–29](../evidence/e0006.txt) ([source](https://docs.rs/crate/arx-kw/0.5.0/source/examples/detached_tag.rs))
