# Use dedicated keys with raw detached storage

G accepts a 32-byte wrapping key and at most 64 plaintext bytes. encrypt returns ciphertext and a separate 16-byte AuthTag. Retain both, reject every decryption error, and use a dedicated key for this protocol: the raw format has no version, variant, or application context.

Basis: Documented.

Features: g.

## Evidence

- [e0006 lines 1–29](../evidence/e0006.txt) ([source](https://docs.rs/crate/arx-kw/0.5.0/source/examples/detached_tag.rs))
- [e0003 lines 24–37](../evidence/e0003.txt) ([source](https://docs.rs/crate/arx-kw/0.5.0/source/README.md))
- [e0003 lines 129–131](../evidence/e0003.txt) ([source](https://docs.rs/crate/arx-kw/0.5.0/source/README.md))
