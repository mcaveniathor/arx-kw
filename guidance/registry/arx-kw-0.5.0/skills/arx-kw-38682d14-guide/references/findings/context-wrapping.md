# Bind a data key to a stable application context

For context-bound GX wrapping enable gx and envelope, import ArxKW, and use encrypt_envelope/decrypt_envelope. Preserve the exact context bytes: the envelope does not store them, and a changed context fails authentication. Contexts are limited to 4096 bytes. Envelopes add 24 bytes and never silently fall back to legacy blobs.

Basis: Documented.

Features: gx, envelope.

## Evidence

- [e0003 lines 133–165](../evidence/e0003.txt) ([source](https://docs.rs/crate/arx-kw/0.5.0/source/README.md))
- [e0016 lines 1–33](../evidence/e0016.txt) ([source](https://docs.rs/crate/arx-kw/0.5.0/source/examples/wrap_key.rs))
