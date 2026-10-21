# Authenticate before rotating a wrapping key

Open the existing envelope under the old wrapping key and context, then wrap the authenticated data key under the new wrapping key using the same context. Keep the intermediate plaintext guarded. Persist and verify the replacement before retiring the old key; production rotation also requires transactions, backups, and key identifiers.

Basis: Documented.

Features: gx, envelope.

## Evidence

- [e0012 lines 1–30](../evidence/e0012.txt) ([source](https://docs.rs/crate/arx-kw/0.5.0/source/examples/rotate_key.rs))
- [e0003 lines 185–188](../evidence/e0003.txt) ([source](https://docs.rs/crate/arx-kw/0.5.0/source/README.md))
