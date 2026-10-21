# Use deterministic wrapping for high-entropy key material

Generate keys with a cryptographically secure random source. Deterministic wrapping reveals repeated inputs within a key and context; it is not general-purpose encryption for passwords or predictable messages. E/G accept up to 64 bytes; EX/GX up to one MiB. Applications must provide replay/rollback protection and key lifecycle management. This crate has no established independent cryptographic audit.

Basis: Documented.

Features: No additional features stated.

## Evidence

- [e0003 lines 14–49](../evidence/e0003.txt) ([source](https://docs.rs/crate/arx-kw/0.5.0/source/README.md))
- [e0017 lines 24–41](../evidence/e0017.txt) ([source](https://docs.rs/crate/arx-kw/0.5.0/source/SECURITY.md))
