# Select only the required variant and envelope features

Disable default features for a minimal dependency graph. gx,envelope provides context-bound GX; g alone provides raw detached wrapping. In 0.5.0 a variant alone no longer enables envelope methods/constants. HMAC and SHA-256 follow envelope; ChaCha and arrayref follow variants; only EX/GX enable XChaCha. zeroize, subtle, and thiserror remain mandatory. Rust 1.88 is the crate minimum.

Basis: Documented.

Features: gx, g, envelope.

## Evidence

- [e0003 lines 55–98](../evidence/e0003.txt) ([source](https://docs.rs/crate/arx-kw/0.5.0/source/README.md))
