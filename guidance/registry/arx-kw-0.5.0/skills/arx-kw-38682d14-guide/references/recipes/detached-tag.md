# Store ciphertext and tag separately

Use raw G wrapping with a dedicated protocol key, guard recovered plaintext, and verify rejection of a modified tag.

Release: arx-kw 0.5.0.

Verification: Compiled: cargo check --locked --all-targets passed; runtime behavior was not tested (rustc 1.99.1 (58cf8f9c3 2026-10-13)).
Compilation does not establish runtime behavior or idiomatic usage.

```toml
[dependencies.arx-kw]
default-features = false
features = ["g"]
version = "=0.5.0"

[dependencies.getrandom]
default-features = false
features = ["std"]
version = "=0.4.3"
```

```rust
//! Store ciphertext and its authentication tag separately using only feature `g`.
use arx_kw::{g::G, ArxKW, ArxKwError, ConstantTimeEq, SecretKey, Zeroizing};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut wrapping_key = SecretKey::new([0; 32]);
    let mut data_key = SecretKey::new([0; 32]);
    getrandom::fill(&mut *wrapping_key)?;
    getrandom::fill(&mut *data_key)?;

    // G accepts at most 64 bytes. Use a dedicated wrapping key for this protocol;
    // this raw format carries no version, variant, or application context.
    let (ciphertext, tag) = G::encrypt(&wrapping_key, &*data_key)?;
    // For example, store these in separate database columns.
    // Detached decryption returns a Vec, so explicitly guard its erasure.
    let recovered = Zeroizing::new(G::decrypt(&wrapping_key, &ciphertext, &tag)?);
    assert!(bool::from(recovered.as_slice().ct_eq(data_key.as_slice())));

    let mut changed_tag = tag;
    changed_tag.0[0] ^= 1;
    assert!(matches!(
        G::decrypt(&wrapping_key, &ciphertext, &changed_tag),
        Err(ArxKwError::BadTags)
    ));
    println!(
        "Stored {} ciphertext bytes and a 16-byte tag; tampering was rejected.",
        ciphertext.len()
    );
    Ok(())
}

```

## Evidence

- [e0006 lines 1–29](../evidence/e0006.txt) ([source](https://docs.rs/crate/arx-kw/0.5.0/source/examples/detached_tag.rs))
- [e0003 lines 71–98](../evidence/e0003.txt) ([source](https://docs.rs/crate/arx-kw/0.5.0/source/README.md))
