# Rotate a wrapping key

Authenticate an existing envelope, rewrap under a new wrapping key, and verify that the data key is unchanged and the old key is rejected. Durable storage and transactional rotation remain application responsibilities.

Release: arx-kw 0.5.0.

Verification: Compiled: cargo check --locked --all-targets passed; runtime behavior was not tested (rustc 1.99.1 (58cf8f9c3 2026-10-13)).
Compilation does not establish runtime behavior or idiomatic usage.

```toml
[dependencies.arx-kw]
default-features = false
features = [
    "gx",
    "envelope",
]
version = "=0.5.0"

[dependencies.getrandom]
default-features = false
features = ["std"]
version = "=0.4.3"
```

```rust
//! Rewrap stored key material under a new wrapping key without changing the data key.
use arx_kw::{gx::GX, ArxKW, ArxKwError, ConstantTimeEq, SecretKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut old_wrapping_key = SecretKey::new([0; 32]);
    let mut new_wrapping_key = SecretKey::new([0; 32]);
    let mut data_key = SecretKey::new([0; 32]);
    getrandom::fill(&mut *old_wrapping_key)?;
    getrandom::fill(&mut *new_wrapping_key)?;
    getrandom::fill(&mut *data_key)?;
    let context = b"example.com/key-vault/v1/record-7";
    let old_envelope = GX::encrypt_envelope(&old_wrapping_key, &*data_key, context)?;

    // Authenticate before rewrapping. The temporary plaintext wipes on scope exit.
    let new_envelope = {
        let plaintext = GX::decrypt_envelope(&old_wrapping_key, &old_envelope, context)?;
        GX::encrypt_envelope(&new_wrapping_key, &plaintext, context)?
    };
    let recovered = GX::decrypt_envelope(&new_wrapping_key, &new_envelope, context)?;
    assert!(bool::from(recovered.as_ref().ct_eq(data_key.as_slice())));
    assert!(matches!(
        GX::decrypt_envelope(&old_wrapping_key, &new_envelope, context),
        Err(ArxKwError::BadTags)
    ));

    // Persist and verify the replacement before retiring the old wrapping key.
    // Production rotation also needs transactions, backups, and a key identifier.
    println!("Rewrapped the data key; the old wrapping key cannot open the new envelope.");
    Ok(())
}

```

## Evidence

- [e0012 lines 1–30](../evidence/e0012.txt) ([source](https://docs.rs/crate/arx-kw/0.5.0/source/examples/rotate_key.rs))
- [e0003 lines 71–98](../evidence/e0003.txt) ([source](https://docs.rs/crate/arx-kw/0.5.0/source/README.md))
- [e0003 lines 139–165](../evidence/e0003.txt) ([source](https://docs.rs/crate/arx-kw/0.5.0/source/README.md))
