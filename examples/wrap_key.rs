//! Wrap a fresh data-encryption key with an application-specific context.
use arx_kw::{gx::GX, ArxKW, ArxKwError, ConstantTimeEq, SecretKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A real application loads its wrapping key from protected persistent storage.
    let mut wrapping_key = SecretKey::new([0; 32]);
    let mut data_key = SecretKey::new([0; 32]);
    getrandom::fill(&mut *wrapping_key)?;
    getrandom::fill(&mut *data_key)?;

    // Include protocol and tenant identifiers in the application context.
    let context = b"example.com/backups/v1/tenant-42";
    let envelope = GX::encrypt_envelope(&wrapping_key, &*data_key, context)?;
    // Store the envelope, keeping the wrapping key separately protected.
    let recovered = GX::decrypt_envelope(&wrapping_key, &envelope, context)?;
    assert!(bool::from(recovered.as_ref().ct_eq(data_key.as_slice())));
    assert!(matches!(
        GX::decrypt_envelope(
            &wrapping_key,
            &envelope,
            b"example.com/backups/v1/tenant-43"
        ),
        Err(ArxKwError::BadTags)
    ));

    println!(
        "Wrapped a 32-byte data key into a {}-byte envelope.",
        envelope.len()
    );
    println!("Recovered the key and rejected a different tenant context.");
    // Owned keys and recovered plaintext are wiped when dropped; never log them.
    Ok(())
}
