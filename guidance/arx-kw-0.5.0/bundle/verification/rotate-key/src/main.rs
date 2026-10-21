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
