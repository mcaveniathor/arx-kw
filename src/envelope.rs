use crate::{memory, ArxKW, ArxKwError, SecretBytes, Zeroize, Zeroizing};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::convert::TryFrom;

/// Length of the magic, version, variant, and reserved bytes preceding a legacy blob.
pub const ENVELOPE_HEADER_LENGTH: usize = 8;
/// Maximum application context length in bytes (four KiB).
pub const MAX_CONTEXT_LENGTH: usize = 4096;
const SALT: &[u8] = b"ARX-KW/context/v1";

const fn header<V: ArxKW + ?Sized>() -> [u8; ENVELOPE_HEADER_LENGTH] {
    [b'A', b'R', b'X', b'K', 1, V::VARIANT_ID, 0, 0]
}

fn derive<V: ArxKW + ?Sized>(
    key: &V::Key,
    context: &[u8],
) -> Result<Zeroizing<V::Key>, ArxKwError> {
    if context.len() > MAX_CONTEXT_LENGTH {
        return Err(ArxKwError::ContextTooLong);
    }
    let mut derived = Zeroizing::new(*key);
    derive_bytes(
        key.as_ref(),
        SALT,
        &[&header::<V>(), context],
        derived.as_mut(),
    )?;
    Ok(derived)
}

pub fn encrypt<V: ArxKW + ?Sized>(
    key: &V::Key,
    plaintext: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, ArxKwError> {
    memory::check_length(plaintext.len(), V::MAX_INPUT_LENGTH)?;
    let key = derive::<V>(key, context)?;
    let blob = V::encrypt_blob(&key, plaintext)?;
    let length = blob
        .len()
        .checked_add(ENVELOPE_HEADER_LENGTH)
        .ok_or(ArxKwError::AllocationFailed)?;
    let mut output = memory::allocate(length)?;
    output.extend_from_slice(&header::<V>());
    output.extend_from_slice(&blob);
    Ok(output)
}

pub fn decrypt<V: ArxKW + ?Sized>(
    key: &V::Key,
    input: &[u8],
    context: &[u8],
) -> Result<SecretBytes, ArxKwError> {
    if input.len() < ENVELOPE_HEADER_LENGTH + 16 || input[..ENVELOPE_HEADER_LENGTH] != header::<V>()
    {
        return Err(ArxKwError::InvalidEnvelope);
    }
    memory::check_length(
        input.len() - ENVELOPE_HEADER_LENGTH - 16,
        V::MAX_INPUT_LENGTH,
    )?;
    let key = derive::<V>(key, context)?;
    V::decrypt_secret(&key, &input[ENVELOPE_HEADER_LENGTH..])
}

// RFC 5869 Extract/Expand. Keep PRK and chaining blocks in guarded buffers
// instead of leaving HKDF output blocks in an unguarded provider temporary.
fn derive_bytes(
    ikm: &[u8],
    salt: &[u8],
    info: &[&[u8]],
    output: &mut [u8],
) -> Result<(), ArxKwError> {
    if output.len() > 255 * 32 {
        return Err(ArxKwError::KeyDerivationFailed);
    }
    let mut extract =
        Hmac::<Sha256>::new_from_slice(salt).map_err(|_| ArxKwError::KeyDerivationFailed)?;
    extract.update(ikm);
    let mut raw = extract.finalize().into_bytes();
    let prk: Zeroizing<[u8; 32]> = Zeroizing::new(*raw.as_ref());
    raw.as_mut_slice().zeroize();
    let mut previous = Zeroizing::new([0u8; 32]);
    for (index, chunk) in output.chunks_mut(32).enumerate() {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&*prk).map_err(|_| ArxKwError::KeyDerivationFailed)?;
        if index != 0 {
            mac.update(&*previous);
        }
        for part in info {
            mac.update(part);
        }
        mac.update(&[u8::try_from(index + 1).map_err(|_| ArxKwError::KeyDerivationFailed)?]);
        let mut raw = mac.finalize().into_bytes();
        previous.copy_from_slice(&raw);
        raw.as_mut_slice().zeroize();
        chunk.copy_from_slice(&previous[..chunk.len()]);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rfc5869_case_one_and_provider_agree() {
        let ikm = [0x0b; 22];
        let salt: Vec<u8> = (0..=12).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let mut output = [0u8; 42];
        derive_bytes(&ikm, &salt, &[&info], &mut output).unwrap();
        assert_eq!(
            hex::encode(output),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
        let reference = hkdf::Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut expected = [0u8; 42];
        reference.expand(&info, &mut expected).unwrap();
        assert_eq!(output, expected);
    }
}
