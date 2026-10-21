use crate::ConstantTimeEq;
use crate::{generate, util, ArxKW, ArxKwError, AuthTag};

/// The ARX-8-2-4-GX variant. Has a key length of 32 bytes and a maximum input length of one MiB.
/// See the [`ArxKW`] trait for usage.
pub struct GX;
impl GX {
    /// The length in bytes of the secret key used by this variant of ARX-KW
    #[must_use]
    pub const fn key_length() -> usize {
        32
    }
}

impl ArxKW for GX {
    type Key = [u8; Self::key_length()];
    const VARIANT_ID: u8 = 4;
    fn encrypt(key: &Self::Key, plaintext: &[u8]) -> Result<(Vec<u8>, AuthTag), ArxKwError> {
        crate::memory::check_length(plaintext.len(), Self::MAX_INPUT_LENGTH)?;
        let (k1, k2) = generate::subkeys(key)?;
        let authentication_tag = util::sip_array_keyed(&k1, plaintext);
        let nonce = construct_nonce(&authentication_tag);
        let mut stream = util::xchacha8::new(&k2, &nonce);
        let mut ciphertext = crate::memory::copy_secret(plaintext)?;
        stream.xor_read(&mut ciphertext)?;
        Ok((std::mem::take(&mut *ciphertext), authentication_tag))
    }
    fn decrypt(
        key: &Self::Key,
        ciphertext: &[u8],
        authentication_tag: &AuthTag,
    ) -> Result<Vec<u8>, ArxKwError> {
        crate::memory::check_length(ciphertext.len(), Self::MAX_INPUT_LENGTH)?;
        let (k1, k2) = generate::subkeys(key)?;
        let nonce = construct_nonce(authentication_tag);
        let mut stream = util::xchacha8::new(&k2, &nonce);
        let mut p_prime = crate::memory::copy_secret(ciphertext)?;
        stream.xor_read(&mut p_prime)?;
        let t_prime = zeroize::Zeroizing::new(util::sip_array_keyed(&k1, &p_prime));
        if bool::from(t_prime.ct_eq(authentication_tag)) {
            // Equality check is done in constant time
            return Ok(std::mem::take(&mut *p_prime));
        }
        Err(ArxKwError::BadTags)
    }
}
/// The prefix specified for the GX variant in the ARX-KW paper (61 72 62 69 74 72 47 58) followed by 16 zeros
const NONCE_INIT_GX: [u8; 24] = [
    0x61, 0x72, 0x62, 0x69, 0x74, 0x72, 0x47, 0x58, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Builds the 24-byte XChaCha8 nonce for ARX-KW-8-2-4-GX.
///
/// Concatenates the eight-byte ASCII prefix `arbitrGX` (`0x6172626974724758`)
/// with the 16-byte authentication tag. Encryption and decryption call this
/// internally; applications normally only need the [`ArxKW`] methods.
///
/// ```
/// # use arx_kw::gx::construct_nonce;
/// # use arx_kw::AuthTag;
/// let mut t = AuthTag([0u8; 16]);
/// for i in (0u8..16u8) {
///     t.0[i as usize] = i;
/// }
/// // t contains [0x0, 0x1, 0x2 .. 0xf]
///
/// let nonce = construct_nonce(&t);
/// assert_eq!(nonce,
/// [0x61,0x72,0x62,0x69,0x74,0x72,0x47,0x58,0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xa,0xb,0xc,0xd,0xe,0xf]);
/// ```
/// Using the authentication tag (T) and resulting nonce (N) for GX from the test vectors included in the ARX-KW paper:
/// ```
///  extern crate hex;
/// # extern crate anyhow;
///  use hex::FromHex;
/// # use arx_kw::{
///     AuthTag,
///     gx::construct_nonce,
/// };
///
/// # fn main() -> anyhow::Result<()> {
/// let authentication_tag = AuthTag(<[u8;16]>::from_hex("016325cf6a3c4b2e3b039675e1ccbc65")?);
/// let nonce_expected = <[u8;24]>::from_hex("6172626974724758016325cf6a3c4b2e3b039675e1ccbc65")?;
/// let nonce = construct_nonce(&authentication_tag);
/// assert_eq!(nonce,nonce_expected);
/// # Ok(())
/// # }
/// ```
#[must_use]
#[inline]
pub fn construct_nonce(authentication_tag: &AuthTag) -> [u8; 24] {
    // Initialize nonce with the defined prefix followed by 16 zeros.
    let mut nonce = NONCE_INIT_GX;
    // Copy the contents of t into bytes 8 to 23 of nonce
    nonce[8..24].clone_from_slice(authentication_tag.as_ref());
    nonce
}

#[cfg(test)]
mod tests {
    extern crate hex;
    use super::*;
    use crate::assert_ct_eq;
    use anyhow::Result;
    use hex::FromHex;

    #[test]
    fn test_encrypt() -> Result<()> {
        let k = <[u8; 32]>::from_hex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )?;
        let p = <[u8; 32]>::from_hex(
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        )?;
        let t_expected = AuthTag(<[u8; 16]>::from_hex("016325cf6a3c4b2e3b039675e1ccbc65")?);
        let c_expected = <[u8; 32]>::from_hex(
            "2f83f391c97f3606ccd5709c6ee15d66cd7e65a2aeb7dc3066636e8f6b0d39c3",
        )?;
        let (c, t) = GX::encrypt(&k, &p)?;
        assert_eq!(&c, &c_expected);
        assert_ct_eq!(t, &t_expected);
        Ok(())
    }

    #[test]
    fn test_encrypt_blob() -> Result<()> {
        let k = <[u8; 32]>::from_hex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )?;
        let p = <[u8; 32]>::from_hex(
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        )?;
        let blob_expected = <[u8; 48]>::from_hex("016325cf6a3c4b2e3b039675e1ccbc652f83f391c97f3606ccd5709c6ee15d66cd7e65a2aeb7dc3066636e8f6b0d39c3")?;
        let blob = GX::encrypt_blob(&k, &p)?;
        assert_ct_eq!(blob, &blob_expected);
        Ok(())
    }

    #[test]
    fn test_decrypt_blob() -> Result<()> {
        let k = <[u8; 32]>::from_hex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )?;
        let p_expected = <[u8; 32]>::from_hex(
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        )?;
        let blob= <[u8; 48]>::from_hex("016325cf6a3c4b2e3b039675e1ccbc652f83f391c97f3606ccd5709c6ee15d66cd7e65a2aeb7dc3066636e8f6b0d39c3")?;
        let p = GX::decrypt_blob(&k, &blob)?;
        assert_ct_eq!(&p, &p_expected);
        Ok(())
    }

    #[test]
    fn test_decrypt() -> Result<()> {
        let k = <[u8; 32]>::from_hex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )?;
        let t = AuthTag(<[u8; 16]>::from_hex("016325cf6a3c4b2e3b039675e1ccbc65")?);
        let c = <[u8; 32]>::from_hex(
            "2f83f391c97f3606ccd5709c6ee15d66cd7e65a2aeb7dc3066636e8f6b0d39c3",
        )?;
        let p_expected = <[u8; 32]>::from_hex(
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        )?;
        let p = GX::decrypt(&k, &c, &t)?;
        assert_eq!(p, p_expected);
        Ok(())
    }

    /// Make sure that a bad authentication tag yields an error when decrypting
    #[test]
    fn test_bad_decrypt() -> Result<()> {
        let k = <[u8; 32]>::from_hex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )?;
        let c = <[u8; 32]>::from_hex(
            "2283f391c97f3606ccd5709c6ee15d66cd7e65a2aeb7dc3066636e8f6b0d39c3",
        )?; // First two hex digits should be 2f instead of 22
        let t_bad = AuthTag(<[u8; 16]>::from_hex("016325cf6a3c4b2e3b039675e1ccbc65")?);
        let res = GX::decrypt(&k, &c, &t_bad);
        assert!(res.is_err());
        Ok(())
    }
}
