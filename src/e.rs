use crate::{util,AuthTag,lqb,ArxKW,ArxKwError,InvalidLengthError};

pub struct E;
impl E {
    #[must_use]
    /// The length in bytes of the secret key used by this variant of ARX-KW
    pub const fn key_length() -> usize {
        48
    }

    #[must_use]
    /// Returns the maximum length in bytes for the input to `G::encrypt`  and `G::decrypt` 
    ///
    /// ---
    /// This is the same for the plaintext input when encrypting and ciphertext input when
    /// decrypting, but is **not** the same for all variants of ARX-KW. Specifically, the *E* and *G*
    /// variants are defined only for plaintext/ciphertext inputs of no more than 512 bits, the length
    /// of a ChaCha Block, whereas *EX* and *GX* do not have this limitation.

    pub const fn max_input_length() -> usize {
        64
    }

}

impl ArxKW for E {
    type Key = [u8; Self::key_length()];
    fn encrypt(key: &Self::Key, plaintext: &[u8]) -> Result<(Vec<u8>, AuthTag), ArxKwError> {
        if plaintext.len() > 48 {
            Err(ArxKwError::InvalidLength(InvalidLengthError::UpTo(plaintext.len(), 48)))
        } else {
            let (k1,k2) = array_refs![key,16,32];
            let authentication_tag = util::sip_array_keyed(k1, plaintext);
            let ciphertext = lqb::chacha8_encrypt(k2, &authentication_tag, plaintext)?;
            Ok((ciphertext, authentication_tag))
        }
    }
    
    fn decrypt(key: &Self::Key, ciphertext: &[u8], authentication_tag: &AuthTag) -> Result<Vec<u8>, ArxKwError> {
        if ciphertext.len() > 48 {
            Err(ArxKwError::InvalidLength(InvalidLengthError::UpTo(ciphertext.len(), 48_usize)))
        } else {
            let (k1,k2) = array_refs![key,16,32];
            let p_prime = lqb::chacha8_encrypt(k2, authentication_tag, ciphertext)?;
            let t_prime = util::sip_array_keyed(k1, &p_prime);
            if &t_prime == authentication_tag {
                Ok(p_prime)
            }
            else {
                Err(ArxKwError::BadTags(t_prime, *authentication_tag))
            }
        }
    }
}

/*
/// Encrypts p in place and returns the authentication tag
pub fn encrypt_in_place(k: &[u8; KEY_LEN], mut p: &mut[u8]) -> Result<[u8;AUTHENTICATION_TAG_LEN]> {
    if p.len() > MAX_MESSAGE_LEN {
        bail!("Invalid length for plaintext input to ARX-KW-8-2-4-E encryption: {} bytes (Maximum: {} bytes)", p.len(), MAX_MESSAGE_LEN);
    }
    let (k1,k2) = array_refs![k, K1_LEN, K2_LEN];
    let t = util::sip_array_keyed(k1, p).as_bytes();
    lqb::chacha8_lqb_mut(k2,&t,&mut p)?;
    Ok(t)
}

/// Decrypts c in place
pub fn decrypt_in_place(k: &[u8;KEY_LEN], mut c: &mut [u8], t: &[u8;AUTHENTICATION_TAG_LEN]) -> Result<()> {
    // ARX-KW-8-2-4-E yields a ciphertext no longer than 512 bits
    if c.len() > MAX_MESSAGE_LEN {
        bail!("Invalid length for ciphertext input to ARX-KW-8-2-4-E decryption: {} bytes (Maximum: {} bytes)", c.len(), MAX_MESSAGE_LEN);
    }
    let (k1,k2) = array_refs![k, K1_LEN, K2_LEN];  // Array reference equivalent of (&k[0..16], &k[16..48])
    lqb::chacha8_lqb_mut(k2,t,&mut c)?;
    let t_prime = util::sip_array_keyed(k1,c).as_bytes();
    if bool::from(t_prime.ct_eq(t)) {
        Ok(())
    }
    else {
        bail!("Decryption failed: authentication tags do not match.");
    }
}
*/

#[cfg(test)]
mod tests {
    extern crate hex;
    use anyhow::Result;
    use hex::FromHex;
    use super::{ArxKW,E};
    

    /*
     * Tests using the Test Vectors provided in the ARX-KW paper 2020-059 by Sato Shinichi
     */

    #[test]
    fn test_encrypt() -> Result<()> {
        let k = <[u8; 48]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f")?;
        let p = <[u8; 32]>::from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")?;
        let t_expected = <[u8; 16]>::from_hex("c4f21d3b4dbcc566c3a73bbc59790f2f")?;
        let c_expected = <[u8; 32]>::from_hex("e6457d24abaf7c2ebdb91416a18366d31a66db61a4e45c9f42a119c353bb1eb1")?;
        let (c,t) = E::encrypt(&k, &p)?;
        assert_eq!(&c, &c_expected);
        assert_eq!(&t, &t_expected);
        Ok(())
    }
    #[test]
    fn test_decrypt() -> Result<()> {

        let c = <[u8; 32]>::from_hex("e6457d24abaf7c2ebdb91416a18366d31a66db61a4e45c9f42a119c353bb1eb1")?;
        let k = <[u8; 48]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f")?;
        let t = <[u8; 16]>::from_hex("c4f21d3b4dbcc566c3a73bbc59790f2f")?;
        let p_expected = <[u8;32]>::from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")?;
        let p = E::decrypt(&k, &c, &t)?;
        assert_eq!(p, p_expected);
        Ok(())
    }
    /*
    #[test]
    fn test_encrypt_in_place() -> Result<()> {
        let k = <[u8; 48]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f")?;
        let mut buf = <[u8; 32]>::from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")?;
        let t_expected = <[u8; 16]>::from_hex("c4f21d3b4dbcc566c3a73bbc59790f2f")?;
        let c_expected = <[u8; 32]>::from_hex("e6457d24abaf7c2ebdb91416a18366d31a66db61a4e45c9f42a119c353bb1eb1")?;
        let t = encrypt_in_place(array_ref![k,0,48], &mut buf)?;
        assert_eq!(&buf, &c_expected);
        assert_eq!(&t.to_vec(), &t_expected);
        Ok(())
    }
    #[test]
    fn test_decrypt_in_place() -> Result<()> {
        let mut buf = <[u8; 32]>::from_hex("e6457d24abaf7c2ebdb91416a18366d31a66db61a4e45c9f42a119c353bb1eb1")?;
        let k = <[u8; 48]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f")?;
        let t = <[u8; 16]>::from_hex("c4f21d3b4dbcc566c3a73bbc59790f2f")?;
        let p_expected = <[u8;32]>::from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")?;
        decrypt_in_place(&k, &mut buf, &t)?;
        assert_eq!(buf, p_expected);
        Ok(())
    }
    */

}
