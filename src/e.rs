use crate::{
    util,
    AuthTag,
    lqb,
    ArxKW,
    ArxKwError,
    InvalidLengthError,
    ConstantTimeEq
};

/// The ARX-8-2-4-E variant. Has a key length of 48 bytes and a maximum input length of 64 bytes.
/// See the [`ArxKW`] trait for usage.
pub struct E;
impl E {
    #[must_use]
    #[cfg(not(tarpaulin_include))]
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

    #[cfg(not(tarpaulin_include))]
    pub const fn max_input_length() -> usize {
        64
    }

}

impl ArxKW for E {
    type Key = [u8; Self::key_length()];
    fn encrypt(key: &Self::Key, plaintext: &[u8]) -> Result<(Vec<u8>, AuthTag), ArxKwError> {
        if plaintext.len() > Self::max_input_length() {
            Err(ArxKwError::InvalidLength(InvalidLengthError::UpTo(plaintext.len(), Self::max_input_length())))
        } else {
            let (k1,k2) = array_refs![key,16,32];
            let authentication_tag = util::sip_array_keyed(k1, plaintext);
            let ciphertext = lqb::chacha8_encrypt(k2, authentication_tag.as_ref(), plaintext)?;
            Ok((ciphertext, authentication_tag))
        }
    }
    
    fn decrypt(key: &Self::Key, ciphertext: &[u8], authentication_tag: &AuthTag) -> Result<Vec<u8>, ArxKwError> {
        if ciphertext.len() > Self::max_input_length() {
            Err(ArxKwError::InvalidLength(InvalidLengthError::UpTo(ciphertext.len(), Self::max_input_length())))
        } else {
            let (k1,k2) = array_refs![key,16,32];
            let p_prime = lqb::chacha8_encrypt(k2, authentication_tag.as_ref(), ciphertext)?;
            let t_prime = util::sip_array_keyed(k1, &p_prime);
            if bool::from(t_prime.ct_eq(authentication_tag)) { // Compare AuthTags in constant time
                return Ok(p_prime);
            }
            Err(ArxKwError::BadTags(t_prime, *authentication_tag))
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate hex;
    use anyhow::Result;
    use hex::FromHex;
    use super::{ArxKW,E};
    use crate::{ConstantTimeEq,assert_ct_eq,AuthTag};
    

    /*
     * Tests using the Test Vectors provided in the ARX-KW paper 2020-059 by Sato Shinichi
     */

    #[test]
    fn test_encrypt() -> Result<()> {
        let k = <[u8; 48]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f")?;
        let p = <[u8; 32]>::from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")?;
        let p_bad = [0xaf; 69];
        let res = E::encrypt(&k, &p_bad);
        assert!(res.is_err());
        let t_expected = AuthTag(<[u8; 16]>::from_hex("c4f21d3b4dbcc566c3a73bbc59790f2f")?);
        let c_expected = <[u8; 32]>::from_hex("e6457d24abaf7c2ebdb91416a18366d31a66db61a4e45c9f42a119c353bb1eb1")?;
        let (c,t) = E::encrypt(&k, &p)?;
        assert_eq!(&c, &c_expected);
        assert_ct_eq!(t, &t_expected);
        Ok(())
    }

    #[test]
    fn test_encrypt_blob() -> Result<()> {
        let k = <[u8; 48]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f")?;
        let p = <[u8; 32]>::from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")?;
        let blob_expected = <[u8; 48]>::from_hex("c4f21d3b4dbcc566c3a73bbc59790f2fe6457d24abaf7c2ebdb91416a18366d31a66db61a4e45c9f42a119c353bb1eb1")?;
        let blob = E::encrypt_blob(&k, &p)?;
        assert_ct_eq!(blob, &blob_expected);
        Ok(())
    }


    #[test]
    fn test_decrypt() -> Result<()> {
        let c = <[u8; 32]>::from_hex("e6457d24abaf7c2ebdb91416a18366d31a66db61a4e45c9f42a119c353bb1eb1")?;
        let k = <[u8; 48]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f")?;
        let t = AuthTag(<[u8; 16]>::from_hex("c4f21d3b4dbcc566c3a73bbc59790f2f")?);
        let p_expected = <[u8;32]>::from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")?;
        let p = E::decrypt(&k, &c, &t)?;
        assert_ct_eq!(p, &p_expected);
        Ok(())
    }


    #[test]
    fn test_decrypt_blob() -> Result<()> {
        let k = <[u8; 48]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f")?;
        let blob = <[u8; 48]>::from_hex("c4f21d3b4dbcc566c3a73bbc59790f2fe6457d24abaf7c2ebdb91416a18366d31a66db61a4e45c9f42a119c353bb1eb1")?;
        let p_expected = <[u8;32]>::from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")?;
        let p = E::decrypt_blob(&k, &blob)?;
        assert_ct_eq!(p, &p_expected);
        Ok(())
    }


    #[test]
    fn test_decrypt_bad() -> Result<()> {
        let k = <[u8; 48]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f")?;
        let c = <[u8; 32]>::from_hex("e6457d24abaf7c2ebdb91416a18366d31a66db61a4e45c9f42a119c353bb1eb1")?;
        let c_bad = [0xbb; 69];
        let t = AuthTag(<[u8; 16]>::from_hex("c4f21d3b4dbcc566c3a73bbc59790f2f")?); // good tag
        let res = E::decrypt(&k, &c_bad, &t);
        assert!(res.is_err());
        let t_bad = AuthTag(<[u8; 16]>::from_hex("c4f21d3b4dbcc566c3a73bbc59790fff")?); // last 2 hex digits should be 2f
        let res = E::decrypt(&k, &c, &t_bad);
        assert!(res.is_err());
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
