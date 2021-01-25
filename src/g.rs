use crate::{
    generate,
    util,
    lqb,
    ArxKW,
    ArxKwError,
    InvalidLengthError,
    AuthTag,
    ConstantTimeEq
};

/// The ARX-8-2-4-G variant. Has a key length of 32 bytes and a maximum input length of 64 bytes.
/// See the `ArxKW` trait for usage.
pub struct G;
impl G {
    /// The length of the secret key used by this variant of ARX-KW, in bytes
    #[must_use]
    #[cfg(not(tarpaulin_include))]
    pub const fn key_length() -> usize {
        32
    }
    
    /// Returns the maximum length in bytes for the input to `G::encrypt`  and `G::decrypt` 
    ///
    /// ---
    /// This is the same for the plaintext input when encrypting and ciphertext input when
    /// decrypting, but is **not** the same for all variants of ARX-KW. Specifically, the *E* and *G*
    /// variants are defined only for plaintext/ciphertext inputs of no more than 512 bits, the length
    /// of a ChaCha Block, whereas *EX* and *GX* do not have this limitation.
    #[cfg(not(tarpaulin_include))]
    #[must_use]
    pub const fn max_input_length() -> usize {
        64
    }
}


impl ArxKW for G {
    type Key = [u8; Self::key_length()];
    fn encrypt(key: &Self::Key, plaintext: &[u8]) -> Result<(Vec<u8>, AuthTag), ArxKwError> {
        if plaintext.len() > Self::max_input_length() {
            Err(ArxKwError::InvalidLength(InvalidLengthError::UpTo(plaintext.len(), Self::max_input_length())))
        } else {
            let (k1,k2) = generate::subkeys(key)?;
            let authentication_tag = util::sip_array_keyed(&k1, plaintext);
            let ciphertext = lqb::chacha8_encrypt(&k2, authentication_tag.as_ref(), plaintext)?;
            Ok((ciphertext, authentication_tag))
        }
    }
    

    fn decrypt(key: &Self::Key, ciphertext: &[u8], authentication_tag: &AuthTag) -> Result<Vec<u8>, ArxKwError> {
        if ciphertext.len() > Self::max_input_length() {
            Err(ArxKwError::InvalidLength(InvalidLengthError::UpTo(ciphertext.len(), Self::max_input_length())))
        } else {
            let (k1,k2) = generate::subkeys(key)?;
            let p_prime = lqb::chacha8_encrypt(&k2, authentication_tag.as_ref(), ciphertext)?;
            let t_prime = util::sip_array_keyed(&k1, &p_prime);
            if bool::from(t_prime.ct_eq(authentication_tag)) {
                return Ok(p_prime);
            }
            Err(ArxKwError::BadTags(t_prime, *authentication_tag))
        }
    }
}


#[cfg(test)]
mod tests {
    use hex::FromHex;
    use anyhow::Result;
    use super::{G,ArxKW};
    use crate::{AuthTag,assert_ct_eq,ConstantTimeEq};

    #[test]
    fn test_encrypt() -> Result<()> {

        let k = <[u8;32]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")?;
        let p = <[u8;32]>::from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")?;
        let p_bad = [0xaf; 69];
        let res = G::encrypt(&k, &p_bad);
        assert!(res.is_err());
        let t_expected = AuthTag(<[u8;16]>::from_hex("016325cf6a3c4b2e3b039675e1ccbc65")?);
        let c_expected = <[u8;32]>::from_hex("f63830f5148a039b6aacc4b9b6bc281d7704d906e4b5d91e045a62cdfc25eb10")?;
        let (c,t) = G::encrypt(&k,&p)?;
        assert_ct_eq!(c, &c_expected);
        assert_ct_eq!(t, &t_expected);
        Ok(())
    }

    #[test]
    fn test_decrypt() -> Result<()> {
        let k = <[u8;32]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")?;
        let p_expected = <[u8;32]>::from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")?;
        let p_bad = [0xaf; 69];
        let t_expected = AuthTag(<[u8;16]>::from_hex("016325cf6a3c4b2e3b039675e1ccbc65")?);
        let res = G::decrypt(&k, &p_bad, &t_expected);
        assert!(res.is_err());
        let c = <[u8;32]>::from_hex("f63830f5148a039b6aacc4b9b6bc281d7704d906e4b5d91e045a62cdfc25eb10")?;
        let p = G::decrypt(&k,&c,&t_expected)?;
        assert_eq!(p, p_expected);
        Ok(())
    }

    #[test]
    fn test_decrypt_bad() -> Result<()> {
        let k = <[u8;32]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")?;
        let p_expected = <[u8;32]>::from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")?;
        let c = <[u8;32]>::from_hex("f63830f5148a039b6aacc4b9b6bc281d7704d906e4b5d91e045a62cdfc25eb10")?;
        let c_bad = [0xaf; 69];
        let t_expected = AuthTag(<[u8;16]>::from_hex("016325cf6a3c4b2e3b039675e1ccbc65")?);
        let res = G::decrypt(&k, &c_bad, &t_expected);
        assert!(res.is_err());
        let p = G::decrypt(&k,&c,&t_expected)?;
        assert_eq!(p, p_expected);
        let t_bad = AuthTag(<[u8;16]>::from_hex("dab325cf6a3c4b2e3b039675e1ccbc65")?); // first 3 hex digits should be 016
        let res = G::decrypt(&k, &c, &t_bad);
        assert!(res.is_err());
        Ok(())
    }
}
