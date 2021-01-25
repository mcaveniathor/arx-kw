use chacha::KeyStream;
use crate::{util,generate,ArxKW,ArxKwError,AuthTag};
use crate::ConstantTimeEq;

/// The ARX-8-2-4-GX variant. Has a key length of 32 bytes and no maximum input length. 
/// See the `ArxKW` trait for usage.
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
    fn encrypt(key: &Self::Key, plaintext: &[u8]) -> Result<(Vec<u8>, AuthTag), ArxKwError> {
        let (k1,k2) = generate::subkeys(key)?;
        let authentication_tag = util::sip_array_keyed(&k1, plaintext);
        let nonce = construct_nonce(&authentication_tag);
        let mut stream = util::xchacha8::new(&k2,&nonce);
        let mut ciphertext = plaintext.to_vec();
        stream.xor_read(&mut ciphertext).map_err(|e| ArxKwError::ChaChaError(format!("{:?}: X",e)))?;
        Ok((ciphertext,authentication_tag))
    }
    fn decrypt(key: &Self::Key, ciphertext: &[u8], authentication_tag: &AuthTag) -> Result<Vec<u8>, ArxKwError> {
        let (k1,k2) = generate::subkeys(key)?;
        let nonce = construct_nonce(authentication_tag);
        let mut stream = util::xchacha8::new(&k2, &nonce);
        let mut p_prime = ciphertext.to_vec();
        stream.xor_read(&mut p_prime).map_err(|e| ArxKwError::ChaChaError(format!("{:?}: X",e)))?;
        let t_prime = util::sip_array_keyed(&k1, &p_prime);
        if bool::from(t_prime.ct_eq(authentication_tag)) { // Equality check is done in constant time
            Ok(p_prime)
        }
        else {
            Err(ArxKwError::BadTags(t_prime, *authentication_tag))
        }
    }

}
/// The prefix specified for the GX variant in the ARX-KW paper (61 72 62 69 74 72 45 58) followed by 16 zeros
const NONCE_INIT_GX: [u8;24] = [0x61, 0x72, 0x62, 0x69, 0x74, 0x72, 0x47, 0x58,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];

/// Concatenates an authentication tag to the GX prefix defined for ARX-KW-8-2-4-GX and returns the resulting intermediate nonce
///
/// # Please Read:
///
/// **There is probably not much of a reason to use this outside of this library unless you're writing a new ARX-KW implementation**.
///
///
/// I am making it public largely to provide a look into how ARX-KW works (and because I already wrote documentation and doctests for it). 
///
/// Because the nonce is created and consumed within the key wrapping process itself (as opposed to the authentication tag, stored alongside the wrapped key) and the API exposed by this crate 
/// uses fixed length (ie checked at compile time) input for keys and authentication tags which are of different size than that of the nonce,
/// I hope (perhaps naïvely) that misuse of this function is too awkward to take place. 
/// That said, it is useful as an example and could be re-used in another crate looking to implement ARX-KW-8-2-4-GX.
///
/// ---
/// ## With that out of the way:
///
/// The prefix is the ASCII encoding of the string `arbitrGX`, or 0x6172626974724758, as defined
/// for ARX-KW-8-2-4-GX in the paper by Sato Shinichi.
///
/// The value returned is a fixed-length array of 192 bits suitable for use as a nonce with
/// the `XChaCha8` stream cipher when using the GX variant of ARX-KW 
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
pub fn construct_nonce(authentication_tag: &AuthTag) -> [u8;24] {
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
        let k = <[u8; 32]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")?;
        let p = <[u8; 32]>::from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")?;
        let t_expected = AuthTag(<[u8; 16]>::from_hex("016325cf6a3c4b2e3b039675e1ccbc65")?);
        let c_expected = <[u8; 32]>::from_hex("2f83f391c97f3606ccd5709c6ee15d66cd7e65a2aeb7dc3066636e8f6b0d39c3")?;
        println!("{}","2f83f391c97f3606ccd5709c6ee15d66cd7e65a2aeb7dc3066636e8f6b0d39c3".len());
        let (c,t) = GX::encrypt(&k, &p)?;
        assert_eq!(&c.to_vec(), &c_expected);
        assert_ct_eq!(t, &t_expected);
        Ok(())
    }
    #[test]
    fn test_decrypt() -> Result<()> {
        let k = <[u8; 32]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")?;
        let t = AuthTag(<[u8; 16]>::from_hex("016325cf6a3c4b2e3b039675e1ccbc65")?);
        let c = <[u8; 32]>::from_hex("2f83f391c97f3606ccd5709c6ee15d66cd7e65a2aeb7dc3066636e8f6b0d39c3")?;
        let p_expected = <[u8; 32]>::from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")?;
        let p = GX::decrypt(&k, &c, &t)?;
        assert_eq!(p, p_expected);
        Ok(())
    }

   
}


