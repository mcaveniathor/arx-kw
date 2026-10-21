use crate::AuthTag;

/// Computes SipHash-2-4-128 with zeroizing working state.
pub fn sip_array_keyed(key: &[u8; 16], msg: &[u8]) -> AuthTag {
    crate::sip::hash(key, msg)
}

#[cfg(any(feature = "ex", feature = "gx"))]
pub mod xchacha8 {
    use crate::lqb::{new_chacha8_with_counter, ChaCha8Stream};
    use zeroize::Zeroize;

    /// HChaCha8 followed by ChaCha8 with the original 64-bit counter layout.
    pub fn new(key: &[u8; 32], nonce: &[u8; 24]) -> ChaCha8Stream {
        let prefix = array_ref![nonce, 0, 16];
        let mut subkey = chacha20::hchacha::<chacha20::R8>(key.into(), prefix.into());
        let stream = new_chacha8_with_counter(subkey.as_ref(), [0; 8], *array_ref![nonce, 16, 8]);
        subkey.as_mut_slice().zeroize();
        stream
    }
}
