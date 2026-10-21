/// Contains utilities shared by the G and GX variants of ARX-KW
///
/// The 'G' in those two variants stands for **G**enerated -- as opposed to **E**xtended -- key, as both variants generate the
/// subkeys K1 and K2
use crate::lqb;
use crate::ArxKwError;

/// 384 bits worth of zeros, used in the G and GX variants of ARX-KW
///
/// This is used as the input to the ChaCha8 stream (with an all-zero LQB) used to obtain the subkeys k1 and k2 in the G and GX variants
const ZERO_384: [u8; 48] = [0_u8; 48];
const ZERO_NONCE: [u8; 8] = [0_u8; 8];

type Subkeys = (zeroize::Zeroizing<[u8; 16]>, zeroize::Zeroizing<[u8; 32]>);

/// Generates the data used as the subkeys K1 and K2 in the G and GX variants
///
/// This is done by encrypting a 384-bit all-zero message using a ChaCha8 stream initialized with
/// key `k` and an all-zero LQB
pub fn subkeys(k: &[u8; 32]) -> Result<Subkeys, ArxKwError> {
    let mut stream = lqb::new_chacha8_with_counter(k, ZERO_NONCE, ZERO_NONCE);
    let mut g = zeroize::Zeroizing::new(ZERO_384);
    stream.xor_read(&mut *g)?;
    let (k1, k2) = array_refs![&*g, 16, 32];
    Ok((zeroize::Zeroizing::new(*k1), zeroize::Zeroizing::new(*k2)))
}
