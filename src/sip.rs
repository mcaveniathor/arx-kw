//! SipHash-2-4 with 128-bit output and zeroizing state.
//! Follows the SipHash reference's 128-bit finalization (0xee / 0xdd domains).
use crate::AuthTag;
use zeroize::Zeroizing;

const fn round(v: &mut [u64; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(13) ^ v[0];
    v[0] = v[0].rotate_left(32);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(16) ^ v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(21) ^ v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(17) ^ v[2];
    v[2] = v[2].rotate_left(32);
}

const fn compress(v: &mut [u64; 4], word: u64) {
    v[3] ^= word;
    round(v);
    round(v);
    v[0] ^= word;
}

pub fn hash(key: &[u8; 16], input: &[u8]) -> AuthTag {
    let keys = Zeroizing::new([
        u64::from_le_bytes(*array_ref![key, 0, 8]),
        u64::from_le_bytes(*array_ref![key, 8, 8]),
    ]);
    let mut v = Zeroizing::new([
        keys[0] ^ 0x736f_6d65_7073_6575,
        keys[1] ^ 0x646f_7261_6e64_6f83,
        keys[0] ^ 0x6c79_6765_6e65_7261,
        keys[1] ^ 0x7465_6462_7974_6573,
    ]);
    let (chunks, remainder) = input.as_chunks::<8>();
    for chunk in chunks {
        let word = Zeroizing::new(u64::from_le_bytes(*chunk));
        compress(&mut v, *word);
    }
    let mut tail = Zeroizing::new([0u8; 8]);
    tail[..remainder.len()].copy_from_slice(remainder);
    tail[7] = input.len().to_le_bytes()[0];
    compress(&mut v, u64::from_le_bytes(*tail));
    v[2] ^= 0xee;
    for _ in 0..4 {
        round(&mut v);
    }
    let mut output = [0u8; 16];
    output[..8].copy_from_slice(&(v[0] ^ v[1] ^ v[2] ^ v[3]).to_le_bytes());
    v[1] ^= 0xdd;
    for _ in 0..4 {
        round(&mut v);
    }
    output[8..].copy_from_slice(&(v[0] ^ v[1] ^ v[2] ^ v[3]).to_le_bytes());
    AuthTag(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use siphasher::sip128::SipHasher24;

    #[test]
    fn matches_reference_across_lengths_and_keys() {
        for seed in [0u8, 1, 42, 255] {
            let key = [seed; 16];
            for length in 0usize..=1024 {
                let input: Vec<u8> = (0u8..=250).cycle().take(length).collect();
                let expected = SipHasher24::new_with_key(&key).hash(&input).as_bytes();
                assert_eq!(
                    hash(&key, &input).0,
                    expected,
                    "seed={seed} length={length}"
                );
            }
        }
    }
}
