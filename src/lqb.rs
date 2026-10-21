use crate::ArxKwError;
use chacha20::{
    cipher::{KeyIvInit, StreamCipherCore},
    variants::Ietf,
    ChaChaCore, R8,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ChaCha8 with a 64-bit counter, implemented using RustCrypto's public core API.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ChaCha8Stream {
    key: [u8; 32],
    nonce: [u8; 8],
    counter: u64,
    block: [u8; 64],
    offset: usize,
    exhausted: bool,
}

impl ChaCha8Stream {
    pub fn xor_read(&mut self, output: &mut [u8]) -> Result<(), ArxKwError> {
        let buffered = 64 - self.offset;
        let blocks = if self.exhausted {
            0
        } else {
            (1u128 << 64) - u128::from(self.counter)
        };
        if output.len() as u128 > buffered as u128 + blocks * 64 {
            return Err(ArxKwError::ChaChaError("ChaCha8 stream exhausted".into()));
        }
        for byte in output {
            if self.offset == 64 {
                // An IETF block's first nonce word occupies the original counter's
                // high word. A fresh core for each block preserves the full DJB
                // 64-bit counter, including carry and its final block.
                let counter = self.counter.to_le_bytes();
                let mut nonce = [0u8; 12];
                nonce[..4].copy_from_slice(&counter[4..]);
                nonce[4..].copy_from_slice(&self.nonce);
                let mut core = ChaChaCore::<R8, Ietf>::new((&self.key).into(), (&nonce).into());
                core.set_block_pos(u32::from_le_bytes([
                    counter[0], counter[1], counter[2], counter[3],
                ]));
                core.write_keystream_block((&mut self.block).into());
                self.offset = 0;
                if let Some(next) = self.counter.checked_add(1) {
                    self.counter = next;
                } else {
                    self.exhausted = true;
                }
            }
            *byte ^= self.block[self.offset];
            self.offset += 1;
        }
        Ok(())
    }
}

#[cfg(any(feature = "e", feature = "g"))]
pub fn chacha8_encrypt(key: &[u8; 32], lqb: &[u8; 16], msg: &[u8]) -> Result<Vec<u8>, ArxKwError> {
    let (counter, nonce) = array_refs![lqb, 8, 8];
    let mut stream = new_chacha8_with_counter(key, *counter, *nonce);
    let mut output = crate::memory::copy_secret(msg)?;
    stream.xor_read(&mut output)?;
    Ok(std::mem::take(&mut *output))
}

pub const fn new_chacha8_with_counter(
    key: &[u8; 32],
    counter: [u8; 8],
    nonce: [u8; 8],
) -> ChaCha8Stream {
    ChaCha8Stream {
        key: *key,
        nonce,
        counter: u64::from_le_bytes(counter),
        block: [0; 64],
        offset: 64,
        exhausted: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha::KeyStream;

    #[test]
    fn matches_public_chacha8_across_blocks_and_chunk_sizes() {
        let key = [0x42; 32];
        let nonce = [0x19; 8];
        let mut expected = vec![0x5a; 257];
        chacha::ChaCha::new_chacha8(&key, &nonce)
            .xor_read(&mut expected)
            .unwrap();
        let mut actual = vec![0x5a; 257];
        let mut stream = new_chacha8_with_counter(&key, [0; 8], nonce);
        for part in actual.chunks_mut(17) {
            stream.xor_read(part).unwrap();
        }
        assert_eq!(actual, expected);
    }

    #[test]
    fn counter_carries_into_high_word() {
        use chacha::SeekableKeyStream;
        let key = [0x42; 32];
        let nonce = [0x19; 8];
        let counter = u64::from(u32::MAX);
        let mut expected = [0u8; 129];
        let mut reference = chacha::ChaCha::new_chacha8(&key, &nonce);
        reference.seek_to(counter * 64).unwrap();
        reference.xor_read(&mut expected).unwrap();
        let mut actual = [0u8; 129];
        new_chacha8_with_counter(&key, counter.to_le_bytes(), nonce)
            .xor_read(&mut actual)
            .unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn last_counter_block_is_usable_without_wrapping() {
        let mut stream = new_chacha8_with_counter(&[0; 32], u64::MAX.to_le_bytes(), [0; 8]);
        let mut too_long = [0x5a; 65];
        assert!(stream.xor_read(&mut too_long).is_err());
        assert_eq!(too_long, [0x5a; 65]);
        let mut actual = [0u8; 64];
        stream.xor_read(&mut actual[..1]).unwrap();
        stream.xor_read(&mut actual[1..]).unwrap();
        let mut reference = [
            0x6170_7865,
            0x3320_646e,
            0x7962_2d32,
            0x6b20_6574,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            u32::MAX,
            u32::MAX,
            0,
            0,
        ];
        chacha::permute_and_add(8, &mut reference);
        let expected: Vec<u8> = reference
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        assert_eq!(actual.as_slice(), expected);
        stream.xor_read(&mut []).unwrap();
        assert!(stream.xor_read(&mut [0; 1]).is_err());
    }
}

#[cfg(test)]
mod zeroization_tests {
    use super::*;
    #[test]
    fn owned_stream_state_is_wiped() {
        fn requires_wipe<T: ZeroizeOnDrop>() {}
        requires_wipe::<ChaCha8Stream>();
        let mut stream = new_chacha8_with_counter(&[0x42; 32], [0; 8], [0x24; 8]);
        stream.xor_read(&mut [0; 1]).unwrap();
        stream.zeroize();
        assert_eq!(stream.key, [0; 32]);
        assert_eq!(stream.block, [0; 64]);
        assert_eq!(stream.nonce, [0; 8]);
    }
}
