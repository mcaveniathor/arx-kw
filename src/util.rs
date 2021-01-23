use siphasher::sip128::{SipHasher24,Hasher128};
use std::hash::Hasher;
use crate::{AuthTag};

/// Hashes a message using SipHash2-4 with a 128-bit output
///
///Creates a Sip-2-4 instance keyed with the contents of `key` and set to output 128 bits of data
///and uses it to hash msg
pub fn sip_array_keyed(key: &[u8; 16], msg: &[u8]) -> AuthTag {
    let (sip1_bytes, sip2_bytes) = array_refs![key,8,8]; // Array reference equivalent of (&key[..8], &key[8..16])
    let (sip1, sip2) = (u64::from_le_bytes(*sip1_bytes), u64::from_le_bytes(*sip2_bytes));
    let mut sip_hasher = SipHasher24::new_with_keys(sip1,sip2);
    sip_hasher.write(msg);
    AuthTag(sip_hasher.finish128().as_bytes())
}

/// Contains utilities shared by the EX and GX variants of ARX-KW
pub mod xchacha8 {
    use chacha::ChaCha;
    use byteorder::{ByteOrder,LittleEndian};
    use crate::lqb::ChaChaLQB;

    /// Creates an `XChaCha8` stream (8 rounds with a 24-byte nonce) and the counter set to 0 
    /// Initialized like an `XChaCha20` but with 8 rounds for both the intially generated ChaCha block and
    /// the stream constructed with it.
    #[must_use] pub fn new(key: &[u8; 32], nonce: &[u8; 24]) -> ChaCha {
            let mut st = [
                0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574,
                LittleEndian::read_u32(&key[ 0.. 4]),
                LittleEndian::read_u32(&key[ 4.. 8]),
                LittleEndian::read_u32(&key[ 8..12]),
                LittleEndian::read_u32(&key[12..16]),
                LittleEndian::read_u32(&key[16..20]),
            LittleEndian::read_u32(&key[20..24]),
            LittleEndian::read_u32(&key[24..28]),
            LittleEndian::read_u32(&key[28..32]),
            LittleEndian::read_u32(&nonce[ 0.. 4]),
            LittleEndian::read_u32(&nonce[ 4.. 8]),
            LittleEndian::read_u32(&nonce[ 8..12]),
            LittleEndian::read_u32(&nonce[12..16]),
        ];
        chacha::permute(8, &mut st);

        let tmp = ChaChaLQB {
            input: [
                0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574,
                st[ 0], st[ 1], st[ 2], st[ 3],
                st[12], st[13], st[14], st[15],
                0, 0,
                LittleEndian::read_u32(&nonce[16..20]),
                LittleEndian::read_u32(&nonce[20..24]),
            ],
            output: [0; 64],
            offset: 255,
            large_block_counter: true,
            rounds: 8,
        };
        let cc: ChaCha = unsafe {
            std::mem::transmute(tmp)
        };
        cc
    }
    

    
    
}
