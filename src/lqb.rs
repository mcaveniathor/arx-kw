use chacha::ChaCha;
use byteorder::{ByteOrder,LittleEndian};
use chacha::KeyStream;
use crate::{ArxKwError};

/// A wrapper type that exists solely to allow instantiation of chacha::ChaCha structs with their private fields. The
/// related functions return chacha::ChaCha 
/// TODO see if the maintainers of chacha would accept the functions below (simply adding the counter parameter to the new_chacha* functions) in their library
/// so I can do away with the unsafe blocks
pub struct ChaChaLQB {
    pub input: [u32; 16],
    pub output: [u8; 64],
    pub offset: u8,
    pub rounds: u8,
    pub large_block_counter: bool,
}

/// Instantiates a ChaCha8 stream with the given key and lower quarter block (LQB) initialized to the 128-bit value
/// passed as the parameter `lqb`, then  XORs the keystream with msg **in-place**, returning an error
/// if the end of the stream is reached.
fn _chacha8_encrypt_mut(key: &[u8;32], lqb: &[u8;16], mut msg: &mut [u8]) -> Result<(),ArxKwError> {
    let (counter, nonce) = array_refs![lqb, 8,8]; // Array reference equivalent of (&lqb[..8], &lqb[8..16])
    let mut stream = new_chacha8_with_counter(key, *counter, *nonce);
    stream.xor_read(&mut msg).map_err(|_| ArxKwError::ChaChaError("".to_string()))
}

/// Instantiates a ChaCha stream with the given key and lower quarter block (LQB) initialized to the 128-bit value
/// passed as the parameter `lqb`, then  XORs the keystream with msg, returning an error
/// if the end of the stream is reached.
pub fn chacha8_encrypt(key: &[u8;32], lqb: &[u8;16], msg: &[u8]) -> Result<Vec<u8>,ArxKwError> {
    let mut tmp = msg.to_vec();
    let (counter, nonce) = array_refs![lqb, 8,8]; // Array reference equivalent of (&lqb[..8], &lqb[8..16])
    let mut stream = new_chacha8_with_counter(key, *counter, *nonce);
    stream.xor_read(&mut tmp).map_err(|_| ArxKwError::ChaChaError("".to_string()))?;
    Ok(tmp)
}


/// Creates a ChaCha8 stream with the lower quarter block (LQB) of the ChaCha matrix instantiated
/// with two 32-bit little endian words read from `counter` and two from `nonce`. If counter
/// is 0x00000000 then this is functionally identical to a typical ChaCha8 instance.
pub fn new_chacha8_with_counter(key: &[u8; 32], counter: [u8;8], nonce: [u8; 8]) -> ChaCha {
    let tmp = ChaChaLQB {
        input: [
            0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574,
            LittleEndian::read_u32(&key[ 0.. 4]),
            LittleEndian::read_u32(&key[ 4.. 8]),
            LittleEndian::read_u32(&key[ 8..12]),
            LittleEndian::read_u32(&key[12..16]),
            LittleEndian::read_u32(&key[16..20]),
            LittleEndian::read_u32(&key[20..24]),
            LittleEndian::read_u32(&key[24..28]),
            LittleEndian::read_u32(&key[28..32]),

            // These 64 bytes used for the counter would typically be set to zero in a normal instantiation of ChaCha20,
            // but ARX-KW operates by treating the nonce and counter as a single 128 bit number and
            // instantiating the lower quarter block (LQB), or last four words of the 16-word ChaCha
            // matrix (used for the counter and nonce)
            LittleEndian::read_u32(&counter[ 0.. 4]), // LQB
            LittleEndian::read_u32(&counter[ 4.. 8]), // LQB
            LittleEndian::read_u32(&nonce[ 0.. 4]), // LQB
            LittleEndian::read_u32(&nonce[ 4.. 8]), // LQB
        ],
        output: [0; 64],
        offset: 255,
        large_block_counter: true,
        rounds: 8, // ChaCha8
    };
    let cc: ChaCha = unsafe {
        std::mem::transmute(tmp)
    };
    cc
}


