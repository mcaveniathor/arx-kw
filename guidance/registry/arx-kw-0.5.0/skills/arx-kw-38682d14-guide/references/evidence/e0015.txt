#![cfg(any(feature = "e", feature = "g", feature = "ex", feature = "gx"))]
use arx_kw::ArxKW;
use chacha::KeyStream;
use siphasher::sip128::SipHasher24;
use std::convert::TryInto;

// Independent legacy providers implement the paper's operations without using
// this crate's cipher buffering, SipHash, or subkey/nonce construction helpers.
fn reference(key: &[u8], plaintext: &[u8], generated: bool, extended: bool) -> Vec<u8> {
    let mut subkeys = [0u8; 48];
    if generated {
        chacha::ChaCha::new_chacha8(key.try_into().unwrap(), &[0; 8])
            .xor_read(&mut subkeys)
            .unwrap();
    } else {
        subkeys.copy_from_slice(key);
    }
    let tag = SipHasher24::new_with_key(subkeys[..16].try_into().unwrap())
        .hash(plaintext)
        .as_bytes();
    let cipher_key: &[u8; 32] = subkeys[16..].try_into().unwrap();
    let mut state = [0u32; 16];
    state[..4].copy_from_slice(&[0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]);
    for (target, chunk) in state[4..12]
        .iter_mut()
        .zip(cipher_key.as_chunks::<4>().0.iter())
    {
        *target = u32::from_le_bytes(*chunk);
    }
    let mut ciphertext = plaintext.to_vec();
    if extended {
        let mut nonce = [0u8; 24];
        nonce[..8].copy_from_slice(if generated { b"arbitrGX" } else { b"arbitrEX" });
        nonce[8..].copy_from_slice(&tag);
        for (target, chunk) in state[12..]
            .iter_mut()
            .zip(nonce[..16].as_chunks::<4>().0.iter())
        {
            *target = u32::from_le_bytes(*chunk);
        }
        chacha::permute(8, &mut state);
        let mut derived = [0u8; 32];
        for (chunk, word) in derived
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip(state[..4].iter().chain(&state[12..]))
        {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        chacha::ChaCha::new_chacha8(&derived, nonce[16..].try_into().unwrap())
            .xor_read(&mut ciphertext)
            .unwrap();
    } else {
        for (target, chunk) in state[12..].iter_mut().zip(tag.as_chunks::<4>().0.iter()) {
            *target = u32::from_le_bytes(*chunk);
        }
        chacha::permute_and_add(8, &mut state);
        let stream: Vec<u8> = state.iter().flat_map(|word| word.to_le_bytes()).collect();
        for (byte, mask) in ciphertext.iter_mut().zip(stream) {
            *byte ^= mask;
        }
    }
    let mut blob = tag.to_vec();
    blob.extend_from_slice(&ciphertext);
    blob
}

fn check<V: ArxKW>(key: &V::Key, generated: bool, extended: bool) {
    for length in [
        0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 63, 64, 65, 127, 128, 129, 1024,
    ] {
        if length > V::MAX_INPUT_LENGTH {
            continue;
        }
        let input: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
        let expected = reference(key.as_ref(), &input, generated, extended);
        assert_eq!(V::encrypt_blob(key, &input).unwrap(), expected);
        assert_eq!(V::decrypt_blob(key, &expected).unwrap(), input);
    }
}

#[test]
fn migration_matches_independent_legacy_providers() {
    for seed in [0, 1, 42, 255] {
        #[cfg(feature = "e")]
        check::<arx_kw::e::E>(&[seed; 48], false, false);
        #[cfg(feature = "g")]
        check::<arx_kw::g::G>(&[seed; 32], true, false);
        #[cfg(feature = "ex")]
        check::<arx_kw::ex::EX>(&[seed; 48], false, true);
        #[cfg(feature = "gx")]
        check::<arx_kw::gx::GX>(&[seed; 32], true, true);
    }
}
