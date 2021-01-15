# ARX-KW

[![crates.io](https://img.shields.io/crates/v/arx-kw.svg)](https://crates.io/crates/arx-kw)
[![Docs.rs](https://docs.rs/arx-kw/badge.svg)](https://docs.rs/arx-kw)

---

This library features Rust implementations of the ARX-KW family of novel [Key Wrap](https://wikipedia.org/wiki/Key_Wrap) constructions.

---

# Background

ARX-KW was first presented in [this paper](https://ia.cr/2020/059) written by Satō Shinichi and submitted to the IACR Cryptology ePrint Archive in January 2020. As the name
suggests, these constructions make extensive use of add-rotate-xor algorithms: each of the four
variants specified involves both the [SipHash-2-4](https://wikipedia.org/wiki/SipHash) pseudorandom function with 128-bit output and
a stream cipher from the [ChaCha](https://wikipedia.org/wiki/Salsa20) family of stream ciphers.

ARX-KW is a cipher for deteministic, authenticated encryption which aims to provide strong
authenticity and confidentiality while minimizing the storage overhead and simplicity of use
when compared to existing constructions using the ChaCha cipher either which require keeping state for a nonce and 
a block counter or have a substantial storage overhead in order to manage the nonce
statelessly.

ARX-KW has a static overhead of 128 bits for each of its four variants without the need to keep
state for the nonce used by ChaCha, making the storage overhead only 50% for a 256-bit key

---

# Use

## When

As noted above, the ARX-KW constructions are **Key Wrap** algorithms, designed and intended to
protect other cryptographic keys using [symmetric encryption](https://wikipedia.org/wiki/Symmetric_encryption). It is important to note that ARX-KW, like all Key Wrap constructions, 
was designed with the expectation that its input data is highly [entropic](https://wikipedia.org/wiki/Entropic_security), as is the case with secret cryptographic keys. This is because it is
a [deterministic encryption](https://wikipedia.org/wiki/Deterministic_encryption) scheme and
will always yield the same ciphertext output for a given input; if used to encrypt low-entropy
data (as with general-purpose encryption schemes), it is vulnerable to "leakage", described here:

> Deterministic encryption can leak information to an eavesdropper, who may recognize known ciphertexts. For example, when an adversary learns that a given ciphertext corresponds to some interesting message, they can learn something every time that ciphertext is transmitted. To gain information about the meaning of various ciphertexts, an adversary might perform a statistical analysis of messages transmitted over an encrypted channel, or attempt to correlate ciphertexts with observed actions (e.g., noting that a given ciphertext is always received immediately before a submarine dive). If used to store secret key material (by nature high entropy), this is not an issue as an attacker gains no information about the key encapsulated within. 

## How

Add `arx_kw = "0.1.1"` to your Cargo.toml dependencies section.

Each public module of this crate contains a struct corresponding to one of the four specified
ARX-KW-8-2-4 variants: ARX-8-2-4-`E`, ARX-8-2-4-`G`, ARX-8-2-4-`EX`, and ARX-8-2-4-`GX`. If you're not
sure which to use, `gx::GX` is recommended. The functionality is provided by the `ArxKW` trait,
so that will need to be in scope to use the `encrypt` and `decrypt` methods.

---

```rust

extern crate arx_kw;
extern crate hex;
use hex::FromHex;
use arx_kw::{
     ArxKW,
     gx::GX
};

//!// Encrypt a key using ARX-KW-8-2-4-GX

// The values used here are from the test vectors in the original ARX-KW paper.
// Inputs
let k = <[u8; 32]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")?; // The key we are using to wrap the plaintext secret key
let p = <[u8; 32]>::from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")?; // The plaintext secret key we want to store/transport securely
// Expected outputs
let c_expected = <[u8; 32]>::from_hex("2f83f391c97f3606ccd5709c6ee15d66cd7e65a2aeb7dc3066636e8f6b0d39c3")?; // The ciphertext which contains the wrapped key.
let t_expected = <[u8; 16]>::from_hex("016325cf6a3c4b2e3b039675e1ccbc65")?; // The authentication tag

let (ciphertext, authentication_tag) = GX::encrypt(&k, &p)?;
assert_eq!(ciphertext, c_expected);
assert_eq!(authentication_tag, t_expected);

// Decrypt the wrapped key

let plaintext = GX::decrypt(&k, &ciphertext, &authentication_tag)?;
assert_eq!(plaintext, p);
 ```

# Benchmarks

Presently there are just single encrypt and decrypt benchmarks in the benches directory. They can be run by cloning this repository and running the command `cargo bench`.

# Tests

Tests for encryption and decryption are provided for each of the four variants and use the test vectors from the original ARX-KW paper, along with a couple of doctests. They can be run using `cargo test`
