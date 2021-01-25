#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(clippy::doc_markdown)]
#![warn(clippy::all)]
#![warn(missing_docs)]
//!
//! This library features implementations of the ARX-KW family of novel [Key Wrap](https://wikipedia.org/wiki/Key_Wrap) constructions.
//!
//! ---
//!
//! # Background
//!
//! ARX-KW was first presented in [this paper](https://ia.cr/2020/059) written by Satō Shinichi and submitted to the IACR Cryptology ePrint Archive in January 2020. As the name
//! suggests, these constructions make extensive use of add-rotate-xor algorithms: each of the four
//! variants specified involves both the [SipHash-2-4](https://wikipedia.org/wiki/SipHash) pseudorandom function with 128-bit output and
//! a stream cipher from the [`ChaCha`](https://en.wikipedia.org/wiki/Salsa20) family of stream ciphers.
//!
//! ARX-KW is a cipher for deteministic, authenticated encryption which aims to provide strong
//! authenticity and confidentiality while minimizing the storage overhead and simplicity of use
//! when compared to existing constructions using the ChaCha cipher either which require keeping state for a nonce and 
//! a block counter or have a substantial storage overhead in order to manage the nonce
//! statelessly.
//!
//! ARX-KW has a static overhead of 128 bits for each of its four variants without the need to keep
//! state for the nonce used by ChaCha, making the storage overhead only 50% for a 256-bit key
//!
//! ---
//!
//! # Use
//!
//! ## When
//!
//! As noted above, the ARX-KW constructions are **Key Wrap** algorithms, designed and intended to
//! protect other cryptographic keys using [symmetric encryption](https://wikipedia.org/wiki/Symmetric_encryption). It is important to note that as ARX-KW, like all Key Wrap constructions, 
//! was designed with the expectation that its input data is highly [entropic](https://wikipedia.org/wiki/Entropic_security), as is the case with secret keys. This is because it is
//! a [deterministic encryption](https://wikipedia.org/wiki/Deterministic_encryption) scheme and
//! will always yield the same ciphertext output for a given input; if used to encrypt low-entropy
//! data (as with general-purpose encryption schemes), it is vulnerable to "leakage", described here:
//!
//! > Deterministic encryption can leak information to an eavesdropper, who may recognize known ciphertexts. For example, when an adversary learns that a given ciphertext corresponds to some interesting message, they can learn something every time that ciphertext is transmitted. To gain information about the meaning of various ciphertexts, an adversary might perform a statistical analysis of messages transmitted over an encrypted channel, or attempt to correlate ciphertexts with observed actions (e.g., noting that a given ciphertext is always received immediately before a submarine dive).
//! 
//! If used to store secret key material (by nature high entropy), this is not an issue as an attacker gains no information about the key encapsulated within. 
//!

//! ## Features

//! Use the `nightly` feature to enable SIMD parallelization of the ChaCha computations (nightly Rust required):
//! #### Cargo.toml

//! ```toml
//! [dependencies]
//! arx-kw = {version = "0.1.11", features = ["nightly"]}
//! ```

//! 
//! ## How
//!
//!
//! 
//! Each public module of this crate contains a struct corresponding to one of the four specified
//! ARX-KW-8-2-4 variants: ARX-8-2-4-`E`, ARX-8-2-4-`G`, ARX-8-2-4-`EX`, and ARX-8-2-4-`GX`. If you're not
//! sure which to use, `gx::GX` is recommended. The functionality is provided by the `ArxKW` trait,
//! so that will need to be in scope to use the `encrypt` and `decrypt` methods. The
//! `ConstantTimeEq` trait from the `subtle` crate is re-exported by this crate and is implemented
//! on the `AuthTag` type as well as those covered by the blanket implementations `subtle`
//! provides.
//! 
//! `Eq` and `PartialEq` are by design *not* implemented for `AuthTag` to discourage equality
//! checking that is not O(1), but the internal `[u8;16]` is public should you want to live 
//!
//!
//!
//!
//!
//!>
//!> <br><br><br><br><br>
//!>  
//!> Ḑ̷͉͎̺̳̭͖̗̦̪͓̂͗͒̓̅̆̋̐́̓̓̎̊͐̍̂̈͂̇͆̇͐̉̈̄̈́̈́̓̓̾͒̕͠à̸̢̛̤̠̺̩̱̤̭̪̮̙͈̱̀̍͂̋̓̓͊̈́͊̋̀̾͌͂͘͘̚n̶̡̡̢̪̼̲̫̪̯͖̟͕͚̬̠̥̫̱̮̖̼̪͚̜͙̥̬̙̪̩̮̞̰̼̲̭̏̀̀ģ̸̨̧̳̟͙͙̳̘̥͖̮̼̻͍̯̦̖͋͆̃̏͛̒̌̅͊̃̿̄̒̋͜͜͝͝ͅ ̸̧̟̼͉̳̰̥̮̙͈͖͙͎͇̙͍͚͔͒͋͋̋̒̚͠ͅͅͅè̵̡̘̲̪͔̪̥̹̟̾̅̓͛̐̐̽̅͌̊̓̔̍̓̿̊̆̂̈́͑̽̅̿̚͝͝r̵̛̭̺̠̙̞̫̗̞̪̗̹͎͌͌͌̒̏̌̅̇̉̑̂͋̅̅̀̔̉̾̋̅̏̓͘̚ờ̸̢̡̢̥̟̗̘͉̠̣͕̮͈͍͉̳̫̲̖͖̻̝̯̟͂̊̈́͑̇́͛̏͜͠u̷̎͋͂̽̉͒́̈́̑̋́̌͂̿̋̆́͜͝͝͝s̸̡̡̡̞̞͇͖̖͍̝͖̣̪͓͖̥̟͙̫̪̗͙̯̞͍̽̃̆̒̐̐̊̓̾̚̚ͅĺ̴͕͖͎̣̞͕̙̹̓͒y̷̢̠̠͇͉̘̠̩̳̲͗̑͐̿̿̐͗͊̀̽̀͐̀̿̔̈́͘͝͝
//!> 
//!<br><br><br><br><br>
//!
//! ---
//!
//! ### Encrypt a key
//!
//! ```
//! # extern crate anyhow;
//! # use anyhow::Result;
//! extern crate hex;
//! use hex::FromHex;
//!
//! use arx_kw::{
//!     ArxKW,
//!     gx::GX,
//!     ConstantTimeEq, // From the subtle crate, allows for equality checking in constant time
//!                     // (impl'd for AuthTag and re-exported by this crate)
//!     assert_ct_eq,
//!     AuthTag
//! };
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//!// Encrypt a key using ARX-KW-8-2-4-GX
//!
//!// The values used here are from the test vectors in the original ARX-KW paper.
//! // Inputs
//! let k = <[u8; 32]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")?; // The key we are using to wrap the plaintext secret key
//! let p = <[u8; 32]>::from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")?; // The plaintext secret key we want to store/transport securely
//! // Expected outputs
//! let c_expected = <[u8; 32]>::from_hex("2f83f391c97f3606ccd5709c6ee15d66cd7e65a2aeb7dc3066636e8f6b0d39c3")?; // The ciphertext which contains the wrapped key.
//!
//!// The authentication tag. Note that we wrap this in AuthTag() rather than just using a [u8;16] so that we get constant time equality checking
//! let t_expected = AuthTag(<[u8; 16]>::from_hex("016325cf6a3c4b2e3b039675e1ccbc65")?);
//! // Perform the encryption, returning the encrypted ciphertext and the authentication tag.
//! let (ciphertext, authentication_tag) = GX::encrypt(&k, &p)?;
//! assert_ct_eq!(ciphertext, &c_expected);
//! assert_ct_eq!(authentication_tag, &t_expected);
//!
//! // Decrypt the wrapped key
//!
//! let plaintext = GX::decrypt(&k, &ciphertext, &authentication_tag)?;
//! // The authentication tag is checked during decryption and will return an error if the tags do not match
//! assert_ct_eq!(plaintext, &p);
//! # Ok(())
//! # }
//! ```
//!
//!
//!
//!
extern crate subtle;
extern crate chacha;
extern crate siphasher;
extern crate byteorder;
#[macro_use] extern crate arrayref;
extern crate thiserror;
use thiserror::Error;
mod lqb;
mod util;
mod generate;

/// Module containing items related to the ARX-KW-8-2-4-E variant
pub mod e;
/// Module containing items related to the ARX-KW-8-2-4-G variant
pub mod g;
/// Module containing items related to the ARX-KW-8-2-4-EX variant
pub mod ex;
/// Module containing items related to the ARX-KW-8-2-4-GX variant
pub mod gx;
pub use subtle::{ConstantTimeEq,Choice};

#[derive(Error,Debug)]
/// An error denoting that a value was of an invalid length. Typically this will be used as a
/// variant of `ArxKwError` rather than on its own.
pub enum InvalidLengthError {
    #[error("Invalid length: {0} (expected {1})")]
    /// Invalid length in a context expecting a fixed length.
    _Fixed(usize,usize),
    /// Invalid length in a context which accepts a variable length (e.g. plaintext and ciphertext
    /// inputs)
    #[error("Invalid length: {0} (Maximum: {1}")]
    UpTo(usize,usize)
}
#[derive(Error,Debug)]
/// The error type used by this crate.
pub enum ArxKwError {
    #[error("Invalid length: {0}")]
    /// See `InvalidLengthError`
    InvalidLength(#[from] InvalidLengthError),
    #[error("Reached end of {0}ChaCha8 stream.")]
    /// Occurs if a function using either ChaCha8 or XChaCha8 reaches the end of the stream
    ChaChaError(String), // Use "X" if it occurs while using an extended stream or "" otherwise
    #[error("Authentication tag does not match {0:x?} (Expected {1:x?})")]
    /// Returns if an authentication tag mismatch occurs during decryption
    BadTags(AuthTag,AuthTag)
}

/// The type used as the authentication tag (unencrypted data to be stored alongside encrypted keys) 
/// This is the same for all variants at time of writing (a single, static 128 bits), making
/// for a 50% storage overhead for a 256-bit key like those used for `ChaCha`
///
/// The `subtle::ConstantTimeEq` trait is implemented (and re-exported by this crate) for constant
/// time equality checking of `AuthTag`s
#[derive(Debug,Clone,Copy,)]
pub struct AuthTag(pub [u8; 16]);
impl std::convert::AsRef<[u8;16]> for AuthTag {
    fn as_ref(&self) -> &[u8;16] {
        &self.0
    }
}

impl ConstantTimeEq for AuthTag {
    fn ct_eq(&self, other: &Self) -> Choice {
        println!("peepee");
        self.0.ct_eq(&other.0)
    }
}
/// Macro which provides an equivalent of `assert_eq` in constant time using the `ConstantTimeEq`
/// trait. Accordingly, ConstantTimeEq must be in scope and implemented on the types of $x and $y
/// for this to work. It is implemented for `AuthTag`
#[macro_export]
macro_rules! assert_ct_eq {
    ($x:expr, $y:expr) => {
        if bool::from($x.ct_eq($y)) {
        }
        else {
            panic!("")
        }

    }

}


/// Provides encryption and decryption capabilites
///
/// The ArxKW trait requires a fixed-length array reference for keys and authentication tags,
/// but the ciphertext and plaintext inputs can be slices (their lengths are verified to be valid
/// if used with the E and G variants)
pub trait ArxKW {
    /// The type of data which is used as a key for the type that `impl`s this trait.
    /// Note that this is not the same for all variants of ARX-KW. all of the currently-defined variants use the same-sized keys
    type Key;
    /// Encrypts the plaintext using ARX-KW and returns the encrypted ciphertext and an `AuthTag`
    ///
    /// The authentication tag can be stored/transported alongside it and is needed (along with the
    /// key used to encrypt the plaintext) in order to decrypt the wrapped key.
    ///
    /// # Errors
    /// Returns an error if the key or plaintext is
    /// of invalid length or if the end of the ChaCha cipher is reached unexpectedly.
    fn encrypt(key: &Self::Key, plaintext: &[u8]) -> Result<(Vec<u8>, AuthTag), ArxKwError>;
    /// Attempts to decrypt the ciphertext using ARX-KW and returns the decrypted plaintext if
    /// successful. As ARX-KW is a form of authenticated encryption, the authenticity of the
    /// decrypted text is verified if the function returns an `Ok` value.
    /// which can be stored/transported alongside it. 
    ///
    ///# Errors
    /// Returns an error if the key or ciphertext is of invalid length or if the end of the ChaCha cipher is reached unexpectedly.
    fn decrypt(key: &Self::Key, ciphertext: &[u8], authentication_tag: &AuthTag) -> Result<Vec<u8>, ArxKwError>;
}
