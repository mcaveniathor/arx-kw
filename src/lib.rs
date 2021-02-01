#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(clippy::doc_markdown)]
#![warn(clippy::all)]
#![warn(missing_docs)]
//! # ARX-KW
//! [![crates.io](https://img.shields.io/crates/v/arx-kw.svg)](https://crates.io/crates/arx-kw)
//! [![Docs.rs](https://docs.rs/arx-kw/badge.svg)](https://docs.rs/arx-kw)
//! [![Rust Report Card](https://rust-reportcard.xuri.me/badge/github.com/mcaveniathor/arx-kw)](https://rust-reportcard.xuri.me/report/github.com/mcaveniathor/arx-kw)
//! [![dependency status](https://deps.rs/crate/arx-kw/0.2.12/status.svg)](https://deps.rs/crate/arx-kw/0.2.12)
//! [![Build Status](https://www.travis-ci.com/mcaveniathor/arx-kw.svg?branch=main)](https://www.travis-ci.com/mcaveniathor/arx-kw)
//! [![codecov](https://codecov.io/gh/mcaveniathor/arx-kw/branch/main/graph/badge.svg?token=OVCFNGQDSH)](https://codecov.io/gh/mcaveniathor/arx-kw)
//! [![MIT license](https://img.shields.io/badge/License-MIT-blue.svg)](https://lbesson.mit-license.org/)
//!
//!
//! This library features implementations of the ARX-KW family of novel [Key Wrap](https://wikipedia.org/wiki/Key_Wrap) constructions.
//!
//! The version number for this crate will be incremented in compliance with [Semantic Versioning](https://semver.org/). 
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
//! when compared to existing constructions using the ChaCha cipher which require either keeping state for a nonce and 
//! a block counter or having a substantial storage overhead in order to manage the nonce
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
//!
//! #### Nightly
//!
//! Use the `nightly` feature to enable SIMD parallelization of the ChaCha computations (nightly Rust required):
//!
//! *Cargo.toml*

//! ```toml
//! [dependencies]
//! arx-kw = {version = "0.3", features = ["nightly"]}
//! ```
//!
//!
//! #### Variants
//!
//! The four variants are gated under individual features ("e", "g", "ex", and "gx") for conditional compilation if not all
//! are going to be used. All are enabled by default, but for example if you only want to use
//! the [`gx::GX`] variant:
//!
//! *Cargo.toml*
//!
//! ```toml
//! [dependencies]
//! arx-kw = { version = "0.3", default-features=false, features=["gx"] }
//! ```
//!
//! ## How
//!
//!
//! 
//! Each public module of this crate contains a struct corresponding to one of the four specified
//! ARX-KW-8-2-4 variants: ARX-8-2-4-`E`, ARX-8-2-4-`G`, ARX-8-2-4-`EX`, and ARX-8-2-4-`GX`. If you're not
//! sure which to use, [`gx::GX`] is recommended. The functionality is provided by the `ArxKW` trait,
//! so that will need to be in scope to use the [`ArxKW::encrypt`]/[`ArxKW::encrypt_blob`] and [`ArxKW::decrypt`]/[`ArxKW::decrypt_blob`] methods. The
//! [`ConstantTimeEq`] trait from the `subtle` crate is re-exported by this crate and is implemented
//! on the [`AuthTag`] type as well as those covered by the blanket implementations `subtle`
//! provides.
//!
//! - Encryption and decryption of secret plaintext can be performed using the [`ArxKW::encrypt`]
//! and [`ArxKW::decrypt`] methods, which remove the need to keep track of nonces and how to
//! store/transport them. These methods treat authentication tags and ciphertexts as separate
//! entities; if you need the flexibility of handling them separately, use these -- otherwise, the
//! [`ArxKW::encrypt_blob`] and [`ArxKW::decrypt_blob`] methods described below offer a further layer of abstraction and
//! ease of use at no performance cost.
//!
//! - The [`ArxKW::encrypt_blob`] and [`ArxKW::decrypt_blob`] methods further improve ease of use by allowing the
//! user to treat a [`Vec<u8>`] consisting of an authentication tag  followed by the corresponding
//! ciphertext as a single opaque blob. Consequently, not only is the issue of nonce management
//! addressed by ARX-KW, but management of authentication tags as well! The blob can be stored or
//! transported in one piece, saving headache, database retrievals, and making it easy to perform
//! key wrapping in a safe and simple way.
//! 
//! [`Eq`] and [`PartialEq`] are by design *not* implemented for [`AuthTag`] to discourage equality
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
//! };
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Encrypt a key using ARX-KW-8-2-4-GX with the encrypt_blob method
//!
//! // The values used here are from the test vectors in the original ARX-KW paper.
//! /* 
//!  * Inputs
//!  */ 
//!// The encryption key we are using to wrap the plaintext secret key
//! let key = <[u8; 32]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")?; 
//! // The plaintext secret key we want to store/transport securely
//! let plaintext = <[u8; 32]>::from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")?; 
//!
//! /*
//!  * Expected output: 
//!  * A Vec<u8> containing the authentication tag followed by the ciphertext containing the
//!  * wrapped key. We can treat this as an opaque blob when using the encrypt_blob and decrypt_blob
//!  * methods, meaning we don't have to manually manage authentication tags or nonces.
//!  */
//! let blob_expected = <[u8; 48]>::from_hex("016325cf6a3c4b2e3b039675e1ccbc652f83f391c97f3606ccd5709c6ee15d66cd7e65a2aeb7dc3066636e8f6b0d39c3")?;
//!
//! /*
//!  * Key wrapping performed in one line, simply passing the 
//!  * encryption key and the plaintext to be encrypted.
//!  */
//! let blob = GX::encrypt_blob(&key, &plaintext)?; 
//! assert_ct_eq!(blob, &blob_expected);
//!
//! /*
//!  * Decryption likewise is done in one line, passing the key and the blob to be decrypted.
//!  * The authentication tag is checked to match the ciphertext
//!  * during decryption and will return an error if the tags do not match.
//!  * Returns the decrypted plaintext if successful, otherwise an error.
//!  */
//! let decrypted_plaintext = GX::decrypt_blob(&key, &blob)?;
//! assert_ct_eq!(plaintext, &decrypted_plaintext);
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

#[cfg(feature="e")]
/// Module containing items related to the ARX-KW-8-2-4-E variant
pub mod e;
#[cfg(feature="g")]
/// Module containing items related to the ARX-KW-8-2-4-G variant
pub mod g;
#[cfg(feature="ex")]
/// Module containing items related to the ARX-KW-8-2-4-EX variant
pub mod ex;
#[cfg(feature="gx")]
/// Module containing items related to the ARX-KW-8-2-4-GX variant
pub mod gx;
pub use subtle::{ConstantTimeEq,Choice};

#[derive(Error,Debug)]
/// An error denoting that a value was of an invalid length. Typically this will be used as a
/// variant of [`ArxKwError`] rather than on its own.
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
    /// See [`InvalidLengthError`]
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
/// The [`ConstantTimeEq`] trait is implemented (and re-exported from the `subtle` crate by this crate) for constant
/// time equality checking of `AuthTag`s
#[derive(Debug,Clone,Copy,)]
pub struct AuthTag(pub [u8; 16]);
impl std::convert::AsRef<[u8;16]> for AuthTag {
    #[cfg(not(tarpaulin_include))]
    fn as_ref(&self) -> &[u8;16] {
        &self.0
    }
}

impl ConstantTimeEq for AuthTag {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}
/// Macro which provides an equivalent of [`assert_eq`] in constant time using the [`ConstantTimeEq`]
/// trait. Accordingly, ConstantTimeEq must be in scope and implemented on the types of $x and $y
/// for this to work. It is implemented for [`AuthTag`] and many primitives.
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
/// The ArxKW trait requires a fixed-length array reference for keys and authentication tags
/// but the ciphertext and plaintext inputs can be slices (their lengths are verified to be valid
/// if used with the E and G variants).
///
/// The [`ArxKW::encrypt_blob`] and [`ArxKW::decrypt_blob`] are preferable to [`ArxKW::encrypt`]  and [`ArxKW::decrypt`] in
/// most cases, as they eliminate the need to manually manage authentication tags without a
/// performance penalty, keeping with the
/// spirit of ARX-KW (which was designed with removing the burden of nonce and block counter management as a primary
/// goal.)
pub trait ArxKW {
    /// The type of data which is used as a key for the type that `impl`s this trait.
    /// Note that this is not the same for all variants of ARX-KW. all of the currently-defined variants use the same-sized keys
    type Key;
    /// Encrypts the plaintext using ARX-KW and returns the encrypted ciphertext and an [`AuthTag`]
    ///
    /// The authentication tag can be stored/transported alongside it and is needed (along with the
    /// key used to encrypt the plaintext) in order to decrypt the wrapped key.
    ///
    /// # Errors
    ///
    /// Returns an error if the key or plaintext is
    /// of invalid length or if the end of the ChaCha cipher is reached unexpectedly.
    fn encrypt(key: &Self::Key, plaintext: &[u8]) -> Result<(Vec<u8>, AuthTag), ArxKwError>;
    /// Attempts to decrypt the ciphertext using ARX-KW and returns the decrypted plaintext if
    /// successful. As ARX-KW is a form of authenticated encryption, the authenticity of the
    /// decrypted text is verified if the function returns an `Ok` value.
    /// which can be stored/transported alongside it. 
    ///
    ///# Errors
    ///
    /// Returns an error if the key or ciphertext is of invalid length or if the end of the ChaCha cipher is reached unexpectedly.
    fn decrypt(key: &Self::Key, ciphertext: &[u8], authentication_tag: &AuthTag) -> Result<Vec<u8>, ArxKwError>;


    /// Encrypts the plaintext and returns a [`Vec<u8>`] containing both the authentication tag
    /// and the ciphertext. 
    ///
    /// While ARX-KW by design eliminates the need for nonce management, it can
    /// be further used to eliminate the complexity of managing authentication tags as well without
    /// incurring a large storage overhead. The `encrypt_blob` and `decrypt_blob` methods allow for
    /// this abstraction; the ciphertext and authentication tag can be treated as one opaque "blob" of bytes
    /// and so authentication and decryption of that blob can be done with just the key,
    /// eliminating the need to separately store a nonce or authentication tag. This gives a
    /// user-friendly interface to deterministic and authenticated encryption.
    ///
    /// # Errors
    ///
    /// Returns an error if the key or plaintext is of invalid length or if the end of the
    /// \[X\]ChaCha stream is reached unexpectedly
    ///
    ///```
    /// extern crate arx_kw;
    /// use arx_kw::{ArxKW,gx::GX,assert_ct_eq,ConstantTimeEq};
    /// extern crate hex;
    /// use hex::FromHex;
    /// # extern crate anyhow;
    ///
    /// # fn main() -> anyhow::Result<()> {
    /// let key = <[u8; 32]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")?; // The key being used to encrypt the plaintext
    /// let plaintext = <[u8; 32]>::from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")?; // The key that we are trying to encrypt, as plaintext
    /// // The expected output: a "blob" consisting of the authentication tag followed by ciphertext. This can be treated as one opaque piece of data when using encrypt_blob and decrypt_blob
    /// let blob_expected = <[u8; 48]>::from_hex("016325cf6a3c4b2e3b039675e1ccbc652f83f391c97f3606ccd5709c6ee15d66cd7e65a2aeb7dc3066636e8f6b0d39c3")?;   
    /// let blob = GX::encrypt_blob(&key, &plaintext)?; // The output of encrypt_blob, a Vec<u8>
    /// assert_ct_eq!(blob, &blob_expected);
    /// # Ok(())
    /// # }
    ///```
    fn encrypt_blob(key: &Self::Key, plaintext: &[u8]) -> Result<Vec<u8>, ArxKwError> {
        let (mut ciphertext, authentication_tag) = Self::encrypt(key, plaintext)?;
        let mut blob = Vec::with_capacity(ciphertext.len()+16);
        blob.append(&mut authentication_tag.as_ref().to_vec());
        blob.append(&mut ciphertext);
        Ok(blob)
    }

    /// Decrypts a blob containing an authentication tag followed by the corresponding ciphertext
    ///
    /// If decryption is successful, returns a [`Vec<u8>`] containing the decrypted plaintext.
    ///
    /// While ARX-KW by design eliminates the need for nonce management, it can
    /// be further used to eliminate the complexity of managing authentication tags as well without
    /// incurring a large storage overhead. The `encrypt_blob` and `decrypt_blob` methods allow for
    /// this abstraction; the ciphertext and authentication tag can be treated as one opaque "blob" of bytes
    /// and so authentication and decryption of that blob can be done with just the key,
    /// eliminating the need to separately store a nonce or authentication tag. This gives a
    /// user-friendly interface to deterministic and authenticated encryption.
    ///
    /// # Errors
    ///
    /// Returns an error if the key or ciphertext is of invalid length, the authentication tag does
    /// not match the ciphertext that follows it, or if the end of the \[X\]ChaCha stream is reached unexpectedly
    ///
    /// ```
    /// extern crate arx_kw;
    /// use arx_kw::{ArxKW,e::E,assert_ct_eq,ConstantTimeEq};
    /// extern crate hex;
    /// use hex::FromHex;
    /// # extern crate anyhow;
    ///
    /// # fn main() -> anyhow::Result<()> {
    /// let key = <[u8; 48]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f")?;
    /// let blob = <[u8; 48]>::from_hex("c4f21d3b4dbcc566c3a73bbc59790f2fe6457d24abaf7c2ebdb91416a18366d31a66db61a4e45c9f42a119c353bb1eb1")?;
    /// let plaintext_expected = <[u8;32]>::from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")?;
    /// let plaintext = E::decrypt_blob(&key, &blob)?;
    /// assert_ct_eq!(plaintext, &plaintext_expected);
    /// # Ok(())
    /// # }
    ///```
    ///
    fn decrypt_blob(key: &Self::Key, blob: &[u8]) -> Result<Vec<u8>, ArxKwError> {
        let authentication_tag = AuthTag(*array_ref![blob,0,16]);
        let ciphertext = &blob[16..];
        Self::decrypt(key, ciphertext, &authentication_tag)
    }
}
