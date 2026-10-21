#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(clippy::doc_markdown)]
#![warn(clippy::all)]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

#[macro_use]
#[cfg(any(feature = "e", feature = "g", feature = "ex", feature = "gx"))]
extern crate arrayref;
extern crate thiserror;
use thiserror::Error;
pub use zeroize::{Zeroize, Zeroizing};
#[cfg(feature = "envelope")]
mod envelope;
mod memory;
#[cfg(any(feature = "e", feature = "g", feature = "ex", feature = "gx"))]
mod sip;
#[cfg(feature = "envelope")]
pub use envelope::{ENVELOPE_HEADER_LENGTH, MAX_CONTEXT_LENGTH};
pub use memory::{SecretBytes, SecretKey, MAX_INPUT_LENGTH};
#[cfg(any(feature = "g", feature = "gx"))]
mod generate;
#[cfg(any(feature = "e", feature = "g", feature = "ex", feature = "gx"))]
mod lqb;
#[cfg(any(feature = "e", feature = "g", feature = "ex", feature = "gx"))]
mod util;

#[cfg(feature = "e")]
/// Module containing items related to the ARX-KW-8-2-4-E variant
pub mod e;
#[cfg(feature = "ex")]
/// Module containing items related to the ARX-KW-8-2-4-EX variant
pub mod ex;
#[cfg(feature = "g")]
/// Module containing items related to the ARX-KW-8-2-4-G variant
pub mod g;
#[cfg(feature = "gx")]
/// Module containing items related to the ARX-KW-8-2-4-GX variant
pub mod gx;
pub use subtle::{Choice, ConstantTimeEq};

#[derive(Error, Debug)]
/// An error denoting that a value was of an invalid length. Typically this will be used as a
/// variant of [`ArxKwError`] rather than on its own.
pub enum InvalidLengthError {
    #[error("Invalid length: {0} (expected {1})")]
    /// Invalid length in a context expecting a fixed length.
    _Fixed(usize, usize),
    /// Invalid length in a context which accepts a variable length (e.g. plaintext and ciphertext
    /// inputs)
    #[error("Invalid length: {0} (Maximum: {1})")]
    UpTo(usize, usize),
}
#[derive(Error, Debug)]
/// The error type used by this crate.
pub enum ArxKwError {
    #[error("Invalid length: {0}")]
    /// See [`InvalidLengthError`]
    InvalidLength(#[from] InvalidLengthError),
    #[error("{0}")]
    /// Occurs if a function using either ChaCha8 or XChaCha8 reaches the end of the stream
    ChaChaError(String),
    #[error("Authentication failed")]
    /// Returns if an authentication tag mismatch occurs during decryption
    BadTags,
    /// A blob must contain at least its 16-byte authentication tag.
    #[error("Invalid blob length: {0} (minimum: 16)")]
    InvalidBlobLength(usize),
    /// The allocator rejected an output buffer request.
    #[error("Unable to allocate output buffer")]
    AllocationFailed,
    /// Envelope magic, version, variant, or reserved bytes are invalid.
    #[error("Invalid or unsupported envelope")]
    InvalidEnvelope,
    /// Application context exceeds the documented maximum.
    #[error("Application context is too long")]
    ContextTooLong,
    /// HKDF could not produce a key of the requested size.
    #[error("Context key derivation failed")]
    KeyDerivationFailed,
}

/// The 16-byte authentication tag stored alongside encrypted keys.
///
/// This is the same for all variants at time of writing (a single, static 128 bits), making
/// for a 50% storage overhead for a 256-bit key like those used for `ChaCha`
///
/// The [`ConstantTimeEq`] trait is implemented (and re-exported from the `subtle` crate by this crate) for constant
/// time equality checking of `AuthTag`s
#[derive(Debug, Clone, Copy, Zeroize)]
pub struct AuthTag(pub [u8; 16]);
impl std::convert::AsRef<[u8; 16]> for AuthTag {
    fn as_ref(&self) -> &[u8; 16] {
        &self.0
    }
}

impl ConstantTimeEq for AuthTag {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}
/// Asserts equality using [`ConstantTimeEq`]. The second argument must be a reference.
///
/// The comparison is constant time for equal-length inputs; assertion failure still branches.
/// This macro is intended for tests, not authentication decisions.
#[macro_export]
macro_rules! assert_ct_eq {
    ($x:expr, $y:expr) => {{
        #[allow(unused_imports)]
        use $crate::ConstantTimeEq as _;
        assert!(
            bool::from(($x).ct_eq($y)),
            "constant-time equality assertion failed"
        );
    }};
}

/// Provides deterministic, authenticated key wrapping.
///
/// Keys are fixed-length arrays; E and EX use 48 bytes, G and GX use 32 bytes.
/// Plaintext and ciphertext are byte slices. E/G reject inputs over 64 bytes.
/// Blob methods encode the 16-byte tag followed by ciphertext; applications
/// can instead store the results of [`ArxKW::encrypt`] separately.
pub trait ArxKW {
    /// The type of data which is used as a key for the type that `impl`s this trait.
    /// Note that this is not the same for all variants of ARX-KW. E and EX use 48-byte keys; G and GX use 32-byte keys
    type Key: Copy + Zeroize + AsRef<[u8]> + AsMut<[u8]>;
    /// Stable identifier stored in versioned envelopes (1=E, 2=G, 3=EX, 4=GX).
    const VARIANT_ID: u8;
    /// Maximum plaintext or ciphertext length accepted before allocation.
    const MAX_INPUT_LENGTH: usize = MAX_INPUT_LENGTH;

    /// Wraps key material into a versioned envelope bound to an application context.
    /// Available with the `envelope` feature (enabled by default).
    ///
    /// Use a stable, application-specific context such as `b"example.com/storage/v1"`.
    /// The context is not stored; supply exactly the same bytes during decryption.
    /// # Errors
    /// Returns an error for oversized inputs/context, allocation failure, or encryption failure.
    #[cfg(feature = "envelope")]
    fn encrypt_envelope(
        key: &Self::Key,
        plaintext: &[u8],
        context: &[u8],
    ) -> Result<Vec<u8>, ArxKwError> {
        envelope::encrypt::<Self>(key, plaintext, context)
    }

    /// Opens a versioned envelope into plaintext that zeroizes when dropped.
    /// Available with the `envelope` feature (enabled by default).
    /// # Errors
    /// Rejects invalid headers, wrong variants, oversized input/context, allocation
    /// failure, and authentication failure (including a changed context).
    #[cfg(feature = "envelope")]
    fn decrypt_envelope(
        key: &Self::Key,
        input: &[u8],
        context: &[u8],
    ) -> Result<SecretBytes, ArxKwError> {
        envelope::decrypt::<Self>(key, input, context)
    }

    /// Decrypts a legacy blob into plaintext that zeroizes when dropped.
    /// # Errors
    /// Returns the same errors as [`ArxKW::decrypt_blob`].
    fn decrypt_secret(key: &Self::Key, blob: &[u8]) -> Result<SecretBytes, ArxKwError> {
        Self::decrypt_blob(key, blob).map(SecretBytes::new)
    }
    /// Encrypts the plaintext using ARX-KW and returns the encrypted ciphertext and an [`AuthTag`]
    ///
    /// The authentication tag can be stored/transported alongside it and is needed (along with the
    /// key used to encrypt the plaintext) in order to decrypt the wrapped key.
    ///
    /// # Errors
    ///
    /// Returns an error if the plaintext exceeds the variant limit or the
    /// ChaCha stream is exhausted. Key lengths are checked by the type system.
    fn encrypt(key: &Self::Key, plaintext: &[u8]) -> Result<(Vec<u8>, AuthTag), ArxKwError>;
    /// Attempts to decrypt the ciphertext using ARX-KW and returns the decrypted plaintext if
    /// successful. As ARX-KW is a form of authenticated encryption, the authenticity of the
    /// decrypted text is verified if the function returns an `Ok` value.
    ///
    ///# Errors
    ///
    /// Returns an error if the ciphertext exceeds the variant limit, authentication fails,
    /// or the ChaCha stream is exhausted. Key lengths are checked by the type system.
    fn decrypt(
        key: &Self::Key,
        ciphertext: &[u8],
        authentication_tag: &AuthTag,
    ) -> Result<Vec<u8>, ArxKwError>;

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
    /// Returns an error if the plaintext exceeds the variant limit or the
    /// ChaCha stream is exhausted. Key lengths are checked by the type system.
    ///
    ///```
    /// # #[cfg(feature = "gx")]
    /// # fn main() -> anyhow::Result<()> {
    /// use arx_kw::{ArxKW,gx::GX,assert_ct_eq,ConstantTimeEq};
    /// extern crate hex;
    /// use hex::FromHex;
    /// # extern crate anyhow;
    ///
    /// let key = <[u8; 32]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")?; // The key being used to encrypt the plaintext
    /// let plaintext = <[u8; 32]>::from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")?; // The key that we are trying to encrypt, as plaintext
    /// // The expected output: a "blob" consisting of the authentication tag followed by ciphertext. This can be treated as one opaque piece of data when using encrypt_blob and decrypt_blob
    /// let blob_expected = <[u8; 48]>::from_hex("016325cf6a3c4b2e3b039675e1ccbc652f83f391c97f3606ccd5709c6ee15d66cd7e65a2aeb7dc3066636e8f6b0d39c3")?;   
    /// let blob = GX::encrypt_blob(&key, &plaintext)?; // The output of encrypt_blob, a Vec<u8>
    /// assert_ct_eq!(blob, &blob_expected);
    /// # Ok(())
    /// # }
    /// # #[cfg(not(feature = "gx"))] fn main() {}
    ///```
    fn encrypt_blob(key: &Self::Key, plaintext: &[u8]) -> Result<Vec<u8>, ArxKwError> {
        let (ciphertext, authentication_tag) = Self::encrypt(key, plaintext)?;
        let mut blob = memory::allocate(
            ciphertext
                .len()
                .checked_add(16)
                .ok_or(ArxKwError::AllocationFailed)?,
        )?;
        blob.extend_from_slice(authentication_tag.as_ref());
        blob.extend_from_slice(&ciphertext);
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
    /// Returns an error if the ciphertext exceeds the variant limit, the authentication tag does
    /// not match the ciphertext that follows it, the blob contains fewer than 16 bytes,
    /// or if the end of the \[X\]ChaCha stream is reached unexpectedly
    ///
    /// ```
    /// # #[cfg(feature = "e")]
    /// # fn main() -> anyhow::Result<()> {
    /// use arx_kw::{ArxKW,e::E,assert_ct_eq,ConstantTimeEq};
    /// extern crate hex;
    /// use hex::FromHex;
    /// # extern crate anyhow;
    ///
    /// let key = <[u8; 48]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f")?;
    /// let blob = <[u8; 48]>::from_hex("c4f21d3b4dbcc566c3a73bbc59790f2fe6457d24abaf7c2ebdb91416a18366d31a66db61a4e45c9f42a119c353bb1eb1")?;
    /// let plaintext_expected = <[u8;32]>::from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")?;
    /// let plaintext = E::decrypt_blob(&key, &blob)?;
    /// assert_ct_eq!(plaintext, &plaintext_expected);
    /// # Ok(())
    /// # }
    /// # #[cfg(not(feature = "e"))] fn main() {}
    ///```
    ///
    fn decrypt_blob(key: &Self::Key, blob: &[u8]) -> Result<Vec<u8>, ArxKwError> {
        if blob.len() < 16 {
            return Err(ArxKwError::InvalidBlobLength(blob.len()));
        }
        let mut tag = [0; 16];
        tag.copy_from_slice(&blob[..16]);
        let authentication_tag = AuthTag(tag);
        let ciphertext = &blob[16..];
        Self::decrypt(key, ciphertext, &authentication_tag)
    }
}
