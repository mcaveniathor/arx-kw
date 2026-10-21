use crate::ArxKwError;
use std::{
    fmt,
    ops::{Deref, DerefMut},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Maximum accepted plaintext size: one MiB. E/G retain their stricter 64-byte limit.
pub const MAX_INPUT_LENGTH: usize = 1024 * 1024;
/// Owned plaintext that is wiped on drop and redacted from debug output.
/// Avoid making unguarded copies through the borrowed slice.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub(crate) const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}
impl Deref for SecretBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}
impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}

/// Owned wrapping key that is wiped on drop and redacted from debug output.
/// Borrow with `&*key` when calling this crate. Caller-owned copies are not erased.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey<const N: usize>([u8; N]);
impl<const N: usize> SecretKey<N> {
    /// Takes ownership of a key array. Erase any remaining caller-owned copies.
    #[must_use]
    pub const fn new(key: [u8; N]) -> Self {
        Self(key)
    }
}
impl<const N: usize> Deref for SecretKey<N> {
    type Target = [u8; N];
    fn deref(&self) -> &[u8; N] {
        &self.0
    }
}
impl<const N: usize> DerefMut for SecretKey<N> {
    fn deref_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }
}
impl<const N: usize> fmt::Debug for SecretKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey([REDACTED])")
    }
}

#[cfg(any(feature = "envelope", feature = "ex", feature = "gx"))]
pub fn check_length(length: usize, maximum: usize) -> Result<(), ArxKwError> {
    if length > maximum {
        return Err(crate::InvalidLengthError::UpTo(length, maximum).into());
    }
    Ok(())
}

pub fn allocate(length: usize) -> Result<Vec<u8>, ArxKwError> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(length)
        .map_err(|_| ArxKwError::AllocationFailed)?;
    Ok(buffer)
}

#[cfg(any(feature = "e", feature = "g", feature = "ex", feature = "gx"))]
pub fn copy_secret(input: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, ArxKwError> {
    let mut output = zeroize::Zeroizing::new(allocate(input.len())?);
    output.extend_from_slice(input);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn allocation_overflow_is_an_error() {
        assert!(matches!(
            allocate(usize::MAX),
            Err(ArxKwError::AllocationFailed)
        ));
    }
}

#[cfg(test)]
mod secret_tests {
    use super::*;
    #[test]
    fn secrets_are_redacted_and_explicitly_erasable() {
        fn requires_drop_wipe<T: ZeroizeOnDrop>() {}
        requires_drop_wipe::<SecretKey<32>>();
        requires_drop_wipe::<SecretBytes>();
        let mut key = SecretKey::new([0x42; 32]);
        assert_eq!(format!("{key:?}"), "SecretKey([REDACTED])");
        key.zeroize();
        assert_eq!(&*key, &[0; 32]);
        let mut plaintext = SecretBytes::new(vec![0x42; 32]);
        assert_eq!(format!("{plaintext:?}"), "SecretBytes([REDACTED])");
        plaintext.zeroize();
        assert!(plaintext.is_empty());
    }
}
