#[cfg(any(feature = "e", feature = "g", feature = "ex", feature = "gx"))]
use arx_kw::ArxKW;
use arx_kw::{ArxKwError, AuthTag};

#[cfg(any(feature = "e", feature = "g", feature = "ex", feature = "gx"))]
fn check_variant<V: ArxKW>(key: &V::Key, wrong_key: &V::Key, maximum: usize) {
    for length in 0..16 {
        assert!(
            matches!(V::decrypt_blob(key, &vec![0; length]), Err(ArxKwError::InvalidBlobLength(n)) if n == length)
        );
    }
    for length in [0, 1, 15, 16, 31, 32, 63, 64, 65, 127, 128, 129, 257] {
        let plaintext: Vec<_> = (0..length).map(|i| (i % 251) as u8).collect();
        if length > maximum {
            assert!(matches!(
                V::encrypt(key, &plaintext),
                Err(ArxKwError::InvalidLength(_))
            ));
            assert!(matches!(
                V::decrypt(key, &plaintext, &AuthTag([0; 16])),
                Err(ArxKwError::InvalidLength(_))
            ));
            continue;
        }
        let blob = V::encrypt_blob(key, &plaintext).unwrap();
        assert_eq!(blob.len(), length + 16);
        assert_eq!(blob, V::encrypt_blob(key, &plaintext).unwrap());
        assert_eq!(V::decrypt_blob(key, &blob).unwrap(), plaintext);
        assert!(matches!(
            V::decrypt_blob(wrong_key, &blob),
            Err(ArxKwError::BadTags)
        ));
        // Change every tag byte and representative ciphertext bytes independently.
        for index in 0..blob.len() {
            let mut altered = blob.clone();
            altered[index] ^= 1;
            assert!(matches!(
                V::decrypt_blob(key, &altered),
                Err(ArxKwError::BadTags)
            ));
        }
    }
}

#[test]
fn authentication_errors_do_not_expose_tags() {
    let error = ArxKwError::BadTags;
    assert_eq!(format!("{error}"), "Authentication failed");
    assert_eq!(format!("{error:?}"), "BadTags");
}

#[test]
fn assertion_macro_does_not_require_trait_import() {
    arx_kw::assert_ct_eq!(AuthTag([0; 16]), &AuthTag([0; 16]));
    let bytes = Vec::from([1u8, 2]);
    arx_kw::assert_ct_eq!(bytes, &[1u8, 2]);
}

#[cfg(feature = "e")]
#[test]
fn e_boundaries() {
    check_variant::<arx_kw::e::E>(&[0x42; 48], &[0x24; 48], 64);
}
#[cfg(feature = "g")]
#[test]
fn g_boundaries() {
    check_variant::<arx_kw::g::G>(&[0x42; 32], &[0x24; 32], 64);
}
#[cfg(feature = "ex")]
#[test]
fn ex_boundaries() {
    check_variant::<arx_kw::ex::EX>(&[0x42; 48], &[0x24; 48], usize::MAX);
}
#[cfg(feature = "gx")]
#[test]
fn gx_boundaries() {
    check_variant::<arx_kw::gx::GX>(&[0x42; 32], &[0x24; 32], usize::MAX);
}
