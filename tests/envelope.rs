#![cfg(all(
    feature = "envelope",
    any(feature = "e", feature = "g", feature = "ex", feature = "gx")
))]
#[cfg(feature = "gx")]
use arx_kw::MAX_INPUT_LENGTH;
use arx_kw::{ArxKW, ArxKwError, ENVELOPE_HEADER_LENGTH, MAX_CONTEXT_LENGTH};

#[cfg(any(feature = "e", feature = "g", feature = "ex", feature = "gx"))]
fn check<V: ArxKW>(key: &V::Key) {
    let input = b"secret key material";
    let context = b"example.com/storage/v1";
    let sealed = V::encrypt_envelope(key, input, context).unwrap();
    assert_eq!(sealed.len(), ENVELOPE_HEADER_LENGTH + 16 + input.len());
    assert_eq!(
        V::decrypt_envelope(key, &sealed, context).unwrap().as_ref(),
        input
    );
    assert_eq!(sealed, V::encrypt_envelope(key, input, context).unwrap());
    assert!(matches!(
        V::decrypt_envelope(key, &sealed, b"different context"),
        Err(ArxKwError::BadTags)
    ));
    for byte in 0..sealed.len() {
        let mut altered = sealed.clone();
        altered[byte] ^= 1;
        assert!(
            V::decrypt_envelope(key, &altered, context).is_err(),
            "offset={}",
            byte
        );
    }
    for length in 0..sealed.len() {
        assert!(V::decrypt_envelope(key, &sealed[..length], context).is_err());
    }
    let too_long = vec![0; MAX_CONTEXT_LENGTH + 1];
    assert!(matches!(
        V::encrypt_envelope(key, input, &too_long),
        Err(ArxKwError::ContextTooLong)
    ));
    assert!(matches!(
        V::decrypt_envelope(key, &sealed, &too_long),
        Err(ArxKwError::ContextTooLong)
    ));
    let empty = V::encrypt_envelope(key, &[], context).unwrap();
    assert!(V::decrypt_envelope(key, &empty, context)
        .unwrap()
        .is_empty());
    let blob = V::encrypt_blob(key, input).unwrap();
    assert_eq!(V::decrypt_secret(key, &blob).unwrap().as_ref(), input);
    assert!(V::decrypt_envelope(key, &blob, context).is_err());
}

#[cfg(feature = "e")]
#[test]
fn e_envelopes() {
    check::<arx_kw::e::E>(&[0x42; 48]);
}
#[cfg(feature = "g")]
#[test]
fn g_envelopes() {
    check::<arx_kw::g::G>(&[0x42; 32]);
}
#[cfg(feature = "ex")]
#[test]
fn ex_envelopes() {
    check::<arx_kw::ex::EX>(&[0x42; 48]);
}
#[cfg(feature = "gx")]
#[test]
fn gx_envelopes() {
    check::<arx_kw::gx::GX>(&[0x42; 32]);
}

#[cfg(all(feature = "g", feature = "gx"))]
#[test]
fn envelopes_reject_another_variant() {
    let key = [0x42; 32];
    let envelope = arx_kw::g::G::encrypt_envelope(&key, b"secret", b"context").unwrap();
    assert!(matches!(
        arx_kw::gx::GX::decrypt_envelope(&key, &envelope, b"context"),
        Err(ArxKwError::InvalidEnvelope)
    ));
}

#[cfg(feature = "gx")]
#[test]
fn gx_size_limit_is_enforced_before_processing() {
    use arx_kw::{gx::GX, AuthTag};
    let key = [0x42; 32];
    let oversized = vec![0; MAX_INPUT_LENGTH + 1];
    assert!(matches!(
        GX::encrypt(&key, &oversized),
        Err(ArxKwError::InvalidLength(_))
    ));
    assert!(matches!(
        GX::decrypt(&key, &oversized, &AuthTag([0; 16])),
        Err(ArxKwError::InvalidLength(_))
    ));
    assert!(matches!(
        GX::encrypt_envelope(&key, &oversized, b"context"),
        Err(ArxKwError::InvalidLength(_))
    ));
    let plaintext = &oversized[..MAX_INPUT_LENGTH];
    let envelope = GX::encrypt_envelope(&key, plaintext, b"context").unwrap();
    assert_eq!(
        GX::decrypt_envelope(&key, &envelope, b"context")
            .unwrap()
            .as_ref(),
        plaintext
    );
}
