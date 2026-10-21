use arx_kw::{ArxKW, MAX_CONTEXT_LENGTH};

// Shared assertions used by generated property cases and instrumented fuzzing.
pub fn round_trip<V: ArxKW>(key: &V::Key, plaintext: &[u8], context: &[u8], mutation: usize) {
    let result = V::encrypt_envelope(key, plaintext, context);
    if plaintext.len() > V::MAX_INPUT_LENGTH || context.len() > MAX_CONTEXT_LENGTH {
        assert!(result.is_err());
        return;
    }
    let envelope = result.unwrap();
    assert_eq!(
        V::decrypt_envelope(key, &envelope, context)
            .unwrap()
            .as_ref(),
        plaintext
    );
    assert_eq!(
        V::encrypt_envelope(key, plaintext, context).unwrap(),
        envelope
    );
    let blob = V::encrypt_blob(key, plaintext).unwrap();
    assert_eq!(V::decrypt_secret(key, &blob).unwrap().as_ref(), plaintext);

    let mut altered = envelope.clone();
    let offset = mutation % altered.len();
    altered[offset] ^= 1 << (mutation % 8);
    assert!(V::decrypt_envelope(key, &altered, context).is_err());
    assert!(V::decrypt_envelope(key, &envelope[..mutation % envelope.len()], context).is_err());

    let mut wrong_key = arx_kw::Zeroizing::new(*key);
    wrong_key.as_mut()[0] ^= 1;
    assert!(V::decrypt_envelope(&wrong_key, &envelope, context).is_err());
    let mut wrong_context = context.to_vec();
    if wrong_context.is_empty() {
        wrong_context.push(1);
    } else {
        wrong_context[0] ^= 1;
    }
    assert!(V::decrypt_envelope(key, &envelope, &wrong_context).is_err());

    let mut altered_blob = blob;
    let offset = mutation % altered_blob.len();
    altered_blob[offset] ^= 1 << (mutation % 8);
    assert!(V::decrypt_secret(key, &altered_blob).is_err());
}

pub fn arbitrary_input<V: ArxKW>(key: &V::Key, input: &[u8], context: &[u8]) {
    // Arbitrary bytes can occasionally be valid; accepted input must reproduce
    // exactly under deterministic encryption, rather than assuming rejection.
    if let Ok(plaintext) = V::decrypt_envelope(key, input, context) {
        assert_eq!(
            V::encrypt_envelope(key, &plaintext, context).unwrap(),
            input
        );
    }
    if let Ok(plaintext) = V::decrypt_secret(key, input) {
        assert_eq!(V::encrypt_blob(key, &plaintext).unwrap(), input);
    }
}
