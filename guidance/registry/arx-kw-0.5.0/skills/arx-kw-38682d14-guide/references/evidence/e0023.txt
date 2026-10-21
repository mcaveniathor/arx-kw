#![cfg(all(
    feature = "envelope",
    any(feature = "e", feature = "g", feature = "ex", feature = "gx")
))]

mod support;
use proptest::prelude::*;

fn messages() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        proptest::collection::vec(any::<u8>(), 0..513),
        proptest::sample::select(vec![0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129])
            .prop_flat_map(|length| proptest::collection::vec(any::<u8>(), length)),
    ]
}

fn contexts() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        8 => proptest::collection::vec(any::<u8>(), 0..129),
        1 => proptest::collection::vec(any::<u8>(), 4096),
        1 => proptest::collection::vec(any::<u8>(), 4097),
    ]
}

macro_rules! variant_properties {
    ($name:ident, $variant:ty, $key_length:expr) => {
        proptest! {
            #[test]
            fn $name(key in any::<[u8; $key_length]>(), input in messages(), context in contexts(), mutation in any::<usize>()) {
                support::round_trip::<$variant>(&key, &input, &context, mutation);
                support::arbitrary_input::<$variant>(&key, &input, &context);
            }
        }
    };
}
#[cfg(feature = "e")]
variant_properties!(e_properties, arx_kw::e::E, 48);
#[cfg(feature = "g")]
variant_properties!(g_properties, arx_kw::g::G, 32);
#[cfg(feature = "ex")]
variant_properties!(ex_properties, arx_kw::ex::EX, 48);
#[cfg(feature = "gx")]
variant_properties!(gx_properties, arx_kw::gx::GX, 32);

#[cfg(any(feature = "ex", feature = "gx"))]
fn extended_boundary<V: arx_kw::ArxKW>(key: &V::Key) {
    let mut input = vec![0x5a; V::MAX_INPUT_LENGTH];
    support::round_trip::<V>(key, &input, b"size-boundary", usize::MAX);
    input.push(0);
    assert!(V::encrypt_envelope(key, &input, b"size-boundary").is_err());
    assert!(V::decrypt_secret(key, &[&[0; 16][..], &input].concat()).is_err());
    let mut envelope = b"ARXK\x01\x00\x00\x00".to_vec();
    envelope[5] = V::VARIANT_ID;
    envelope.extend_from_slice(&[0; 16]);
    envelope.extend_from_slice(&input);
    assert!(V::decrypt_envelope(key, &envelope, b"size-boundary").is_err());
}
#[cfg(feature = "ex")]
#[test]
fn ex_maximum_and_oversized_input() {
    extended_boundary::<arx_kw::ex::EX>(&[0x42; 48]);
}
#[cfg(feature = "gx")]
#[test]
fn gx_maximum_and_oversized_input() {
    extended_boundary::<arx_kw::gx::GX>(&[0x42; 32]);
}
