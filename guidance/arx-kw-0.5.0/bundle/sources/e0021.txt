#![cfg(all(
    feature = "envelope",
    any(feature = "e", feature = "g", feature = "ex", feature = "gx")
))]

use arx_kw::ArxKW;
use std::convert::{TryFrom, TryInto};

fn check<V: ArxKW>(name: &str)
where
    for<'a> V::Key: TryFrom<&'a [u8]>,
    for<'a> <V::Key as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
{
    let mut count = 0;
    for line in include_str!("vectors/envelope-v1.tsv").lines() {
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 5);
        if fields[0] != name {
            continue;
        }
        let key_bytes = hex::decode(fields[1]).unwrap();
        let key: V::Key = key_bytes.as_slice().try_into().unwrap();
        let plaintext = hex::decode(fields[2]).unwrap();
        let context = hex::decode(fields[3]).unwrap();
        let expected = hex::decode(fields[4]).unwrap();
        assert_eq!(
            V::encrypt_envelope(&key, &plaintext, &context).unwrap(),
            expected
        );
        assert_eq!(
            V::decrypt_envelope(&key, &expected, &context)
                .unwrap()
                .as_ref(),
            plaintext
        );
        count += 1;
    }
    assert_eq!(count, 4);
}

#[cfg(feature = "e")]
#[test]
fn e_v040_envelope_vectors() {
    check::<arx_kw::e::E>("e");
}
#[cfg(feature = "g")]
#[test]
fn g_v040_envelope_vectors() {
    check::<arx_kw::g::G>("g");
}
#[cfg(feature = "ex")]
#[test]
fn ex_v040_envelope_vectors() {
    check::<arx_kw::ex::EX>("ex");
}
#[cfg(feature = "gx")]
#[test]
fn gx_v040_envelope_vectors() {
    check::<arx_kw::gx::GX>("gx");
}
