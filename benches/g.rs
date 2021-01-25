extern crate criterion;
use criterion::{black_box,criterion_group,criterion_main,Criterion};
extern crate hex;
use hex::{FromHex};
use arx_kw::{
    ArxKW,
    g::G,
    AuthTag
};

fn bench_encrypt(c: &mut Criterion) {
    let k = <[u8;32]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
    let p = <[u8;32]>::from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef").unwrap();
    c.bench_function("G encrypt 32 byte plaintext", |b| b.iter(|| G::encrypt(black_box(&k), black_box(&p)).unwrap()));
}

fn bench_decrypt(c: &mut Criterion) {
    let k = <[u8;32]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
    let ciphertext = <[u8;32]>::from_hex("f63830f5148a039b6aacc4b9b6bc281d7704d906e4b5d91e045a62cdfc25eb10").unwrap();
    let t = AuthTag(<[u8;16]>::from_hex("016325cf6a3c4b2e3b039675e1ccbc65").unwrap());
    c.bench_function("G decrypt 32 byte ciphertext", |b| b.iter(|| G::decrypt(black_box(&k), black_box(&ciphertext), black_box(&t)).unwrap()));
}

criterion_group!(benches,bench_encrypt,bench_decrypt);
criterion_main!(benches);
