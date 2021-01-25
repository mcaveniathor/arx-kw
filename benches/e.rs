extern crate hex;
extern crate criterion;
use criterion::{black_box,criterion_group,criterion_main,Criterion};
use hex::{FromHex};
use arx_kw::{
    ArxKW,
    e::E,
    AuthTag,
};

fn bench_encrypt(c: &mut Criterion) {
    let k = <[u8; 48]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f").unwrap();
    let p = <[u8; 32]>::from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef").unwrap();
    c.bench_function("E encrypt 32 byte plaintext", |b| b.iter(|| E::encrypt(black_box(&k), black_box(&p)).unwrap()));
}

fn bench_decrypt(c: &mut Criterion) {
    let ciphertext = <[u8; 32]>::from_hex("e6457d24abaf7c2ebdb91416a18366d31a66db61a4e45c9f42a119c353bb1eb1").unwrap();
    let k = <[u8; 48]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f").unwrap();
    let t = AuthTag(<[u8; 16]>::from_hex("c4f21d3b4dbcc566c3a73bbc59790f2f").unwrap());
    c.bench_function("E decrypt 32 byte ciphertext", |b| b.iter(|| E::decrypt(black_box(&k), black_box(&ciphertext), black_box(&t)).unwrap()));
}


criterion_group!(benches,bench_encrypt,bench_decrypt);
criterion_main!(benches);
