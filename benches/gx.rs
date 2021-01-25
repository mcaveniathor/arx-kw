extern crate criterion;
use criterion::{black_box,criterion_group,criterion_main,Criterion};
extern crate hex;
use hex::{FromHex};
use arx_kw::{
    ArxKW,
    gx::GX,
    AuthTag
};

fn bench_encrypt(c: &mut Criterion) {
    let k = <[u8; 32]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
    let p = <[u8; 32]>::from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef").unwrap();
    c.bench_function("GX encrypt 32 byte plaintext", |b| b.iter(|| GX::encrypt(black_box(&k), black_box(&p)).unwrap()));
}

fn bench_decrypt(c: &mut Criterion) {
    let k = <[u8; 32]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
    let t = AuthTag(<[u8; 16]>::from_hex("016325cf6a3c4b2e3b039675e1ccbc65").unwrap());
    let ciphertext = <[u8; 32]>::from_hex("2f83f391c97f3606ccd5709c6ee15d66cd7e65a2aeb7dc3066636e8f6b0d39c3").unwrap();
    c.bench_function("GX decrypt 32 byte plaintext", |b| b.iter(|| GX::decrypt(black_box(&k), black_box(&ciphertext), black_box(&t)).unwrap()));
}

criterion_group!(benches,bench_encrypt,bench_decrypt);
criterion_main!(benches);
