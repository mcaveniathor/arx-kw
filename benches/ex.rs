extern crate criterion;
use criterion::{black_box,criterion_group,criterion_main,Criterion};
extern crate hex;
use hex::{FromHex};
use arx_kw::{
    ArxKW,
    ex::EX,
    AuthTag
};

/* 
 * Benchmarks using the test vectors provided in the ARX-KW paper
 */

fn bench_encrypt(c: &mut Criterion) {
    let k = <[u8; 48]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f").unwrap();
    let p = <[u8; 32]>::from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef").unwrap();
    c.bench_function("EX encrypt 32 byte plaintext", |b| b.iter(|| EX::encrypt(black_box(&k), black_box(&p)).unwrap()));
}

fn bench_decrypt(c: &mut Criterion) {
    let k = <[u8; 48]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f").unwrap();
    let t = AuthTag(<[u8; 16]>::from_hex("c4f21d3b4dbcc566c3a73bbc59790f2f").unwrap());
    let ciphertext = <[u8; 32]>::from_hex("02a55ab1d7f549db160e8ecb33e1c6d65a05d0ebaba54dc0712285787c8a62db").unwrap();
    c.bench_function("EX decrypt 32 byte ciphertext", |b| b.iter(|| EX::decrypt(black_box(&k), black_box(&ciphertext), black_box(&t)).unwrap()));
}


criterion_group!(benches,bench_encrypt,bench_decrypt);
criterion_main!(benches);
