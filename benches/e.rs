#![feature(test)]

#[cfg(test)]
mod e {
    extern crate test;
    extern crate hex;
    use hex::{FromHex};
    use test::{Bencher,black_box};
    use arx_kw::{
        ArxKW,
        e::E,
        AuthTag,
    };

    #[bench]
    fn bench_encrypt(b: &mut Bencher) {
        let k = <[u8; 48]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f").unwrap();
        let p = <[u8; 32]>::from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef").unwrap();
        b.iter(|| {
            black_box(E::encrypt(&k, &p).unwrap());
        });
    }

    #[bench]
    fn bench_decrypt(b: &mut Bencher) {
        let c = <[u8; 32]>::from_hex("e6457d24abaf7c2ebdb91416a18366d31a66db61a4e45c9f42a119c353bb1eb1").unwrap();
        let k = <[u8; 48]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f").unwrap();
        let t = AuthTag(<[u8; 16]>::from_hex("c4f21d3b4dbcc566c3a73bbc59790f2f").unwrap());
        b.iter(|| {
            black_box(E::decrypt(&k, &c, &t).unwrap());
        });
    }
}
