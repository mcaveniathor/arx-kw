#![feature(test)]

#[cfg(test)]
mod g {
    extern crate test;
    extern crate hex;
    use hex::{FromHex};
    use test::{Bencher,black_box};
    use arx_kw::{
        ArxKW,
        gx::GX,
    };

    #[bench]
    fn bench_encrypt(b: &mut Bencher) {
        let k = <[u8; 32]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let p = <[u8; 32]>::from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef").unwrap();
        b.iter(|| {
            black_box(GX::encrypt(&k, &p).unwrap());
        });
    }

    #[bench]
    fn bench_decrypt(b: &mut Bencher) {
        let k = <[u8; 32]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let t = <[u8; 16]>::from_hex("016325cf6a3c4b2e3b039675e1ccbc65").unwrap();
        let c = <[u8; 32]>::from_hex("2f83f391c97f3606ccd5709c6ee15d66cd7e65a2aeb7dc3066636e8f6b0d39c3").unwrap();
        b.iter(|| {
            black_box(GX::decrypt(&k, &c, &t).unwrap());
        });
    }
}
