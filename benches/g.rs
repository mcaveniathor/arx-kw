#![feature(test)]

#[cfg(test)]
mod g {
    extern crate test;
    extern crate hex;
    use hex::{FromHex};
    use test::{Bencher,black_box};
    use arx_kw::{
        ArxKW,
        g::G,
    };

    #[bench]
    fn bench_encrypt(b: &mut Bencher) {
        let k = <[u8;32]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let p = <[u8;32]>::from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef").unwrap();
        b.iter(|| {
            black_box(G::encrypt(&k, &p).unwrap());
        });
    }

    #[bench]
    fn bench_decrypt(b: &mut Bencher) {
        let k = <[u8;32]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let c = <[u8;32]>::from_hex("f63830f5148a039b6aacc4b9b6bc281d7704d906e4b5d91e045a62cdfc25eb10").unwrap();
        let t = <[u8;16]>::from_hex("016325cf6a3c4b2e3b039675e1ccbc65").unwrap();
        b.iter(|| {
            black_box(G::decrypt(&k, &c, &t).unwrap());
        });
    }
}
