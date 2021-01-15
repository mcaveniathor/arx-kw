#![feature(test)]

#[cfg(test)]
mod g {
    extern crate test;
    extern crate hex;
    use hex::{FromHex};
    use test::{Bencher,black_box};
    use arx_kw::{
        ArxKW,
        ex::EX
    };

    /* 
     * Benchmarks using the test vectors provided in the ARX-KW paper
     */

    #[bench]
    fn bench_encrypt(b: &mut Bencher) {
        let k = <[u8; 48]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f").unwrap();
        let p = <[u8; 32]>::from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef").unwrap();
        b.iter(|| {
            black_box(EX::encrypt(&k, &p).unwrap());
        });
    }

    #[bench]
    fn bench_decrypt(b: &mut Bencher) {
        let k = <[u8; 48]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f").unwrap();
        let t = <[u8; 16]>::from_hex("c4f21d3b4dbcc566c3a73bbc59790f2f").unwrap();
        let c = <[u8; 32]>::from_hex("02a55ab1d7f549db160e8ecb33e1c6d65a05d0ebaba54dc0712285787c8a62db").unwrap();
        b.iter(|| {
            black_box(EX::decrypt(&k, &c, &t).unwrap());
        });
    }
}
