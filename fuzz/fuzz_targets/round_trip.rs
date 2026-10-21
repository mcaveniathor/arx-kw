#![no_main]
use libfuzzer_sys::fuzz_target;
mod input;
#[path = "../../tests/support/mod.rs"]
#[allow(dead_code)]
mod support;

fuzz_target!(|data: &[u8]| {
    if let Some((key, context, payload, mutation)) = input::split(data) {
        let key32 = std::array::from_fn(|i| key[i]);
        support::round_trip::<arx_kw::e::E>(&key, payload, context, mutation);
        support::round_trip::<arx_kw::g::G>(&key32, payload, context, mutation);
        support::round_trip::<arx_kw::ex::EX>(&key, payload, context, mutation);
        support::round_trip::<arx_kw::gx::GX>(&key32, payload, context, mutation);
    }
});
