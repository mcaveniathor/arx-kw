# Instrumented fuzzing

These development-only targets require nightly Rust, a C++ compiler, and
`cargo-fuzz`. They live in a separate, unpublished workspace excluded from the
library package. Runtime dependencies and the library MSRV are unaffected.

From the repository root:

```sh
rustup toolchain install nightly-2026-10-21 --profile minimal --component rust-src
cargo install cargo-fuzz --version 0.13.2 --locked
cargo fetch --manifest-path fuzz/Cargo.toml --locked
python dev/seed-fuzz.py
CARGO_NET_OFFLINE=true cargo +nightly-2026-10-21 fuzz run envelope -- -max_total_time=300 -max_len=8192 -timeout=10 -rss_limit_mb=2048
CARGO_NET_OFFLINE=true cargo +nightly-2026-10-21 fuzz run round_trip -- -max_total_time=300 -max_len=8192 -timeout=10 -rss_limit_mb=2048
```

`envelope` tries arbitrary envelopes and legacy blobs for all four variants.
Accepted data must encrypt back to the same bytes. `round_trip` tests generated
keys and plaintext, determinism, and rejection after key, context, tag/ciphertext,
and truncation changes. Both targets share assertions with the Proptest suite.
Seeds include the frozen 0.4.0 envelope vectors. The first 48 input bytes hold
key material, the next four encode context length and mutation offset, and the
remaining bytes hold context followed by payload.

CI runs each target for 30 seconds using libFuzzer coverage instrumentation and
AddressSanitizer. This is a smoke check, not evidence of exhaustive fuzzing.
Inputs are bounded to 8192 bytes to keep feedback fast; deterministic integration
tests separately exercise the one-MiB EX/GX limits and 4096-byte context limit.

Crashes are saved under `fuzz/artifacts/<target>/`. Replay a finding with:

```sh
CARGO_NET_OFFLINE=true cargo +nightly-2026-10-21 fuzz run envelope fuzz/artifacts/envelope/<artifact>
```

Keep the reproducer and convert confirmed bugs into permanent regression tests.
Use synthetic data. Corpus files and artifacts are ignored; dependency resolution
is recorded in `fuzz/Cargo.lock`. Cargo-fuzz has no `--locked` flag; fetch the
locked dependencies first and run offline. CI also checks that the lockfile
remains unchanged.

Run property tests separately with `cargo test --all-features --test properties`.
`PROPTEST_CASES=2048` increases generated cases; `PROPTEST_RNG_SEED=<u64>` fixes
random generation for reproduction. Proptest's saved regression files should be
retained when they reproduce a confirmed bug.
