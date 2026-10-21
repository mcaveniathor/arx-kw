# Release 0.4.0

Prepared on branch `release/0.4.0`. This is a breaking release from 0.3.2;
review CHANGELOG.md and the README migration section before publishing.
Version 0.4.0 was not present on crates.io during preparation.

## Release contents

- Updates dependencies, docs, CI, malformed-input handling, and error privacy.
- Removes private-layout casts and the legacy runtime cipher provider.
- Adds bounded/fallible output allocation and owned secret-memory handling.
- Adds versioned, context-bound envelopes while preserving legacy paper vectors.
- Requires Rust 1.88 and removes the obsolete `nightly` feature.

## Reproduce validation

From the checkout, activate the installed tools:

```sh
export CARGO_HOME=/workspace/.cargo RUSTUP_HOME=/workspace/.rustup
export PATH="$CARGO_HOME/bin:$PATH"
cargo +1.99.1 fmt --check
cargo +1.99.1 clippy --all-targets --all-features --locked -- -D warnings
cargo +1.99.1 test --all-features --locked
cargo +1.88.0 test --all-features --locked
for feature in e g ex gx; do
  cargo +1.99.1 test --no-default-features --features "$feature" --locked || exit $?
done
cargo +1.99.1 test --no-default-features --locked
cargo +1.99.1 bench --all-features --locked -- --test
RUSTDOCFLAGS='-D warnings' cargo +1.99.1 doc --no-deps --all-features --locked
cargo audit
cargo +1.99.1 publish --dry-run --locked
```

The library intentionally ignores Cargo.lock in Git. The prepared workspace
retains its resolved lockfile; a fresh clone must first generate one. Hosted CI
resolves current dependencies to test consumer compatibility. Do not disable
package integrity checks or skip the verification build.

## Publication

The preparation task does not push, tag, publish, or change registry ownership.
After reviewing the release commit and passing hosted CI, publish from this
branch with a crates.io account authorized for this crate:

```sh
cargo +1.99.1 publish --locked
```

Create/push the release tag and GitHub release only after the registry accepts
the package. Keep the release notes aligned with CHANGELOG.md. Enter registry
credentials through the normal secure credential mechanism; do not store them
in repository files or logs.

## Assurance scope

Implementation and compatibility tests do not replace an independent audit of
the construction, the new envelope protocol, or its implementation. Zeroization
covers owned buffers and state, not every possible compiler/register/provider
copy or caller-owned data. A formal constant-time proof and an independent
cryptographic audit require separate expert review; neither is claimed here.
