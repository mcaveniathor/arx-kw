# Releasing ARX-KW

This guide covers the 0.5.0 release. Review the changelog, README migration
section, and implementation review before tagging. Release
preparation does not publish a crate or push a tag.

## One-time repository setup

1. In GitHub repository settings, select **GitHub Actions** as the Pages source.
   The Pages workflow publishes the Stucco site; the legacy `gh-pages` branch
   remains intact and is no longer the source. If the existing `github-pages`
   environment restricts deployment branches, allow `main`.
2. Create a GitHub Actions environment named `crates-io`. Configure any required
   reviewers there to control when the publication job may start.
3. In the crate's crates.io settings, add a **GitHub trusted publisher** with:

   | Setting | Value |
   | --- | --- |
   | Repository owner | `mcaveniathor` |
   | Repository | `arx-kw` |
   | Workflow filename | `release.yml` |
   | Environment | `crates-io` |

   Use the exact filename and environment name. The official
   `rust-lang/crates-io-auth-action` exchanges GitHub's OIDC identity for a
   temporary registry token and revokes it after the job. No stored
   `CARGO_REGISTRY_TOKEN` secret is required. See
   [crates.io trusted publishing](https://crates.io/docs/trusted-publishing).

GitHub Pages and crates.io configuration are external prerequisites. Committing
the workflow files does not enable or validate either service configuration.

## CI and pre-release checks

CI tests stable Rust and the minimum supported Rust 1.88 on Linux, macOS, and
Windows. Linux jobs check feature combinations, benchmark smoke tests, strict
Clippy, formatting, workflow syntax, release guardrails, and the built Stucco
site with its generated API reference. A separate weekly dependency audit
checks both the library and website lockfiles. External actions are pinned to immutable commits, annotated with their versions.
The SLSA reusable generator is the exception: upstream requires a full semantic
version tag (`v2.1.0`) so its signing identity can be verified.

The library intentionally ignores Cargo.lock to exercise current dependency
resolution. CI generates a lockfile and uses `--locked` for subsequent steps.
The site's lockfile is committed because it is a private build tool.

From the checkout, using an installed Rust toolchain and Python 3.11 or newer:

```sh
cargo generate-lockfile
cargo fmt --check
cargo fmt --manifest-path site/Cargo.toml --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo clippy --all-targets --no-default-features --locked -- -D warnings
cargo clippy --manifest-path site/Cargo.toml --locked -- -D warnings
cargo test --all-features --locked
cargo +1.88.0 test --all-features --locked
for feature in e g ex gx; do
  cargo test --no-default-features --features "$feature" --locked || exit $?
  cargo test --no-default-features --features "$feature,envelope" --locked || exit $?
done
cargo test --no-default-features --locked
cargo test --no-default-features --features envelope --locked
python dev/check-features.py
cargo run --example wrap_key --no-default-features --features gx,envelope --locked
cargo run --example rotate_key --no-default-features --features gx,envelope --locked
cargo run --example detached_tag --no-default-features --features g --locked
cargo bench --all-features --locked -- --test
python -B -m unittest discover -s dev/tests -v
cargo run --manifest-path site/Cargo.toml --locked -- target/pages --base /arx-kw/
cargo clean --doc
RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --all-features --locked
mkdir -p target/pages/doc
cp -R target/doc/. target/pages/doc/
python dev/check-site.py target/pages --base /arx-kw/
cargo audit
cargo audit --file site/Cargo.lock
```

Install cargo-audit with `cargo install cargo-audit --version 0.22.2 --locked`.
Install the checksum-verified workflow linter with
`python dev/install-actionlint.py /tmp/actionlint`, then run `/tmp/actionlint`.
The installer supports Linux x86-64, matching CI's lint runner.
Do not bypass package verification or artifact checksums.

Release jobs pin Rust/Cargo 1.99.1 in both verification and publication so
archive reproduction is unaffected by a later stable-toolchain update during
an environment approval. CI continues to test current stable Rust and the MSRV.

## Tag and publish

Version 0.5.0 makes `envelope` optional, changing explicitly reduced-feature
builds. This is a new breaking version, rather than a 0.4.x patch. Published
0.4.0 and its tag remain immutable.

1. Update `Cargo.toml`, changelog, release status in the README, and landing-page
   version label together. Finalize the release notes and any unreleased label.
2. Merge the reviewed changes into `main` and wait for CI to pass. The release
   workflow requires a successful push-triggered main CI run for that exact
   commit and rejects tags outside `main` history.
3. Create and push the matching version tag when publication is intended:

   ```sh
   git switch main
   git pull --ff-only
   git tag -a v0.5.0 -m 'Release 0.5.0'
   git push origin v0.5.0
   ```

Pushing the tag starts `.github/workflows/release.yml`:

- **Verify:** check tag/version equality, main ancestry, successful CI, clean source, tests,
  MSRV, linting, site links, and both dependency audits. Run a registry publish
  dry run, then explicitly retain the archive with `cargo package`; verify its
  version and clean VCS commit; record SHA-256
  and changelog release notes.
- **Provenance:** pass the verified crate's SHA-256 to the isolated upstream
  SLSA generator. Sign keylessly using GitHub OIDC and record the signing event
  in Sigstore's public transparency log. This job has no registry credentials
  and does not create a GitHub release. GitHub requires the caller to grant
  `contents: write` because the reusable workflow declares an optional upload
  job, even though `upload-assets: false` keeps that job disabled.
- **Publish:** download the verified archive, lockfile, and signed provenance.
  Verify the artifact digest, source repository, exact version tag, and trusted
  generator identity using `slsa-verifier`. Rebuild the package and compare it
  byte for byte. Only then obtain registry credentials through trusted publishing
  and publish with the same lockfile.
- **GitHub release:** only after registry publication succeeds, create the
  release and attach the verified `.crate`, `SHA256SUMS`, and
  `arx-kw.intoto.jsonl` signed provenance. Cargo versions
  with a prerelease suffix produce a GitHub prerelease.

The verified package and lockfile are also retained as a workflow artifact for
14 days. The source archive includes the lockfile but excludes website and CI
build tooling from the published library.

## Retry and failure handling

Correct an external configuration failure and use **Re-run failed jobs**. The
manual workflow can also be dispatched against the same tag, never against a
branch. An already published registry version is accepted only if its downloaded
archive has exactly the verified SHA-256; a different archive aborts the run.
GitHub release attachments can be retried after a successful registry publish.

A crates.io upload cannot be undone by deleting a GitHub release or tag. Never
move a published version tag to different source, or change expected checksums
to force a retry. Fix source problems in a new patch release.

## Assurance scope

Implementation and compatibility tests do not replace an independent audit of
the construction, envelope protocol, or implementation. Zeroization covers
owned buffers and state, not every compiler/register/provider copy or
caller-owned data. Neither a formal constant-time proof nor an independent
cryptographic audit is claimed by release automation.

## Verify release provenance

Install [slsa-verifier](https://github.com/slsa-framework/slsa-verifier) v2.7.1
from its verified distribution or build its tagged source. Download the crate
and signed provenance from the same GitHub release, then run:

```sh
gh release download v0.5.0 --repo mcaveniathor/arx-kw \
  --pattern 'arx-kw-0.5.0.crate' --pattern arx-kw.intoto.jsonl
slsa-verifier verify-artifact arx-kw-0.5.0.crate \
  --provenance-path arx-kw.intoto.jsonl \
  --source-uri github.com/mcaveniathor/arx-kw \
  --source-tag v0.5.0 \
  --builder-id 'https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0'
```

The same verification can be applied to the `.crate` downloaded from crates.io;
its bytes must match the attested digest. A checksum alone does not authenticate
an artifact. Verification failures must block publication; do not disable the
provenance dependency or substitute an unsigned statement.

This integration uses the upstream generic SLSA Build Level 3 generator and its
isolated signing workflow. It attests the caller-supplied crate digest and source
identity; it does not make dependencies hermetic, establish reproducible compiled
binaries, or certify cryptographic correctness. The initial tagged hosted run
must succeed before provenance is available or end-to-end verification can be
claimed. No historical release is retroactively attested. Generator signing
requires access to GitHub OIDC and Sigstore services; do not run it on a
self-hosted replacement or grant the generator registry secrets.
