# ARX-KW release guidance

This directory contains Symposiast tooling and recipes for the **published
arx-kw 0.5.0** crate. The full bundle preserves source evidence, citations,
consumer projects, lockfiles, and actual compilation records. The portable
Symposium entry contains release-gated skills and recipes with their evidence.
Neither is included in the published library's runtime dependencies or package.

| Recipe | Features (defaults disabled) | Runtime assertions |
| --- | --- | --- |
| `wrap-key` | `gx,envelope` | Recovery and wrong-tenant-context rejection |
| `rotate-key` | `gx,envelope` | Data key preserved; old wrapping key rejected |
| `detached-tag` | `g` | Recovery and modified-tag rejection |

Each recipe uses `arx-kw = "=0.5.0"` and OS randomness from `getrandom = "=0.4.3"`.
The programs are copied from the published examples and use secret-erasing guards.
They demonstrate wrapping operations; applications still manage durable wrapping
keys, transactional rotation, context encoding, and replay/rollback protection.

- [Full bundle](arx-kw-0.5.0/bundle/bundle.json)
- [Imported analysis](arx-kw-0.5.0/analysis.json)
- [Generation and runtime validation record](arx-kw-0.5.0/generation.json)
- [Portable skill](registry/arx-kw-0.5.0/skills/arx-kw-38682d14-guide/SKILL.md)

## Validate the guidance

Install the generator from its recorded source commit (Rust 1.99.1 was used):

```sh
cargo install --git https://github.com/mcaveniathor/symposiast \
  --rev 2ad0f3e2d8f6b043a9a600a9788da498a20e87fe --locked symposiast
python dev/check-guidance.py
```

Run commands from the repository root. `--symposiast /path/to/symposiast` selects
an existing installation. After dependencies are cached, add `--offline`.
The checker works in a temporary directory and leaves the frozen bundle unchanged.
It compares the portable export, rechecks and runs all three recipes, checks exact
registry versions/checksums and feature declarations, tests MCP retrieval, and
checks a version-drift warning using a synthetic 0.4.0 lockfile. CI runs this check.
No provider login or analysis subprocess is required for verification.

To run an individual frozen consumer directly:

```sh
cargo run --locked --manifest-path guidance/arx-kw-0.5.0/bundle/verification/wrap-key/Cargo.toml
```

## Use the portable Symposium skill

Add this local registry to your existing Symposium configuration, substituting
an absolute checkout path:

```toml
[[registry]]
name = "arx-kw-guidance"
path = "/path/to/arx-kw/guidance/registry"
```

Then run `cargo agents sync` in the consuming Rust project and inspect
`cargo agents status`. Symposium is a separate installation; the portable entry
does not require Symposiast. Its dependency predicate targets exactly 0.5.0.
Confirm the consumer's source and resolved version before using the recipes.
See [Symposiast registry documentation](https://github.com/mcaveniathor/symposiast/blob/2ad0f3e2d8f6b043a9a600a9788da498a20e87fe/docs/registry.md).

## Use MCP retrieval and version checks

For the full runtime plugin, install the bundle with Symposiast, then sync from
the consuming workspace:

```sh
symposiast install guidance/arx-kw-0.5.0/bundle
# In the consuming Rust project:
cargo agents sync
cargo agents status
```

`install` regenerates machine-specific executable and bundle paths; generated
`bundle/plugin` files are ignored in this repository. Restart the consuming MCP
session if needed. Use one distribution of the skill in a workspace: the full
runtime plugin and portable entry share its identity. Check `get_release_info`
before `search_guidance` and `get_recipe`; a stale server can outlive a dependency
upgrade. Installation and consumer-wide synchronization have not been performed
by this repository's validation.

The standalone interfaces are:

```sh
symposiast serve guidance/arx-kw-0.5.0/bundle
symposiast check guidance/arx-kw-0.5.0/bundle --workspace /path/to/consumer
```

`serve` uses newline-delimited MCP over standard input/output. `check` emits
advisory warnings; an empty result can also mean no matching lockfile/package,
so independently confirm that the intended dependency was found.

## Reproduce or revise this release's bundle

Use new paths; collection and registry export preserve existing destinations:

```sh
symposiast collect arx-kw --version 0.5.0 --output /tmp/arx-kw-guidance-new/bundle
python dev/add-guidance-license.py /tmp/arx-kw-guidance-new/bundle
symposiast analyze /tmp/arx-kw-guidance-new/bundle \
  --analysis guidance/arx-kw-0.5.0/analysis.json
symposiast export-registry /tmp/arx-kw-guidance-new/bundle \
  --output /tmp/arx-kw-guidance-new/registry/arx-kw-0.5.0
```

The license supplement verifies the published archive checksum before retaining
its MIT notice; the pinned collector does not select that notice itself. Keep the
license source in full and portable distributions. Analysis import validates
citations and compiles recipes. Recollection timestamps and compiler logs may
differ; compare release identity, evidence hashes, recipe fingerprints, lockfiles,
and the reviewed content. A new crate version requires new collection and analysis;
do not reuse these citations without checking its evidence.

## Scope and recorded evidence

The published crate SHA-256 is
`cbb86bc1a4850f71f13be89e8c20c65b784928b486b02e9babd1db38aea1925a`,
from source commit `9fee6602ffb20a1d50e30615d131031884d5df1e`.
The analysis was imported as structured data; `review` remains `null` because no
separate review was performed. Symposiast's `compiled` status means
`cargo check --locked --all-targets` passed. Separate runtime runs are recorded
in generation.json and consumer run logs. Linux x86_64/Rust 1.99.1 validation
does not establish compatibility on every consumer platform or cryptographic
security.

The collector bounds evidence to 48 files, 48 KiB per file, and 320 KiB total;
it does not crawl rendered or external documentation. It rejected one special
entry in the pinned repository archive. The documentation inventory contains
eight Rust snippets: one supports the envelope recipes, and seven are explicitly
skipped because they cover legacy blob vectors or low-level nonce construction.
Standalone example programs are separate evidence. Nonliteral rustdoc includes
are not expanded. All collection/inventory warnings are retained in the bundle.
