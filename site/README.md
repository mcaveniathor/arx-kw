# Website development

The GitHub Pages site is generated in Rust with
[Stucco 0.5](https://github.com/mcaveniathor/stucco). Stucco supplies the semantic
components, accessible skip link, validated Slate theme, and hashed assets.
Site-specific layout and prose styles live in `assets/site.css`. The site
follows the browser's light/dark preference and works without JavaScript.

## Build locally

From the repository root, using Rust 1.88 or newer and Python 3.11 or newer:

```sh
cargo run --manifest-path site/Cargo.toml --locked -- target/pages/arx-kw --base /arx-kw/
cargo clean --doc
cargo doc --all-features --no-deps
mkdir -p target/pages/arx-kw/doc
cp -R target/doc/. target/pages/arx-kw/doc/
python dev/check-site.py target/pages/arx-kw --base /arx-kw/
python -m http.server 8000 --directory target/pages
```

Open the project's `/arx-kw/` path on your local server. To host the site at
the domain root instead, build with `--base /` and serve that output directory.
The explicit base path applies to every page, canonical URL, and Stucco asset.
The library's generated API reference retains the existing `doc/arx_kw/` path.
The previous Criterion report entry points to instructions for running current
benchmarks; historical timings are not presented as current release results.

## Content sources

| Output | Source |
| --- | --- |
| Landing page | Stucco components in `site/src/main.rs` |
| Guide | Root `README.md` |
| Security | Security and envelope sections of the root README |
| Changelog | `CHANGELOG.md` |
| Implementation review | `CODE_REVIEW.md` |
| Release guide | `RELEASE.md` |
| Website development | This file |
cargo clean --doc
| API reference | `cargo doc --all-features --no-deps` |

Update these Markdown files rather than editing generated HTML. Rustdoc-hidden
example scaffolding is omitted on the website. Heading anchors and the sidebar
are generated together. The independent `site/Cargo.toml` and committed lockfile
keep website tooling out of the cryptography library's runtime dependencies.
The command writes its own files without deleting other content in the output
folder; build into an empty output folder for a deployment.

## Validation

```sh
cargo fmt --manifest-path site/Cargo.toml --check
cargo clippy --manifest-path site/Cargo.toml --locked -- -D warnings
python dev/check-site.py target/pages/arx-kw --base /arx-kw/
```

The checker verifies the rendered site's landmarks, headings, navigation,
local links and fragments, stylesheets, and project-prefixed asset paths.
CI performs this check on the exact Pages artifact, including the API reference.

## Deployment

The Pages workflow builds the static site and API documentation, checks links,
and uploads the complete artifact. On `main`, it deploys to the `github-pages`
environment using GitHub's Pages actions. Select **GitHub Actions** as the Pages
source in repository settings. The legacy `gh-pages` branch is preserved but
is no longer the publishing source. CI also builds the site on pull requests,
without publishing it. No production preview is created by a local build.
