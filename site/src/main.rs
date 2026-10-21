use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd, html};
use std::{collections::HashMap, env, fs, io, path::PathBuf};
use stucco::{Meta, Raw, el, prelude::*};

const README: &str = include_str!("../../README.md");
const CHANGELOG: &str = include_str!("../../CHANGELOG.md");
const REVIEW: &str = include_str!("../../CODE_REVIEW.md");
const RELEASE: &str = include_str!("../../RELEASE.md");
const SITE_GUIDE: &str = include_str!("../README.md");
const REPO: &str = "https://github.com/mcaveniathor/arx-kw";

struct Site {
    base: String,
    bundle: Bundle,
}

impl Site {
    fn new(base: &str) -> io::Result<Self> {
        if !base.starts_with('/')
            || (base.contains("..") || base.contains("//"))
            || base.contains(['?', '#', '\\'])
            || !base
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "/-_".contains(c))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "base must be an absolute URL path",
            ));
        }
        let base = format!("{}/", base.trim_end_matches('/'));
        let bundle = Bundle::new(Preset::Slate).prefix(&format!("{base}_stucco/"));
        Ok(Self { base, bundle })
    }
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }
    fn frame(&self, title: &str, path: &str, content: impl Render) -> String {
        let mut navigation = el::nav().aria("label", "Primary").class("site-nav");
        for (name, target) in [
            ("Guide", "guide.html"),
            ("Security", "security.html"),
            ("Changelog", "changelog.html"),
            ("API", "doc/arx_kw/index.html"),
        ] {
            let mut link = el::a().href(self.url(target)).text(name);
            if target == path {
                link = link.aria("current", "page");
            }
            navigation = navigation.child(link);
        }
        let header = el::header()
            .class("site-header wrap")
            .child(
                el::a()
                    .class("brand")
                    .href(self.url(""))
                    .child(
                        el::span()
                            .class("brand-mark")
                            .aria("hidden", "true")
                            .text("[↔]"),
                    )
                    .text("ARX-KW"),
            )
            .child(navigation)
            .child(el::a().href(REPO).class("source-link").text("GitHub"));
        let footer = el::footer()
            .class("site-footer wrap")
            .child(
                el::div()
                    .child(el::strong().text("ARX-KW"))
                    .child(el::p().text("Key wrapping, written in Rust. MIT licensed.")),
            )
            .child(
                el::nav()
                    .aria("label", "Footer")
                    .child(el::a().href(self.url("release.html")).text("Release guide"))
                    .child(
                        el::a()
                            .href(self.url("review.html"))
                            .text("Implementation review"),
                    )
                    .child(
                        el::a()
                            .href("https://github.com/mcaveniathor/stucco")
                            .text("Built with Stucco"),
                    ),
            );
        Page::new(&self.bundle, format!("{title} · ARX-KW"))
            .server_theme(None)
            .meta(Meta::description("Deterministic, authenticated key wrapping in Rust. Learn the ARX-KW variants, context-bound envelopes, and security boundaries.")
                .canonical(format!("https://mcaveniathor.github.io{}", self.url(path))))
            .head((el::link().attr("rel", "stylesheet").href(self.url("assets/site.css")),
                el::link().attr("rel", "icon").attr("type", "image/svg+xml").href(self.url("assets/favicon.svg"))))
            .body(el::div().child(stucco::layout::SkipLink::new()).child(header).child(content).child(footer))
            .render()
    }
    fn home(&self) -> String {
        let intro = el::div().class("hero-copy")
            .child(el::p().class("eyebrow").text("RUST / DETERMINISTIC KEY WRAPPING"))
            .child(Heading::new(1, "Wrap keys. Keep the context.").display())
            .child(Text::new("Authenticated key wrapping without nonce bookkeeping. Four ARX-KW variants, one Rust API, and context-bound envelopes for new applications.").class("lead"))
            .child(el::div().class("hero-actions")
                .child(ButtonLink::new("Read the guide →", self.url("guide.html")).variant(Variant::Primary))
                .child(ButtonLink::new("Explore the API", self.url("doc/arx_kw/index.html"))))
            .child(el::p().class("release-note").text("0.4.0 release candidate · Rust 1.88+ · MIT"));
        let example = Card::new().class("example")
            .header(el::div().class("example-title").text("WRAP WITH A CONTEXT").child(el::span().text("Rust")))
            .child(el::pre().attr("tabindex", "0").child(el::code().text("use arx_kw::{gx::GX, ArxKW};\n\nlet envelope = GX::encrypt_envelope(\n    &wrapping_key,\n    &key_material,\n    b\"example.com/storage/v1\",\n)?;")))
            .footer(el::p().text("Supply a securely generated wrapping key and high-entropy key material."));
        let mut features = el::section()
            .class("feature-grid")
            .aria("label", "At a glance");
        for (number, title, description) in [
            (
                "01",
                "No nonce to manage",
                "Deterministic encryption derives its cipher inputs from the authentication tag.",
            ),
            (
                "02",
                "Bound to your application",
                "Versioned envelopes bind the format, variant, and your application context.",
            ),
            (
                "03",
                "Explicit secret ownership",
                "SecretKey and SecretBytes wipe their owned buffers and redact debug output.",
            ),
        ] {
            features = features.child(
                el::article()
                    .child(el::span().class("eyebrow").text(number))
                    .child(Heading::new(2, title).size(Size::Lg))
                    .child(Text::new(description)),
            );
        }
        let format = el::section().class("format-section")
            .child(el::div().child(el::p().class("eyebrow").text("ONE SELF-DESCRIBING ENVELOPE"))
                .child(Heading::new(2, "The bytes have a place."))
                .child(Text::new("Envelope v1 adds 24 bytes. The application context is supplied separately and bound through key derivation.")))
            .child(el::div().class("byte-layout").aria("label", "Envelope: 8-byte header, 16-byte authentication tag, then ciphertext")
                .child(el::div().class("byte-header").child(el::strong().text("Header")).child(el::span().text("8 bytes")))
                .child(el::div().class("byte-tag").child(el::strong().text("Authentication tag")).child(el::span().text("16 bytes")))
                .child(el::div().class("byte-cipher").child(el::strong().text("Ciphertext")).child(el::span().text("Your wrapped key"))));
        let safety = el::aside().class("safety-note")
            .child(el::strong().text("Designed for high-entropy keys."))
            .child(el::p().text("Determinism reveals repeated inputs within the same key and context. This implementation has not had an independent cryptographic audit."))
            .child(el::a().href(self.url("security.html")).text("Understand the security boundaries →"));
        self.frame(
            "Key wrapping in Rust",
            "",
            el::main()
                .id("main")
                .class("wrap landing")
                .child(el::section().class("hero").child(intro).child(example))
                .child(features)
                .child(format)
                .child(safety),
        )
    }
    fn document(&self, title: &str, path: &str, source: &str, description: &str) -> String {
        let source = source.split_once('\n').map_or(source, |(_, rest)| rest);
        let (content, headings) = markdown(source, &self.base);
        let mut toc = el::nav()
            .class("toc")
            .aria("label", "On this page")
            .child(el::p().class("eyebrow").text("ON THIS PAGE"));
        for (id, label) in headings {
            toc = toc.child(el::a().href(format!("#{id}")).text(label));
        }
        self.frame(
            title,
            path,
            el::main()
                .id("main")
                .class("wrap docs-layout")
                .child(
                    el::article()
                        .class("document")
                        .child(el::p().class("eyebrow").text("ARX-KW / DOCUMENTATION"))
                        .child(Heading::new(1, title).display())
                        .child(Text::new(description).class("lead"))
                        .child(el::div().class("prose").child(Raw::trusted(content))),
                )
                .child(el::aside().class("docs-sidebar").child(toc)),
        )
    }
}

fn markdown(source: &str, base: &str) -> (String, Vec<(String, String)>) {
    // Rustdoc's hidden scaffolding must not be shown as part of website examples.
    let mut rust = false;
    let cleaned = source
        .lines()
        .filter(|line| {
            if line.starts_with("```") {
                rust = !rust && line.starts_with("```rust");
                return true;
            }
            !(rust && (*line == "#" || line.starts_with("# ")))
        })
        .collect::<Vec<_>>()
        .join("\n");
    let mut events: Vec<_> = Parser::new_ext(
        &cleaned,
        Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH,
    )
    .collect();
    let mut headings = Vec::new();
    let mut seen = HashMap::<String, usize>::new();
    for index in 0..events.len() {
        if let Event::Start(Tag::Heading { level, .. }) = events[index] {
            let label: String = events[index + 1..]
                .iter()
                .take_while(|e| !matches!(e, Event::End(TagEnd::Heading(_))))
                .filter_map(|e| match e {
                    Event::Text(s) | Event::Code(s) => Some(s.as_ref()),
                    _ => None,
                })
                .collect();
            let slug = label
                .to_lowercase()
                .split(|c: char| !c.is_alphanumeric())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join("-");
            let occurrence = seen.entry(slug.clone()).or_default();
            let id = if *occurrence == 0 {
                slug
            } else {
                format!("{slug}-{occurrence}")
            };
            *occurrence += 1;
            events[index] = Event::Start(Tag::Heading {
                level,
                id: Some(id.clone().into()),
                classes: vec![],
                attrs: vec![],
            });
            if level == pulldown_cmark::HeadingLevel::H2 {
                headings.push((id, label));
            }
        }
    }
    for event in &mut events {
        if let Event::Start(Tag::Link { dest_url, .. }) = event {
            let prefix = format!("{REPO}/blob/main/");
            let target = match dest_url.strip_prefix(&prefix).unwrap_or(dest_url.as_ref()) {
                "site/README.md" => Some("site.html"),
                "CHANGELOG.md" => Some("changelog.html"),
                "CODE_REVIEW.md" => Some("review.html"),
                "RELEASE.md" => Some("release.html"),
                _ => None,
            };
            if let Some(target) = target {
                *dest_url = format!("{base}{target}").into();
            }
        }
    }
    let mut output = String::new();
    html::push_html(&mut output, events.into_iter());
    (output.replace("<pre>", "<pre tabindex=\"0\">"), headings)
}

fn section(source: &str, heading: &str) -> String {
    let marker = format!("## {heading}\n");
    let start = source
        .find(&marker)
        .expect("documented README section exists");
    let end = source[start + marker.len()..]
        .find("\n## ")
        .map_or(source.len(), |n| start + marker.len() + n);
    source[start..end].to_owned()
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let out = PathBuf::from(
        args.next()
            .ok_or("usage: arx-kw-site OUTPUT [--base /arx-kw/]")?,
    );
    let base = match args.next().as_deref() {
        None => "/arx-kw/".into(),
        Some("--base") => args.next().ok_or("--base requires a path")?,
        _ => return Err("unknown option".into()),
    };
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let site = Site::new(&base)?;
    fs::create_dir_all(&out)?;
    fs::create_dir_all(out.join("assets"))?;
    fs::write(out.join("index.html"), site.home())?;
    let security = format!(
        "# Security\n\n{}\n\n{}",
        section(README, "Security and input limits"),
        section(README, "Versioned envelopes and secret ownership")
    );
    for (name, title, source, description) in [
        (
            "site.html",
            "Website development",
            SITE_GUIDE,
            "Build, validate, and maintain the Stucco documentation site.",
        ),
        (
            "guide.html",
            "The guide",
            README,
            "Install the crate, choose a variant, and wrap your first key.",
        ),
        (
            "security.html",
            "Security boundaries",
            security.as_str(),
            "Input limits, determinism, context binding, and the scope of memory erasure.",
        ),
        (
            "changelog.html",
            "Changelog",
            CHANGELOG,
            "What changes in the next release, including compatibility and migration notes.",
        ),
        (
            "review.html",
            "Implementation review",
            REVIEW,
            "Findings, fixes, validation evidence, and the assurance boundary.",
        ),
        (
            "release.html",
            "Release guide",
            RELEASE,
            "Reproduce validation and prepare a registry publication.",
        ),
    ] {
        fs::write(
            out.join(name),
            site.document(title, name, source, description),
        )?;
    }
    fs::write(
        out.join("404.html"),
        site.frame(
            "Page not found",
            "404.html",
            el::main()
                .id("main")
                .class("wrap not-found")
                .child(Heading::new(1, "This page has moved or does not exist."))
                .child(ButtonLink::new(
                    "Return to the guide",
                    site.url("guide.html"),
                )),
        ),
    )?;
    let benchmarks = "# Benchmarks\n\nRun current Criterion benchmarks with `cargo bench`, or select a variant with `cargo bench --bench gx`.\n\nThe earlier published timing reports are historical and are not carried forward as measurements of this release. Local results are written under `target/criterion/`.\n\nPerformance depends on the CPU, compiler, features, and build configuration. The release validation performs functional benchmark smoke checks and does not claim timing improvements.";
    fs::write(
        out.join("benchmarks.html"),
        site.document(
            "Benchmarks",
            "benchmarks.html",
            benchmarks,
            "Measure the current implementation on your own hardware.",
        ),
    )?;
    fs::create_dir_all(out.join("criterion/reports"))?;
    fs::write(
        out.join("criterion/reports/index.html"),
        site.frame(
            "Benchmark reports",
            "criterion/reports/index.html",
            el::main()
                .id("main")
                .class("wrap not-found")
                .child(Heading::new(1, "Benchmark reports have moved."))
                .child(Text::new(
                    "Historical results are not measurements of the current implementation.",
                ))
                .child(ButtonLink::new(
                    "Run current benchmarks",
                    site.url("benchmarks.html"),
                )),
        ),
    )?;
    for path in site.bundle.paths() {
        let asset = site.bundle.get(&path).ok_or("missing Stucco asset")?;
        let relative = path
            .strip_prefix(&site.base)
            .ok_or("asset escaped base path")?;
        let destination = out.join(relative);
        fs::create_dir_all(destination.parent().ok_or("invalid asset path")?)?;
        fs::write(destination, asset.bytes)?;
    }
    fs::write(
        out.join("assets/site.css"),
        include_str!("../assets/site.css"),
    )?;
    fs::write(
        out.join("assets/favicon.svg"),
        include_str!("../assets/favicon.svg"),
    )?;
    fs::write(
        out.join("assets/stucco-license.txt"),
        include_str!("../assets/stucco-license.txt"),
    )?;
    fs::write(out.join(".nojekyll"), "")?;
    println!(
        "Built ARX-KW documentation at {} (base {})",
        out.display(),
        site.base
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
