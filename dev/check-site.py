#!/usr/bin/env python3
"""Validate generated documentation, including project-base links and assets."""
import argparse
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit


class Document(HTMLParser):
    def __init__(self, path):
        super().__init__(convert_charrefs=True)
        self.ids, self.links, self.counts = set(), [], {}
        self.stucco_css = False
        self.focusable_code = True
        self.feed(path.read_text())

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.counts[tag] = self.counts.get(tag, 0) + 1
        if tag == "pre":
            self.focusable_code &= attrs.get("tabindex") == "0"
        if "id" in attrs:
            if attrs["id"] in self.ids:
                raise AssertionError(f"duplicate id {attrs['id']}")
            self.ids.add(attrs["id"])
        for attribute in ("href", "src"):
            if attrs.get(attribute):
                self.links.append(attrs[attribute])
        if tag == "link" and attrs.get("rel") == "stylesheet":
            self.stucco_css |= "/_stucco/" in attrs.get("href", "")


def check(root, base):
    root = root.resolve()
    assert base.startswith("/") and base.endswith("/") and "//" not in base
    pages = sorted(root.glob("*.html"))
    assert len(pages) >= 8, "documentation pages missing"
    assert (root / ".nojekyll").exists(), "Jekyll bypass missing"
    assert (root / "doc/arx_kw/index.html").exists(), "API reference missing"
    cache = {}
    for path in pages:
        doc = Document(path)
        cache[path] = doc
        assert doc.counts.get("main") == 1, f"{path.name}: expected one main landmark"
        assert doc.counts.get("h1") == 1, f"{path.name}: expected one page heading"
        assert doc.focusable_code, f"{path.name}: code blocks must support keyboard scrolling"
        assert doc.stucco_css, f"{path.name}: missing Stucco stylesheet"
        assert "main" in doc.ids and "#main" in doc.links, f"{path.name}: missing skip link"
    checked = 0
    for path, doc in list(cache.items()):
        for link in doc.links:
            if urlsplit(link).scheme or link.startswith("//"):
                continue
            resolved = urlsplit(urljoin(base + path.name, link))
            assert resolved.path.startswith(base), f"{path.name}: link escaped base: {link}"
            target = (root / unquote(resolved.path[len(base):])).resolve()
            assert target.is_relative_to(root), f"link escaped output directory: {link}"
            if target.is_dir():
                target = target / "index.html"
            assert target.is_file(), f"{path.name}: missing target {link}"
            if resolved.fragment and target.suffix == ".html":
                if target not in cache:
                    cache[target] = Document(target)
                assert unquote(resolved.fragment) in cache[target].ids, f"{path.name}: missing anchor {link}"
            checked += 1
    legacy = root / "criterion/reports/index.html"
    assert legacy.exists(), "legacy benchmark entry point missing"
    print(f"Validated {len(pages)} pages and {checked} local links/assets for base {base}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--base", default="/arx-kw/")
    args = parser.parse_args()
    check(args.root, args.base)
