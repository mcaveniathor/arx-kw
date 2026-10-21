#!/usr/bin/env python3
"""Release metadata, package provenance, and immutable registry checks (no uploads)."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tomllib
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent.parent


def metadata(tag, manifest=None):
    package = (manifest or tomllib.loads((ROOT / "Cargo.toml").read_text()))["package"]
    name, version = package["name"], package["version"]
    if name != "arx-kw":
        raise ValueError("release workflow only publishes arx-kw")
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", version):
        raise ValueError("unsupported release version")
    if tag != f"v{version}":
        raise ValueError(f"tag {tag!r} must match Cargo.toml version v{version}")
    return {"name": name, "version": version, "tag": tag, "prerelease": "-" in version}


def verify_archive(archive, head, version):
    with tarfile.open(archive, "r:gz") as tar:
        prefix = f"arx-kw-{version}/"
        vcs = json.load(tar.extractfile(prefix + ".cargo_vcs_info.json"))["git"]
        manifest = tomllib.loads(tar.extractfile(prefix + "Cargo.toml").read().decode())
    if vcs.get("sha1") != head or vcs.get("dirty", False):
        raise ValueError("package must contain the clean tagged commit")
    if manifest["package"].get("name") != "arx-kw" or manifest["package"]["version"] != version:
        raise ValueError("package version differs from release")


def notes(changelog, version):
    heading = re.search(rf"^## {re.escape(version)}(?:\s.*)?$", changelog, re.M)
    if not heading:
        raise ValueError("release version is missing from CHANGELOG.md")
    body = changelog[heading.end():].lstrip()
    return re.split(r"^## ", body, maxsplit=1, flags=re.M)[0].rstrip() + "\n"


def prepare(tag, output):
    meta = metadata(tag)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    archive = ROOT / "target/package" / f"{meta['name']}-{meta['version']}.crate"
    verify_archive(archive, head, meta["version"])
    output.mkdir(parents=True, exist_ok=True)
    destination = output / archive.name
    shutil.copyfile(archive, destination)
    shutil.copyfile(ROOT / "Cargo.lock", output / "Cargo.lock")
    (output / "release-notes.md").write_text(notes((ROOT / "CHANGELOG.md").read_text(), meta["version"]))
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    (output / "SHA256SUMS").write_text(f"{digest}  {destination.name}\n")
    if path := os.environ.get("GITHUB_OUTPUT"):
        with open(path, "a") as stream:
            for key in ("name", "version", "tag", "prerelease"):
                stream.write(f"{key}={str(meta[key]).lower() if isinstance(meta[key], bool) else meta[key]}\n")
    print(f"Verified package for {head}: {destination.name} ({digest})")


def registry_state(version, expected_digest, fetch=None):
    """Only skip an immutable registry version if its actual archive matches."""
    def download(url):
        request = Request(url, headers={"User-Agent": "arx-kw-release"})
        with urlopen(request, timeout=60) as response:
            return response.read()
    fetch = fetch or download
    base = f"https://crates.io/api/v1/crates/arx-kw/{version}"
    try:
        fetch(base)
    except HTTPError as error:
        if error.code == 404:
            return False
        raise
    actual = hashlib.sha256(fetch(base + "/download")).hexdigest()
    if actual != expected_digest:
        raise ValueError("registry version exists with a different package; refusing to skip or overwrite")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["metadata", "prepare", "registry"])
    parser.add_argument("--tag", required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "target/release-artifacts")
    args = parser.parse_args()
    meta = metadata(args.tag)
    if args.command == "metadata":
        print(json.dumps(meta))
    elif args.command == "prepare":
        prepare(args.tag, args.output)
    else:
        expected = (args.output / "SHA256SUMS").read_text().split()[0]
        published = registry_state(meta["version"], expected)
        if path := os.environ.get("GITHUB_OUTPUT"):
            with open(path, "a") as stream:
                stream.write(f"published={str(published).lower()}\n")
        print("Identical package already published" if published else "Version is available to publish")


if __name__ == "__main__":
    main()
