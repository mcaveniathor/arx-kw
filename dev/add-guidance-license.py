#!/usr/bin/env python3
"""Preserve the published MIT notice omitted by Symposiast 0.1.0 collection."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile
from urllib.request import Request, urlopen


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args()
    path = args.bundle / "bundle.json"
    bundle = json.loads(path.read_text())
    release = bundle["release"]
    if release["name"] != "arx-kw" or release["version"] != "0.5.0":
        raise ValueError("this supplement is for arx-kw 0.5.0")
    url = "https://static.crates.io/crates/arx-kw/arx-kw-0.5.0.crate"
    with urlopen(Request(url, headers={"User-Agent": "arx-kw-guidance"}), timeout=60) as response:
        archive = response.read()
    if hashlib.sha256(archive).hexdigest() != release["checksum"]:
        raise ValueError("published archive checksum mismatch")
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        member = tar.getmember("arx-kw-0.5.0/LICENSE")
        if not member.isfile():
            raise ValueError("license must be a regular archive member")
        notice = tar.extractfile(member).read()
    source = {"id": "license", "kind": "license", "path": "sources/license.txt",
              "url": "https://docs.rs/crate/arx-kw/0.5.0/source/LICENSE",
              "sha256": hashlib.sha256(notice).hexdigest()}
    previous = [s for s in bundle["sources"] if s["id"] == "license"]
    if previous and previous != [source]:
        raise ValueError("conflicting existing license source")
    if not previous:
        bundle["sources"].append(source)
    (args.bundle / source["path"]).write_bytes(notice)
    path.write_text(json.dumps(bundle, indent=2) + "\n")
    print("Preserved checksum-verified published license notice")


if __name__ == "__main__":
    main()
