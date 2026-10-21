#!/usr/bin/env python3
"""Install a pinned actionlint binary after checking the upstream SHA-256 manifest."""
import hashlib
import io
from pathlib import Path
import sys
import tarfile
from urllib.request import urlopen

VERSION = "1.7.12"
name = f"actionlint_{VERSION}_linux_amd64.tar.gz"
base = f"https://github.com/rhysd/actionlint/releases/download/v{VERSION}/"
checksums = urlopen(base + f"actionlint_{VERSION}_checksums.txt", timeout=60).read().decode()
expected = {line.split()[-1].lstrip("*"): line.split()[0] for line in checksums.splitlines()}[name]
archive = urlopen(base + name, timeout=60).read()
if hashlib.sha256(archive).hexdigest() != expected:
    raise SystemExit("actionlint checksum mismatch")
output = Path(sys.argv[1])
output.parent.mkdir(parents=True, exist_ok=True)
with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
    output.write_bytes(tar.extractfile("actionlint").read())
output.chmod(0o755)
print(f"Installed verified actionlint {VERSION}: {output}")
