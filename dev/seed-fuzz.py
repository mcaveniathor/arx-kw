#!/usr/bin/env python3
"""Seed instrumented fuzz targets from frozen, published envelope vectors."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main():
    for target in ("envelope", "round_trip"):
        (ROOT / "fuzz" / "corpus" / target).mkdir(parents=True, exist_ok=True)
    for index, line in enumerate((ROOT / "tests/vectors/envelope-v1.tsv").read_text().splitlines()):
        variant, key, plaintext, context, envelope = line.split("\t")
        key, plaintext, context, envelope = map(bytes.fromhex, (key, plaintext, context, envelope))
        prefix = key.ljust(48, b"\0") + len(context).to_bytes(2, "little") + index.to_bytes(2, "little")
        for target, payload in (("envelope", envelope), ("round_trip", plaintext)):
            path = ROOT / "fuzz" / "corpus" / target / f"{variant}-{index}"
            path.write_bytes(prefix + context + payload)
    print("Seeded 16 inputs for each of two fuzz targets")


if __name__ == "__main__":
    main()
