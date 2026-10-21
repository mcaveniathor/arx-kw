#!/usr/bin/env python3
"""Check resolved runtime dependency graphs for supported feature combinations."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent
OPTIONAL = {"chacha20", "arrayref", "hmac", "sha2"}


def tree(features, *extra):
    command = ["cargo", "tree", "--locked", "--no-default-features"]
    if features:
        command += ["--features", ",".join(features)]
    return subprocess.check_output(command + list(extra), cwd=ROOT, text=True)


def check(features):
    graph = tree(features, "--edges", "normal", "--prefix", "none", "--format", "{p}")
    packages = {line.split()[0] for line in graph.splitlines() if line.strip()}
    variant = next((f for f in features if f in {"e", "g", "ex", "gx"}), None)
    expected = ({"chacha20", "arrayref"} if variant else set())
    if "envelope" in features:
        expected |= {"hmac", "sha2"}
    actual = packages & OPTIONAL
    if actual != expected:
        raise AssertionError(f"{features}: expected {expected}, resolved {actual}")
    if "getrandom" in packages:
        raise AssertionError(f"{features}: example randomness leaked into runtime dependencies")
    if variant:
        cipher_features = tree(features, "--edges", "normal,features", "--invert", "chacha20")
        xchacha = 'feature "xchacha"' in cipher_features
        if xchacha != (variant in {"ex", "gx"}):
            raise AssertionError(f"{features}: unexpected XChaCha activation: {xchacha}")
    print(f"Checked {','.join(features) or 'no features'}: {', '.join(sorted(actual)) or 'no optional crypto dependencies'}")


if __name__ == "__main__":
    check([])
    check(["envelope"])
    for variant in ("e", "g", "ex", "gx"):
        check([variant])
        check([variant, "envelope"])
