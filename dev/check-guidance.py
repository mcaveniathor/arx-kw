#!/usr/bin/env python3
"""Verify the portable export, consumer recipes, and MCP tools in temporary storage."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parent.parent
GUIDANCE = ROOT / "guidance/arx-kw-0.5.0"


def run(*args, **kwargs):
    kwargs.setdefault("timeout", 300)
    return subprocess.run(args, check=True, text=True, **kwargs)


def files(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--symposiast", default="symposiast")
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    executable = shutil.which(args.symposiast)
    if not executable:
        raise SystemExit("Install the pinned Symposiast CLI described in guidance/README.md")
    bundle = json.loads((GUIDANCE / "bundle/bundle.json").read_text())
    generation = json.loads((GUIDANCE / "generation.json").read_text())
    assert bundle["release"] == generation["release"]
    assert bundle["review"] is None
    assert bundle["analysis"] == json.loads((GUIDANCE / "analysis.json").read_text())
    with tempfile.TemporaryDirectory(prefix="arx-guidance-") as temporary:
        temporary = Path(temporary)
        # Check the committed export before verification updates compiler records.
        exported = temporary / "registry"
        run(executable, "export-registry", str(GUIDANCE / "bundle"), "--output", str(exported))
        assert files(exported) == files(ROOT / "guidance/registry/arx-kw-0.5.0"), "portable export is stale"
        assert any(p.name == "license.txt" for p in (GUIDANCE / "bundle/sources").iterdir())
        assert any(p.name == "license.txt" for p in exported.rglob("license.txt"))
        local = temporary / "bundle"
        shutil.copytree(GUIDANCE / "bundle", local, ignore=shutil.ignore_patterns("target", "plugin"))
        run(executable, "verify", str(local), *(["--offline"] if args.offline else []))
        for recipe in bundle["analysis"]["recipes"]:
            consumer = local / "verification" / recipe["id"]
            lock = tomllib.loads((consumer / "Cargo.lock").read_text())
            packages = [p for p in lock["package"] if p["name"] == "arx-kw"]
            assert len(packages) == 1
            assert packages[0]["version"] == "0.5.0"
            assert packages[0]["checksum"] == bundle["release"]["checksum"]
            assert packages[0]["source"] == "registry+https://github.com/rust-lang/crates.io-index"
            manifest = tomllib.loads((consumer / "Cargo.toml").read_text())
            dependency = manifest["dependencies"]["arx-kw"]
            assert dependency["version"] == "=0.5.0" and not dependency["default-features"]
            assert dependency["features"] == recipe["features"]
            env = dict(os.environ, CARGO_TARGET_DIR=str(local / "verification/target"))
            run("cargo", "run", "--locked", "--manifest-path", str(consumer / "Cargo.toml"),
                *(["--offline"] if args.offline else []), env=env)
            result = run(executable, "check", str(local), "--workspace", str(consumer), capture_output=True)
            assert json.loads(result.stdout) == [], result.stdout
        drift = temporary / "drift"
        drift.mkdir()
        (drift / "Cargo.lock").write_text('version = 4\n[[package]]\nname = "arx-kw"\nversion = "0.4.0"\n')
        result = run(executable, "check", str(local), "--workspace", str(drift), capture_output=True)
        assert any("version mismatch" in warning for warning in json.loads(result.stdout))
        requests = [
            {"id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "arx-guidance-check", "version": "1"}}},
            {"method": "notifications/initialized"},
            {"id": 2, "method": "tools/list"},
            {"id": 3, "method": "tools/call", "params": {"name": "get_release_info", "arguments": {}}},
            {"id": 4, "method": "tools/call", "params": {"name": "search_guidance", "arguments": {"query": "rotation", "limit": 3}}},
        ]
        for index, recipe in enumerate(bundle["analysis"]["recipes"], 5):
            requests.append({"id": index, "method": "tools/call", "params": {"name": "get_recipe", "arguments": {"id": recipe["id"]}}})
        wire = "".join(json.dumps(dict(jsonrpc="2.0", **request)) + "\n" for request in requests)
        result = run(executable, "serve", str(local), input=wire, capture_output=True, timeout=30)
        responses = {r["id"]: r for r in map(json.loads, result.stdout.splitlines())}
        assert len(responses) == len(requests) - 1
        assert all("error" not in r and not r["result"].get("isError", False) for r in responses.values())
        assert {t["name"] for t in responses[2]["result"]["tools"]} == {"get_release_info", "search_guidance", "get_recipe"}
        payload = lambda index: json.loads(responses[index]["result"]["content"][0]["text"])
        assert payload(3)["release"] == bundle["release"]
        assert payload(3)["review"] is None
        assert payload(4)["results"]
        for index, recipe in enumerate(bundle["analysis"]["recipes"], 5):
            assert payload(index)["recipe"] == recipe
            assert payload(index)["verification"]["status"] == "compiled"
        print("Verified portable export, three compiled/running recipes, exact dependency identity, drift warning, and MCP retrieval")


if __name__ == "__main__":
    main()
