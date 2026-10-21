"""Exercise release rejection paths without registry credentials or network calls."""
import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from urllib.error import HTTPError

spec = importlib.util.spec_from_file_location("release", Path(__file__).parents[1] / "release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseChecks(unittest.TestCase):
    def test_tag_must_match_manifest(self):
        data = {"package": {"name": "arx-kw", "version": "0.4.0"}}
        self.assertEqual(release.metadata("v0.4.0", data)["version"], "0.4.0")
        for tag in ["main", "v0.3.2", "v0.4.0;anything"]:
            with self.assertRaises(ValueError):
                release.metadata(tag, data)

    def test_workflow_rejects_other_crate_names(self):
        with self.assertRaises(ValueError):
            release.metadata("v0.4.0", {"package": {"name": "other-crate", "version": "0.4.0"}})

    def test_release_notes_stop_at_next_version(self):
        source = "# Changelog\n\n## 0.4.0 (unreleased)\n\nNew.\n### Details\nMore.\n\n## 0.3.2\nOld."
        self.assertEqual(release.notes(source, "0.4.0"), "New.\n### Details\nMore.\n")
        with self.assertRaises(ValueError):
            release.notes(source, "0.5.0")

    def test_existing_registry_package_must_match(self):
        content = b"verified archive"
        digest = hashlib.sha256(content).hexdigest()
        self.assertTrue(release.registry_state("0.4.0", digest, fetch=lambda _: content))
        with self.assertRaises(ValueError):
            release.registry_state("0.4.0", "different", fetch=lambda _: content)

    def test_only_not_found_means_unpublished(self):
        def failure(code):
            def fetch(url):
                raise HTTPError(url, code, "failure", {}, None)
            return fetch
        self.assertFalse(release.registry_state("0.4.0", "unused", failure(404)))
        for code in [401, 403, 429, 500]:
            with self.assertRaises(HTTPError):
                release.registry_state("0.4.0", "unused", failure(code))

    def test_package_rejects_dirty_or_wrong_commit(self):
        import json
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "test.crate"
            for commit, dirty, valid in [("expected", False, True), ("other", False, False), ("expected", True, False)]:
                with tarfile.open(path, "w:gz") as archive:
                    files = {
                        ".cargo_vcs_info.json": json.dumps({"git": {"sha1": commit, "dirty": dirty}}),
                        "Cargo.toml": '[package]\nname = "arx-kw"\nversion = "0.4.0"',
                    }
                    for name, text in files.items():
                        data = text.encode()
                        info = tarfile.TarInfo("arx-kw-0.4.0/" + name)
                        info.size = len(data)
                        archive.addfile(info, io.BytesIO(data))
                if valid:
                    release.verify_archive(path, "expected", "0.4.0")
                else:
                    with self.assertRaises(ValueError):
                        release.verify_archive(path, "expected", "0.4.0")


if __name__ == "__main__":
    unittest.main()
