"""Unit tests for manifest serialization, validation, and atomic writes."""

from __future__ import annotations

import json

import pytest

from file_integrity_checker.hashing import HashResult
from file_integrity_checker.manifest import (
    MANIFEST_VERSION,
    Manifest,
    ManifestEntry,
    ManifestError,
    build_manifest,
    read_manifest,
    serialize,
    to_dict,
    write_manifest,
)

SCAN = {
    "a.txt": HashResult(digest="aa", size=3, error=None),
    "sub/b.txt": HashResult(digest="bb", size=4, error=None),
    "broken.txt": HashResult(digest=None, size=None, error="permission denied"),
}


def test_build_manifest_sorts_entries() -> None:
    manifest = build_manifest("sha256", ".", True, SCAN, "test/1.0")
    assert [entry.path for entry in manifest.entries] == [
        "a.txt",
        "broken.txt",
        "sub/b.txt",
    ]


def test_roundtrip_through_disk(tmp_path) -> None:
    manifest = build_manifest("sha256", ".", True, SCAN, "test/1.0")
    dest = tmp_path / "manifest.json"
    write_manifest(manifest, dest)
    loaded = read_manifest(dest)

    assert loaded.algorithm == "sha256"
    assert loaded.recursive is True
    assert loaded.base_dir == "."
    assert loaded.generator == "test/1.0"
    assert loaded.entries == manifest.entries


def test_serialize_uses_hash_key_and_version() -> None:
    manifest = build_manifest("sha256", ".", False, {"f": HashResult("abc", 1, None)}, "t")
    data = json.loads(serialize(manifest))
    assert data["manifest_version"] == MANIFEST_VERSION
    assert data["files"][0]["hash"] == "abc"
    assert data["files"][0]["path"] == "f"


def test_to_dict_shape() -> None:
    manifest = build_manifest("md5", "x", True, {"f": HashResult("d", 2, None)}, "t")
    d = to_dict(manifest)
    assert set(d) == {
        "manifest_version",
        "generator",
        "algorithm",
        "created_at",
        "base_dir",
        "recursive",
        "files",
    }


def test_read_manifest_missing_file(tmp_path) -> None:
    with pytest.raises(ManifestError):
        read_manifest(tmp_path / "nope.json")


def test_read_manifest_corrupted_json(tmp_path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(ManifestError, match="corrupted manifest"):
        read_manifest(path)


def test_read_manifest_wrong_version(tmp_path) -> None:
    path = tmp_path / "ver.json"
    path.write_text(json.dumps({"manifest_version": 99, "files": []}), encoding="utf-8")
    with pytest.raises(ManifestError, match="unsupported manifest version"):
        read_manifest(path)


def test_read_manifest_missing_fields(tmp_path) -> None:
    path = tmp_path / "field.json"
    path.write_text(json.dumps({"manifest_version": 1, "files": []}), encoding="utf-8")
    with pytest.raises(ManifestError, match="malformed manifest"):
        read_manifest(path)


def test_read_manifest_non_object_root(tmp_path) -> None:
    path = tmp_path / "root.json"
    path.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
    with pytest.raises(ManifestError, match="must be a JSON object"):
        read_manifest(path)


def test_read_manifest_entry_missing_path(tmp_path) -> None:
    path = tmp_path / "entry.json"
    path.write_text(
        json.dumps(
            {
                "manifest_version": 1,
                "algorithm": "sha256",
                "base_dir": ".",
                "recursive": False,
                "created_at": "2026-01-01T00:00:00+00:00",
                "files": [{"hash": "abc"}],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ManifestError, match="missing 'path'"):
        read_manifest(path)


def test_atomic_write_leaves_no_temp_files(tmp_path) -> None:
    manifest = build_manifest("sha256", ".", True, SCAN, "test/1.0")
    dest = tmp_path / "m.json"
    write_manifest(manifest, dest)
    leftovers = [p.name for p in tmp_path.iterdir()]
    assert leftovers == ["m.json"]


def test_write_manifest_creates_parent_dirs(tmp_path) -> None:
    manifest = build_manifest("sha256", ".", False, {}, "test/1.0")
    dest = tmp_path / "deep" / "dir" / "m.json"
    write_manifest(manifest, dest)
    assert dest.is_file()


def test_entry_with_error_roundtrips() -> None:
    manifest = build_manifest("sha256", ".", False, SCAN, "test/1.0")
    broken = next(e for e in manifest.entries if e.path == "broken.txt")
    assert broken.digest is None
    assert broken.error == "permission denied"


def test_manifest_is_frozen() -> None:
    manifest = Manifest("sha256", ".", False, "now", "t", (ManifestEntry("f"),))
    with pytest.raises(Exception):
        manifest.entries = ()  # type: ignore[misc]