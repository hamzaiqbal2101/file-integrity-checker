"""Unit tests for the verification comparison logic."""

from __future__ import annotations

from file_integrity_checker.comparator import Status, compare
from file_integrity_checker.hashing import HashResult
from file_integrity_checker.manifest import Manifest, ManifestEntry

ALGORITHM = "sha256"


def _manifest(entries: list[ManifestEntry]) -> Manifest:
    return Manifest(
        algorithm=ALGORITHM,
        base_dir=".",
        recursive=True,
        created_at="2026-01-01T00:00:00+00:00",
        generator="test/1.0",
        entries=tuple(entries),
    )


def test_all_unchanged() -> None:
    manifest = _manifest([ManifestEntry(path="a", size=1, digest="111")])
    scan = {"a": HashResult(digest="111", size=1, error=None)}
    result = compare(manifest, scan)
    assert result.has_changes is False
    assert result.unchanged == 1
    assert result.total == 1
    assert result.count(Status.UNCHANGED) == 0  # unchanged are counted, not listed


def test_modified_reports_old_and_new() -> None:
    manifest = _manifest([ManifestEntry(path="a", size=1, digest="111")])
    scan = {"a": HashResult(digest="222", size=2, error=None)}
    result = compare(manifest, scan)
    assert result.has_changes is True
    change = result.changes[0]
    assert change.status is Status.MODIFIED
    assert change.old_digest == "111"
    assert change.new_digest == "222"
    assert change.old_size == 1
    assert change.new_size == 2


def test_missing_file() -> None:
    manifest = _manifest([ManifestEntry(path="gone", size=5, digest="abc")])
    result = compare(manifest, {})
    assert result.changes[0].status is Status.MISSING
    assert result.changes[0].old_digest == "abc"


def test_new_file() -> None:
    manifest = _manifest([ManifestEntry(path="known", size=1, digest="111")])
    scan = {
        "known": HashResult(digest="111", size=1, error=None),
        "intruder": HashResult(digest="999", size=9, error=None),
    }
    result = compare(manifest, scan)
    assert result.has_changes is True
    new_change = next(c for c in result.changes if c.status is Status.NEW)
    assert new_change.path == "intruder"
    assert new_change.new_digest == "999"


def test_baseline_error_entry_is_reported_unreadable() -> None:
    manifest = _manifest([ManifestEntry(path="locked", size=None, digest=None, error="denied")])
    scan = {"locked": HashResult(digest="abc", size=3, error=None)}
    result = compare(manifest, scan)
    change = result.changes[0]
    assert change.status is Status.UNREADABLE
    assert "baseline" in change.detail


def test_current_read_error_is_unreadable() -> None:
    manifest = _manifest([ManifestEntry(path="f", size=1, digest="111")])
    scan = {"f": HashResult(digest=None, size=None, error="cannot read file: denied")}
    result = compare(manifest, scan)
    assert result.changes[0].status is Status.UNREADABLE
    assert result.changes[0].old_digest == "111"


def test_empty_manifest_and_empty_scan() -> None:
    result = compare(_manifest([]), {})
    assert result.has_changes is False
    assert result.total == 0


def test_changes_sorted_by_status_then_path() -> None:
    manifest = _manifest(
        [
            ManifestEntry(path="z", size=1, digest="zzz"),
            ManifestEntry(path="a", size=1, digest="aaa"),
        ]
    )
    scan = {"c": HashResult(digest="ccc", size=3, error=None)}
    result = compare(manifest, scan)
    statuses = [change.status for change in result.changes]
    # MISSING sorts before NEW; paths then determine order within a status.
    assert statuses == [Status.MISSING, Status.MISSING, Status.NEW]


def test_counts_per_status() -> None:
    manifest = _manifest(
        [
            ManifestEntry(path="m1", size=1, digest="d"),
            ManifestEntry(path="m2", size=1, digest="d"),
        ]
    )
    scan = {"n1": HashResult(digest="x", size=1, error=None)}
    result = compare(manifest, scan)
    assert result.count(Status.MISSING) == 2
    assert result.count(Status.NEW) == 1
    assert result.count(Status.MODIFIED) == 0