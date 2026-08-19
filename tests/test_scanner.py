"""Unit tests for directory/file scanning, exclusions, and symlinks."""

from __future__ import annotations

import pytest

from file_integrity_checker.hashing import hash_file
from file_integrity_checker.scanner import scan_files


def _populate(root):
    root = root / "tree"
    root.mkdir()
    (root / "a.txt").write_text("aaa", encoding="utf-8")
    (root / "b.log").write_text("log", encoding="utf-8")
    nested = root / "sub"
    nested.mkdir()
    (nested / "c.txt").write_text("ccc", encoding="utf-8")
    (nested / "d.tmp").write_text("tmp", encoding="utf-8")
    hidden = root / ".git"
    hidden.mkdir()
    (hidden / "HEAD").write_text("ref", encoding="utf-8")
    return root


def test_scan_single_file(tmp_path) -> None:
    path = tmp_path / "solo.txt"
    path.write_text("solo", encoding="utf-8")
    results, warnings = scan_files(path, algorithm="sha256")
    assert warnings == []
    assert set(results) == {"solo.txt"}
    assert results["solo.txt"] == hash_file(path)


def test_scan_directory_non_recursive_only_top_level(tmp_path) -> None:
    root = _populate(tmp_path)
    results, _ = scan_files(root, algorithm="sha256", recursive=False)
    assert set(results) == {"a.txt", "b.log"}


def test_scan_directory_recursive_includes_nested(tmp_path) -> None:
    root = _populate(tmp_path)
    results, _ = scan_files(root, algorithm="sha256", recursive=True)
    assert set(results) == {"a.txt", "b.log", "sub/c.txt", "sub/d.tmp", ".git/HEAD"}


def test_exclude_glob_pattern(tmp_path) -> None:
    root = _populate(tmp_path)
    results, _ = scan_files(
        root, algorithm="sha256", recursive=True, excludes=["*.log", "*.tmp"]
    )
    assert "b.log" not in results
    assert "sub/d.tmp" not in results
    assert "a.txt" in results


def test_exclude_directory_by_name(tmp_path) -> None:
    root = _populate(tmp_path)
    results, _ = scan_files(
        root, algorithm="sha256", recursive=True, excludes=[".git"]
    )
    assert ".git/HEAD" not in results
    assert "a.txt" in results
    assert "sub/c.txt" in results


def test_exclude_single_file_target(tmp_path) -> None:
    path = tmp_path / "skip.me"
    path.write_text("x", encoding="utf-8")
    results, _ = scan_files(path, algorithm="sha256", excludes=["*.me"])
    assert results == {}


def test_progress_callback_fires(tmp_path) -> None:
    root = _populate(tmp_path)
    counts: list[int] = []
    scan_files(
        root,
        algorithm="sha256",
        recursive=True,
        on_progress=lambda count: counts.append(count),
    )
    assert counts == [1, 2, 3, 4, 5]


def test_scan_missing_target_warns_not_raises(tmp_path) -> None:
    results, warnings = scan_files(tmp_path / "nope", algorithm="sha256")
    assert results == {}
    assert warnings


def test_symlinks_skipped_by_default(tmp_path) -> None:
    root = _populate(tmp_path)
    target = root / "a.txt"
    try:
        (root / "link.txt").symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported on this platform")

    results, _ = scan_files(root, algorithm="sha256", recursive=False)
    assert "link.txt" not in results
    assert "a.txt" in results


def test_symlinks_followed_when_requested(tmp_path) -> None:
    root = _populate(tmp_path)
    try:
        (root / "link.txt").symlink_to(root / "a.txt")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported on this platform")

    results, _ = scan_files(
        root, algorithm="sha256", recursive=False, follow_symlinks=True
    )
    assert "link.txt" in results
    assert results["link.txt"].digest == results["a.txt"].digest