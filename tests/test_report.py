"""Unit tests for report rendering."""

from __future__ import annotations

from file_integrity_checker.comparator import Change, ComparisonResult, Status
from file_integrity_checker.report import export_report, render_report

ALGORITHM = "sha256"


def _result() -> ComparisonResult:
    return ComparisonResult(
        algorithm=ALGORITHM,
        unchanged=3,
        changes=(
            Change(
                path="config.txt",
                status=Status.MODIFIED,
                old_digest="oldhash",
                new_digest="newhash",
                old_size=10,
                new_size=14,
            ),
            Change(path="gone.txt", status=Status.MISSING, old_digest="g", old_size=5),
            Change(path="planted.txt", status=Status.NEW, new_digest="n", new_size=1),
        ),
    )


def test_clean_report_shows_unchanged_count() -> None:
    result = ComparisonResult(algorithm=ALGORITHM, unchanged=5, changes=())
    text = render_report(result, "m.json", ".")
    assert "NO CHANGES DETECTED" in text
    assert "Total files: 5" in text
    assert "UNCHANGED" in text
    assert "Exit code:  0" in text


def test_tampered_report_shows_verdict_and_counts() -> None:
    text = render_report(_result(), "m.json", "/base")
    assert "TAMPERING DETECTED" in text
    assert "Total files: 6" in text  # 3 unchanged + 3 changes
    assert "UNCHANGED  3" in text
    assert "MODIFIED   1" in text
    assert "MISSING    1" in text
    assert "NEW        1" in text
    assert "Exit code:  1" in text


def test_modified_shows_old_and_new_hash() -> None:
    text = render_report(_result(), "m.json", ".")
    assert "[MODIFIED] config.txt" in text
    assert "old sha256: oldhash" in text
    assert "new sha256: newhash" in text
    assert "10 -> 14 bytes" in text


def test_missing_and_new_shown() -> None:
    text = render_report(_result(), "m.json", ".")
    assert "[MISSING] gone.txt" in text
    assert "was sha256: g" in text
    assert "[NEW] planted.txt" in text
    assert "now sha256: n" in text


def test_export_report_writes_file(tmp_path) -> None:
    dest = tmp_path / "nested" / "report.txt"
    export_report(_result(), dest, "m.json", "/base")
    text = dest.read_text(encoding="utf-8")
    assert "TAMPERING DETECTED" in text


def test_no_changes_details_section() -> None:
    result = ComparisonResult(algorithm=ALGORITHM, unchanged=2, changes=())
    text = render_report(result, "m.json", ".")
    assert "(no changes)" in text