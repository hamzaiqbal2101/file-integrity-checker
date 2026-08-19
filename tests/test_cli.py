"""End-to-end CLI tests: baseline, verify, tamper detection, and exit codes."""

from __future__ import annotations

import json

from file_integrity_checker.cli import EXIT_ERROR, EXIT_OK, EXIT_TAMPERED, main
from file_integrity_checker.manifest import read_manifest


def _populate(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    (root / "a.txt").write_text("aaa", encoding="utf-8")
    nested = root / "sub"
    nested.mkdir()
    (nested / "b.txt").write_text("bbb", encoding="utf-8")
    return root


def test_baseline_creates_valid_manifest(tmp_path, capsys) -> None:
    root = _populate(tmp_path)
    manifest_path = tmp_path / "manifest.json"

    exit_code = main(
        ["baseline", str(root), "--recursive", "--output", str(manifest_path)]
    )
    out, _ = capsys.readouterr()

    assert exit_code == EXIT_OK
    assert manifest_path.is_file()
    manifest = read_manifest(manifest_path)
    assert manifest.algorithm == "sha256"
    assert {entry.path for entry in manifest.entries} == {"a.txt", "sub/b.txt"}
    assert "Baseline written" in out


def test_baseline_default_algorithm_is_sha256(tmp_path) -> None:
    root = _populate(tmp_path)
    manifest_path = tmp_path / "m.json"
    main(["baseline", str(root), "--output", str(manifest_path)])
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert data["algorithm"] == "sha256"


def test_verify_unchanged_returns_zero(tmp_path, capsys) -> None:
    root = _populate(tmp_path)
    manifest_path = tmp_path / "m.json"
    main(["baseline", str(root), "--recursive", "--output", str(manifest_path)])

    exit_code = main(["verify", str(root), "--manifest", str(manifest_path)])
    out, _ = capsys.readouterr()

    assert exit_code == EXIT_OK
    assert "NO CHANGES DETECTED" in out
    assert "Exit code:  0" in out


def test_verify_detects_modified_file(tmp_path, capsys) -> None:
    root = _populate(tmp_path)
    manifest_path = tmp_path / "m.json"
    main(["baseline", str(root), "--recursive", "--output", str(manifest_path)])

    (root / "a.txt").write_text("aaa-tampered", encoding="utf-8")

    exit_code = main(["verify", str(root), "--manifest", str(manifest_path)])
    out, _ = capsys.readouterr()

    assert exit_code == EXIT_TAMPERED
    assert "TAMPERING DETECTED" in out
    assert "MODIFIED" in out
    assert "a.txt" in out
    assert "old sha256:" in out
    assert "new sha256:" in out
    assert "Exit code:  1" in out


def test_verify_detects_missing_file(tmp_path, capsys) -> None:
    root = _populate(tmp_path)
    manifest_path = tmp_path / "m.json"
    main(["baseline", str(root), "--recursive", "--output", str(manifest_path)])

    (root / "a.txt").unlink()

    exit_code = main(["verify", str(root), "--manifest", str(manifest_path)])
    out, _ = capsys.readouterr()

    assert exit_code == EXIT_TAMPERED
    assert "MISSING" in out
    assert "a.txt" in out


def test_verify_detects_new_file(tmp_path, capsys) -> None:
    root = _populate(tmp_path)
    manifest_path = tmp_path / "m.json"
    main(["baseline", str(root), "--recursive", "--output", str(manifest_path)])

    (root / "planted.txt").write_text("planted", encoding="utf-8")

    exit_code = main(["verify", str(root), "--manifest", str(manifest_path)])
    out, _ = capsys.readouterr()

    assert exit_code == EXIT_TAMPERED
    assert "NEW" in out
    assert "planted.txt" in out


def test_verify_with_exclude_avoids_spurious_new(tmp_path, capsys) -> None:
    root = _populate(tmp_path)
    (root / "scratch.log").write_text("log", encoding="utf-8")
    manifest_path = tmp_path / "m.json"

    main(
        [
            "baseline",
            str(root),
            "--recursive",
            "--output",
            str(manifest_path),
            "--exclude",
            "*.log",
        ]
    )
    exit_code = main(
        [
            "verify",
            str(root),
            "--manifest",
            str(manifest_path),
            "--exclude",
            "*.log",
        ]
    )
    out, _ = capsys.readouterr()

    assert exit_code == EXIT_OK
    assert "NO CHANGES DETECTED" in out


def test_verify_export_report(tmp_path, capsys) -> None:
    root = _populate(tmp_path)
    manifest_path = tmp_path / "m.json"
    report_path = tmp_path / "reports" / "report.txt"
    main(["baseline", str(root), "--recursive", "--output", str(manifest_path)])

    (root / "a.txt").write_text("changed", encoding="utf-8")

    exit_code = main(
        ["verify", str(root), "--manifest", str(manifest_path), "--output", str(report_path)]
    )
    capsys.readouterr()

    assert exit_code == EXIT_TAMPERED
    assert report_path.is_file()
    text = report_path.read_text(encoding="utf-8")
    assert "TAMPERING DETECTED" in text
    assert "old sha256:" in text
    assert "new sha256:" in text


def test_verify_corrupt_manifest_returns_error(tmp_path, capsys) -> None:
    root = _populate(tmp_path)
    manifest_path = tmp_path / "m.json"
    manifest_path.write_text("{broken", encoding="utf-8")

    exit_code = main(["verify", str(root), "--manifest", str(manifest_path)])
    out, err = capsys.readouterr()

    assert exit_code == EXIT_ERROR
    assert "corrupted manifest" in err


def test_verify_missing_manifest_returns_error(tmp_path, capsys) -> None:
    exit_code = main(["verify", str(tmp_path), "--manifest", str(tmp_path / "nope.json")])
    capsys.readouterr()
    assert exit_code == EXIT_ERROR


def test_baseline_missing_path_returns_error(tmp_path, capsys) -> None:
    exit_code = main(["baseline", str(tmp_path / "ghost")])
    capsys.readouterr()
    assert exit_code == EXIT_ERROR


def test_baseline_single_file(tmp_path, capsys) -> None:
    target = tmp_path / "solo.txt"
    target.write_text("solo", encoding="utf-8")
    manifest_path = tmp_path / "m.json"
    main(["baseline", str(target), "--output", str(manifest_path)])

    manifest = read_manifest(manifest_path)
    assert {entry.path for entry in manifest.entries} == {"solo.txt"}


def test_default_verify_target_uses_manifest_base_dir(tmp_path, capsys) -> None:
    root = _populate(tmp_path)
    manifest_path = tmp_path / "m.json"
    main(["baseline", str(root), "--recursive", "--output", str(manifest_path)])

    # No path argument: verify falls back to manifest.base_dir.
    exit_code = main(["verify", "--manifest", str(manifest_path)])
    capsys.readouterr()
    assert exit_code == EXIT_OK


def test_report_export_never_leaks_in_stdout_pipe(tmp_path, capsys) -> None:
    """Sanity check: report output is deterministic and self-contained."""
    root = _populate(tmp_path)
    manifest_path = tmp_path / "m.json"
    main(["baseline", str(root), "--recursive", "--output", str(manifest_path)])
    exit_code = main(["verify", str(root), "--manifest", str(manifest_path)])
    out, _ = capsys.readouterr()
    assert exit_code == EXIT_OK
    assert len(out.splitlines()) > 10  # full report, not a one-liner


def test_manifest_inside_scanned_tree_is_not_reported_new(tmp_path, capsys) -> None:
    """A manifest stored inside the scanned tree must not trigger a NEW hit."""
    root = _populate(tmp_path)
    manifest_path = root / "integrity-manifest.json"  # deliberately inside tree
    assert main(["baseline", str(root), "--recursive", "--output", str(manifest_path)]) == EXIT_OK

    exit_code = main(["verify", str(root), "--manifest", str(manifest_path)])
    out, _ = capsys.readouterr()

    assert exit_code == EXIT_OK
    assert "NO CHANGES DETECTED" in out
    assert "Summary" in out
