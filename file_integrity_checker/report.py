"""Console and file report rendering for verification results.

The report shows the overall verdict, a summary by status, and per-file
detail including old vs new hashes for modified files. The same renderer
drives both the console output and the optional ``--output`` export so the
two can never drift.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from file_integrity_checker.comparator import ComparisonResult, Status

_STATUS_LABELS = {
    Status.UNCHANGED: "UNCHANGED",
    Status.MODIFIED: "MODIFIED",
    Status.MISSING: "MISSING",
    Status.NEW: "NEW",
    Status.UNREADABLE: "UNREADABLE",
}


def _render_details(result: ComparisonResult) -> list[str]:
    """Render the per-file detail section of the report.

    Args:
        result: The comparison result.

    Returns:
        A list of lines describing every change in detail.
    """
    lines: list[str] = []
    for change in result.changes:
        label = _STATUS_LABELS[change.status]
        lines.append(f"[{label}] {change.path}")

        if change.status is Status.MODIFIED:
            lines.append(f"    old {result.algorithm}: {change.old_digest or 'n/a'}")
            lines.append(f"    new {result.algorithm}: {change.new_digest or 'n/a'}")
            if change.old_size is not None or change.new_size is not None:
                lines.append(
                    f"    size: {change.old_size if change.old_size is not None else 'n/a'} -> "
                    f"{change.new_size if change.new_size is not None else 'n/a'} bytes"
                )
        elif change.status is Status.MISSING:
            lines.append(f"    was {result.algorithm}: {change.old_digest or 'n/a'}")
        elif change.status is Status.NEW:
            lines.append(f"    now {result.algorithm}: {change.new_digest or 'n/a'}")
        elif change.status is Status.UNREADABLE and change.detail:
            lines.append(f"    note: {change.detail}")
    return lines


def render_report(
    result: ComparisonResult,
    manifest_path: str,
    base_dir: str,
    generated_at: str | None = None,
) -> str:
    """Render a complete human-readable verification report.

    Args:
        result: The comparison result to report.
        manifest_path: Path of the manifest that was verified.
        base_dir: Base directory recorded in the manifest.
        generated_at: ISO timestamp to stamp the report with; defaults to
            the current UTC time.

    Returns:
        The full report text (multi-line, trailing newline).
    """
    timestamp = generated_at or datetime.now(timezone.utc).isoformat(timespec="seconds")
    verdict = "TAMPERING DETECTED" if result.has_changes else "NO CHANGES DETECTED"

    lines = [
        "File Integrity Verification Report",
        "=" * 40,
        f"Generated:  {timestamp}",
        f"Manifest:   {manifest_path}",
        f"Base dir:   {base_dir}",
        f"Algorithm:  {result.algorithm}",
        f"Result:     {verdict}",
        "",
        "Summary",
        "-------",
        f"Total files: {result.total}",
    ]
    for status in Status:
        # UNCHANGED files are tallied in `unchanged`, not listed in
        # `changes`; every other status is counted from the change list.
        count = result.unchanged if status is Status.UNCHANGED else result.count(status)
        lines.append(f"{_STATUS_LABELS[status]:<10} {count}")

    lines += ["", "Details", "-------"]
    details = _render_details(result)
    lines.extend(details if details else ["(no changes)"])

    lines += ["", f"Exit code:  {1 if result.has_changes else 0}"]
    return "\n".join(lines) + "\n"


def export_report(
    result: ComparisonResult,
    path: str | Path,
    manifest_path: str,
    base_dir: str,
) -> None:
    """Write a rendered report to a file, creating parent directories.

    Args:
        result: The comparison result to export.
        path: Destination file path.
        manifest_path: Path of the manifest that was verified.
        base_dir: Base directory recorded in the manifest.

    Raises:
        OSError: If the report cannot be written.
    """
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(render_report(result, manifest_path, base_dir), encoding="utf-8")