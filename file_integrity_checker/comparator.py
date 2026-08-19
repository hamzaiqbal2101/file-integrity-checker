"""Verification comparison logic.

Given a baseline :class:`~file_integrity_checker.manifest.Manifest` and a
fresh scan, every file is classified into exactly one status:

============  ===============================================================
Status        Meaning
============  ===============================================================
UNCHANGED     Hash matches the baseline.
MODIFIED      Hash differs from the baseline (content or metadata changed).
MISSING       In the manifest but not present on disk.
NEW           Present on disk but not in the manifest.
UNREADABLE    Could not be hashed (read error, or was unstable at baseline).
============  ===============================================================

NEW files are treated as changes because an integrity whitelist is
violated by any unauthorized addition, not just by edits to known files.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping

from file_integrity_checker.hashing import HashResult
from file_integrity_checker.manifest import Manifest


class Status(Enum):
    """Classification of a single file after verification."""

    UNCHANGED = "unchanged"
    MODIFIED = "modified"
    MISSING = "missing"
    NEW = "new"
    UNREADABLE = "unreadable"


@dataclass(frozen=True)
class Change:
    """A single file whose verification result is not UNCHANGED.

    Attributes:
        path: Relative path of the file.
        status: The change classification.
        old_digest: Digest recorded in the manifest, if any.
        new_digest: Digest computed during verification, if any.
        old_size: Size recorded in the manifest, if any.
        new_size: Size observed during verification, if any.
        detail: Additional context (e.g. the underlying read error).
    """

    path: str
    status: Status
    old_digest: str | None = None
    new_digest: str | None = None
    old_size: int | None = None
    new_size: int | None = None
    detail: str | None = None


@dataclass(frozen=True)
class ComparisonResult:
    """Outcome of comparing a manifest against a fresh scan.

    Attributes:
        algorithm: Hash algorithm used for the comparison.
        unchanged: Number of files matching their baseline.
        changes: Tuple of every non-UNCHANGED file, sorted by status then
            path for stable reporting.
    """

    algorithm: str
    unchanged: int
    changes: tuple[Change, ...]

    @property
    def total(self) -> int:
        """Total number of files considered (baseline + new files)."""
        return self.unchanged + len(self.changes)

    @property
    def has_changes(self) -> bool:
        """True when any file did not verify as UNCHANGED."""
        return bool(self.changes)

    def count(self, status: Status) -> int:
        """Return how many files have the given status.

        Args:
            status: A :class:`Status` to count.

        Returns:
            The number of changes with that status.
        """
        return sum(1 for change in self.changes if change.status is status)


def compare(
    manifest: Manifest, scan_results: Mapping[str, HashResult]
) -> ComparisonResult:
    """Compare a baseline manifest against a fresh scan.

    Args:
        manifest: The baseline :class:`Manifest`.
        scan_results: Mapping of relative path to :class:`HashResult`,
            produced by :func:`file_integrity_checker.scanner.scan_files`.

    Returns:
        A :class:`ComparisonResult`. Any status other than UNCHANGED counts
        as a change (and therefore a non-zero exit code at the CLI layer).
    """
    scanned = dict(scan_results)
    manifest_paths = {entry.path for entry in manifest.entries}

    changes: list[Change] = []
    unchanged = 0

    for entry in manifest.entries:
        if entry.error:
            # The baseline itself could not verify this file, so we cannot
            # prove it is unchanged. Surface it explicitly rather than
            # silently trusting it.
            current = scanned.get(entry.path)
            changes.append(
                Change(
                    path=entry.path,
                    status=Status.UNREADABLE,
                    new_digest=current.digest if current else None,
                    new_size=current.size if current else None,
                    detail=f"could not be hashed at baseline: {entry.error}",
                )
            )
            continue

        current = scanned.get(entry.path)
        if current is None:
            changes.append(
                Change(
                    path=entry.path,
                    status=Status.MISSING,
                    old_digest=entry.digest,
                    old_size=entry.size,
                    detail="in manifest but not found on disk",
                )
            )
            continue

        if current.error:
            changes.append(
                Change(
                    path=entry.path,
                    status=Status.UNREADABLE,
                    old_digest=entry.digest,
                    old_size=entry.size,
                    new_size=current.size,
                    detail=f"cannot re-hash file: {current.error}",
                )
            )
            continue

        if current.digest == entry.digest:
            unchanged += 1
        else:
            changes.append(
                Change(
                    path=entry.path,
                    status=Status.MODIFIED,
                    old_digest=entry.digest,
                    new_digest=current.digest,
                    old_size=entry.size,
                    new_size=current.size,
                )
            )

    # Files present on disk but absent from the manifest are NEW.
    for relpath in sorted(set(scanned) - manifest_paths):
        current = scanned[relpath]
        changes.append(
            Change(
                path=relpath,
                status=Status.NEW,
                new_digest=current.digest,
                new_size=current.size,
                detail=current.error or "not in manifest",
            )
        )

    changes.sort(key=lambda change: (change.status.value, change.path))
    return ComparisonResult(
        algorithm=manifest.algorithm, unchanged=unchanged, changes=tuple(changes)
    )