"""Directory/file scanning and chunked hashing.

The scanner walks a target, applies exclusion patterns, and hashes every
selected file. Results are keyed by the path *relative to the scanned base*
(using POSIX separators) so manifests stay portable across machines and
across moves of the scanned tree.

Symlink policy (a deliberate security decision, documented in the README):

* By default symlinks are NOT followed. Following them would let an
  integrity check silently hash files outside the scanned tree and would
  open a window for a symlink-swap (TOCTOU) attack, where an attacker
  redirects a symlink between the scan and the hash.
* With ``follow_symlinks=True`` they are traversed; ``os.walk`` detects
  symlink cycles so an infinite loop cannot occur.
"""

from __future__ import annotations

import fnmatch
import os
from collections.abc import Callable, Iterable
from pathlib import Path

from file_integrity_checker.hashing import CHUNK_SIZE, HashResult, hash_file

ProgressCallback = Callable[[int], None]


def _normalize_patterns(patterns: Iterable[str]) -> tuple[str, ...]:
    """Normalize exclusion patterns for cross-platform matching.

    Backslashes are converted to forward slashes so patterns written on
    Windows behave identically to those written on POSIX.

    Args:
        patterns: Raw exclusion patterns.

    Returns:
        A tuple of normalized patterns.
    """
    return tuple(pattern.strip().replace("\\", "/") for pattern in patterns if pattern.strip())


def _is_excluded(relpath: str, patterns: tuple[str, ...]) -> bool:
    """Return True when a relative path matches any exclusion pattern.

    Matching uses :func:`fnmatch.fnmatch` against the whole relative path
    AND against each individual path component, so both
    ``--exclude "*.log"`` and ``--exclude ".git"`` behave intuitively.

    Args:
        relpath: Relative path (POSIX separators).
        patterns: Normalized exclusion patterns.

    Returns:
        True when the path should be skipped.
    """
    if any(fnmatch.fnmatch(relpath, pattern) for pattern in patterns):
        return True
    parts = relpath.split("/")
    return any(
        fnmatch.fnmatch(part, pattern) for part in parts for pattern in patterns
    )


def _iter_top_level_files(directory: Path) -> Iterable[Path]:
    """Yield the regular files directly inside ``directory`` (not sorted).

    Args:
        directory: The directory to list.

    Returns:
        An iterable of file paths.
    """
    for child in directory.iterdir():
        if child.is_file():
            yield child


def scan_files(
    target: str | os.PathLike[str],
    *,
    algorithm: str,
    recursive: bool = False,
    excludes: Iterable[str] = (),
    follow_symlinks: bool = False,
    chunk_size: int = CHUNK_SIZE,
    on_progress: ProgressCallback | None = None,
) -> tuple[dict[str, HashResult], list[str]]:
    """Scan a file or directory and hash every selected file.

    Args:
        target: File or directory to scan.
        algorithm: Hash algorithm name (see
            :data:`file_integrity_checker.hashing.SUPPORTED_ALGORITHMS`).
        recursive: When scanning a directory, recurse into subdirectories.
        excludes: fnmatch patterns; matching files/directories are skipped.
        follow_symlinks: Whether to traverse symlinks (default False).
        chunk_size: Read buffer size in bytes.
        on_progress: Optional callback invoked with the running count of
            hashed files; useful for progress reporting on large trees.

    Returns:
        A tuple of:

        * A dict mapping relative paths (POSIX separators) to
          :class:`~file_integrity_checker.hashing.HashResult`.
        * A list of non-fatal warnings (e.g. unreadable directories), never
          silently swallowed.
    """
    patterns = _normalize_patterns(excludes)
    results: dict[str, HashResult] = {}
    warnings: list[str] = []
    count = 0
    path = Path(target)

    # --- Single file (or symlink-to-file) target ---------------------------
    if path.is_file():
        if not _is_excluded(path.name, patterns):
            results[path.name] = hash_file(path, algorithm, chunk_size)
            count += 1
            if on_progress:
                on_progress(count)
        return results, warnings

    if not path.is_dir():
        warnings.append(f"target is not a file or directory: {target}")
        return results, warnings

    # --- Directory target ---------------------------------------------------
    base = path

    def onerror(error: OSError) -> None:
        warnings.append(f"cannot access directory: {error}")

    def process_file(filepath: Path, relpath: str) -> None:
        nonlocal count
        if _is_excluded(relpath, patterns):
            return
        if filepath.is_symlink() and not follow_symlinks:
            return
        results[relpath] = hash_file(filepath, algorithm, chunk_size)
        count += 1
        if on_progress:
            on_progress(count)

    if not recursive:
        for child in sorted(_iter_top_level_files(base), key=lambda p: p.name):
            if child.is_symlink() and not follow_symlinks:
                continue
            process_file(child, child.name)
        return results, warnings

    for dirpath, dirnames, filenames in os.walk(
        base, topdown=True, followlinks=follow_symlinks, onerror=onerror
    ):
        dir_path = Path(dirpath)
        # Prune excluded directories in place so os.walk does not descend.
        for dirname in list(dirnames):
            rel = (dir_path / dirname).relative_to(base).as_posix()
            if _is_excluded(rel, patterns):
                dirnames.remove(dirname)

        for name in sorted(filenames):
            filepath = dir_path / name
            relpath = filepath.relative_to(base).as_posix()
            process_file(filepath, relpath)

    return results, warnings