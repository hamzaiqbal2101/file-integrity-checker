"""Chunked file hashing with size-stability detection.

Files are read in fixed-size chunks instead of being loaded whole, so files
of any size (including multiple GB) are handled with constant memory usage.

A file that is modified *while* it is being read produces a hash that
matches neither the old nor the new content. To avoid ever trusting such a
hash, the file size is checked immediately before and after the read; a
mismatch marks the result unstable and no digest is returned.

Algorithm policy (see README):
* SHA-256 is the default and recommended choice.
* SHA-512 is provided for stronger digest sizes where required.
* MD5 and SHA-1 are provided for legacy compatibility ONLY. Both are
  vulnerable to collision attacks and must not be relied on for
  security-critical integrity checks.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

CHUNK_SIZE = 8192
DEFAULT_ALGORITHM = "sha256"

SUPPORTED_ALGORITHMS = ("md5", "sha1", "sha256", "sha512")


@dataclass(frozen=True)
class HashResult:
    """Outcome of hashing a single file.

    Attributes:
        digest: Hex digest, or None when hashing failed or was unstable.
        size: File size in bytes, or None when it could not be determined.
        error: Human-readable failure reason, or None on success.
    """

    digest: str | None
    size: int | None
    error: str | None


def normalize_algorithm(name: str) -> str:
    """Validate and normalize an algorithm name.

    Args:
        name: Algorithm name as given by the user (e.g. ``"SHA-256"``,
            ``"sha256"``).

    Returns:
        The normalized, lowercased name.

    Raises:
        ValueError: If the algorithm is not in SUPPORTED_ALGORITHMS.
    """
    normalized = name.strip().lower().replace("-", "")
    if normalized not in SUPPORTED_ALGORITHMS:
        raise ValueError(
            f"unsupported algorithm {name!r}; supported: "
            f"{', '.join(SUPPORTED_ALGORITHMS)}"
        )
    return normalized


def hash_file(
    path: str | os.PathLike[str],
    algorithm: str = DEFAULT_ALGORITHM,
    chunk_size: int = CHUNK_SIZE,
) -> HashResult:
    """Hash a single file by reading it in chunks.

    Args:
        path: Path to the file to hash.
        algorithm: One of :data:`SUPPORTED_ALGORITHMS`.
        chunk_size: Number of bytes read per iteration.

    Returns:
        A :class:`HashResult`. ``digest`` is None (with ``error`` set) when
        the file cannot be read or changes while it is being hashed, so a
        caller never trusts an inconsistent hash.
    """
    try:
        hasher = hashlib.new(normalize_algorithm(algorithm))
    except ValueError as exc:
        return HashResult(None, None, str(exc))

    try:
        with open(path, "rb") as handle:
            size_before = os.fstat(handle.fileno()).st_size
            size = 0
            while True:
                chunk = handle.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
                size += len(chunk)
            size_after = os.fstat(handle.fileno()).st_size
    except OSError as exc:
        reason = exc.strerror or str(exc)
        return HashResult(None, None, f"cannot read file: {reason}")

    if size_before != size_after:
        return HashResult(None, size, "file changed while being hashed (unstable)")

    return HashResult(hasher.hexdigest(), size, None)