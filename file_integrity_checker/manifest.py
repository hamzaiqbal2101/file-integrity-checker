"""Baseline manifest serialization.

Manifests are JSON documents describing a baseline state of a file or
directory tree. They are written *atomically* (temp file + rename in the
same directory) so a crash mid-write can never leave a truncated or corrupt
baseline.

Tamper-evidence: a manifest on the same disk as the files it describes can
be rewritten by an attacker along with the files. Real deployments should
store the manifest off-box and/or sign it (HMAC or asymmetric signature).
Signing is documented as a future improvement in the README; the on-disk
format already reserves the structure needed to add a signature without a
breaking change.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from file_integrity_checker.hashing import HashResult

MANIFEST_VERSION = 1
DEFAULT_MANIFEST_NAME = "integrity-manifest.json"


class ManifestError(Exception):
    """Raised when a manifest is missing, malformed, or incompatible."""


@dataclass(frozen=True)
class ManifestEntry:
    """A single file record within a manifest.

    Attributes:
        path: Path relative to the scanned base, POSIX separators.
        size: File size in bytes, or None if unknown or unreadable.
        digest: Hex digest, or None if the file could not be hashed.
        error: Read error recorded at baseline time, or None.
    """

    path: str
    size: int | None = None
    digest: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class Manifest:
    """An integrity baseline for a file or directory tree."""

    algorithm: str
    base_dir: str
    recursive: bool
    created_at: str
    generator: str
    entries: tuple[ManifestEntry, ...]


def build_manifest(
    algorithm: str,
    base_dir: str,
    recursive: bool,
    scan_results: dict[str, HashResult],
    generator: str,
) -> Manifest:
    """Build a :class:`Manifest` from scanner output.

    Args:
        algorithm: Hash algorithm used for every entry.
        base_dir: The path that was scanned (informational; entries are
            relative to it).
        recursive: Whether the scan recursed into subdirectories.
        scan_results: Mapping of relative path to :class:`HashResult`.
        generator: Tool identifier string recorded for provenance.

    Returns:
        A :class:`Manifest` with entries sorted by path for stable output.
    """
    entries = tuple(
        ManifestEntry(
            path=relpath,
            size=result.size,
            digest=result.digest,
            error=result.error,
        )
        for relpath, result in sorted(scan_results.items())
    )
    return Manifest(
        algorithm=algorithm,
        base_dir=base_dir,
        recursive=recursive,
        created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        generator=generator,
        entries=entries,
    )


def to_dict(manifest: Manifest) -> dict[str, object]:
    """Convert a :class:`Manifest` to its JSON-serializable dict form.

    The digest is emitted under the key ``hash`` (not ``digest``) to keep
    the on-disk schema concise and matching the tool's vocabulary.

    Args:
        manifest: The manifest to serialize.

    Returns:
        A dict ready for :func:`json.dumps`.
    """
    files = [
        {
            "path": entry.path,
            "size": entry.size,
            "hash": entry.digest,
            "error": entry.error,
        }
        for entry in manifest.entries
    ]
    return {
        "manifest_version": MANIFEST_VERSION,
        "generator": manifest.generator,
        "algorithm": manifest.algorithm,
        "created_at": manifest.created_at,
        "base_dir": manifest.base_dir,
        "recursive": manifest.recursive,
        "files": files,
    }


def serialize(manifest: Manifest) -> str:
    """Render a :class:`Manifest` as pretty-printed JSON text.

    Args:
        manifest: The manifest to render.

    Returns:
        JSON text ending with a newline.
    """
    return json.dumps(to_dict(manifest), indent=2, sort_keys=True) + "\n"


def from_dict(data: object) -> Manifest:
    """Parse and validate a manifest dict.

    Args:
        data: The parsed JSON value.

    Returns:
        A :class:`Manifest`.

    Raises:
        ManifestError: If the document is malformed, missing required
            fields, or has an unsupported ``manifest_version``.
    """
    if not isinstance(data, dict):
        raise ManifestError("manifest root must be a JSON object")

    # Version is validated first so a newer/incompatible manifest fails with
    # a precise message rather than a generic "missing field" error.
    try:
        version = int(data["manifest_version"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ManifestError(f"malformed manifest: {exc}") from exc
    if version != MANIFEST_VERSION:
        raise ManifestError(f"unsupported manifest version: {version}")

    try:
        algorithm = str(data["algorithm"])
        base_dir = str(data["base_dir"])
        recursive = bool(data["recursive"])
        created_at = str(data["created_at"])
        generator = str(data.get("generator", "unknown"))
        files = data["files"]
    except (KeyError, TypeError, ValueError) as exc:
        raise ManifestError(f"malformed manifest: {exc}") from exc

    if not isinstance(files, list):
        raise ManifestError("manifest 'files' must be a list")

    entries: list[ManifestEntry] = []
    for raw in files:
        if not isinstance(raw, dict):
            raise ManifestError("manifest entry must be an object")
        try:
            entry_path = str(raw["path"])
        except (KeyError, TypeError) as exc:
            raise ManifestError(f"manifest entry missing 'path': {exc}") from exc
        entries.append(
            ManifestEntry(
                path=entry_path,
                size=raw.get("size"),
                digest=raw.get("hash"),
                error=raw.get("error"),
            )
        )

    return Manifest(
        algorithm=algorithm,
        base_dir=base_dir,
        recursive=recursive,
        created_at=created_at,
        generator=generator,
        entries=tuple(entries),
    )


def write_manifest(manifest: Manifest, path: str | os.PathLike[str]) -> None:
    """Serialize and atomically write a manifest.

    The manifest is first written to a temporary file in the destination
    directory, then renamed into place with :func:`os.replace`. This
    guarantees the destination never contains a partial write.

    Args:
        manifest: The manifest to write.
        path: Destination file path. Parent directories are created.

    Raises:
        OSError: If the manifest cannot be written.
    """
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(
        prefix=f"{dest.name}.", suffix=".tmp", dir=str(dest.parent), text=True
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(serialize(manifest))
        os.replace(tmp_path, dest)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def read_manifest(path: str | os.PathLike[str]) -> Manifest:
    """Load and validate a manifest from disk.

    Args:
        path: Path to the manifest file.

    Returns:
        The loaded :class:`Manifest`.

    Raises:
        ManifestError: If the file is missing, unreadable, contains invalid
            JSON, or fails validation.
    """
    manifest_path = Path(path)
    if not manifest_path.is_file():
        raise ManifestError(f"manifest not found: {manifest_path}")

    try:
        text = manifest_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ManifestError(f"cannot read manifest: {exc}") from exc

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ManifestError(f"corrupted manifest (invalid JSON): {exc}") from exc

    return from_dict(data)