"""file_integrity_checker - a security engineering portfolio tool.

A modular, production-style File Integrity Verifier (FIM) that:

* Hashes files in fixed-size chunks (constant memory for multi-GB files)
  using MD5, SHA-1, SHA-256, or SHA-512 (SHA-256 default; MD5/SHA-1 are
  legacy-compatibility only -- see README for why they must not be relied
  on for security).
* Creates JSON baseline manifests, then verifies them, classifying every
  file as UNCHANGED, MODIFIED, MISSING, NEW, or UNREADABLE.
* Never silently fails: unreadable files are recorded in the manifest and
  flagged during verification, never dropped.
* Returns meaningful exit codes so it can drive CI/CD pipelines and cron
  jobs (0 = clean, 1 = tampering detected, 3 = operational error).
"""

from __future__ import annotations

from .comparator import Change, ComparisonResult, Status, compare
from .hashing import (
    CHUNK_SIZE,
    DEFAULT_ALGORITHM,
    SUPPORTED_ALGORITHMS,
    HashResult,
    hash_file,
    normalize_algorithm,
)
from .manifest import (
    DEFAULT_MANIFEST_NAME,
    MANIFEST_VERSION,
    Manifest,
    ManifestEntry,
    ManifestError,
    build_manifest,
    read_manifest,
    write_manifest,
)
from .scanner import scan_files

__version__ = "1.0.0"

__all__ = [
    "CHUNK_SIZE",
    "DEFAULT_ALGORITHM",
    "SUPPORTED_ALGORITHMS",
    "HashResult",
    "hash_file",
    "normalize_algorithm",
    "Change",
    "ComparisonResult",
    "Status",
    "compare",
    "DEFAULT_MANIFEST_NAME",
    "MANIFEST_VERSION",
    "Manifest",
    "ManifestEntry",
    "ManifestError",
    "build_manifest",
    "read_manifest",
    "write_manifest",
    "scan_files",
    "__version__",
]