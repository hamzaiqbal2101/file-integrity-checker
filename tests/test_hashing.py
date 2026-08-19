"""Unit tests for chunked hashing and the algorithm registry."""

from __future__ import annotations

import hashlib

import pytest

from file_integrity_checker.hashing import (
    HashResult,
    hash_file,
    normalize_algorithm,
)


def test_normalize_algorithm_normalizes_names() -> None:
    assert normalize_algorithm("sha256") == "sha256"
    assert normalize_algorithm("SHA-256") == "sha256"
    assert normalize_algorithm("  md5 ") == "md5"


def test_normalize_algorithm_rejects_unknown() -> None:
    with pytest.raises(ValueError):
        normalize_algorithm("crc32")
    with pytest.raises(ValueError):
        normalize_algorithm("sha3_999")


def test_known_content_hash(tmp_path) -> None:
    payload = b"hello world"
    path = tmp_path / "data.bin"
    path.write_bytes(payload)
    result = hash_file(path)
    assert result.error is None
    assert result.digest == hashlib.sha256(payload).hexdigest()
    assert result.size == len(payload)


@pytest.mark.parametrize(
    "algorithm",
    ["md5", "sha1", "sha256", "sha512"],
)
def test_all_algorithms_match_hashlib(tmp_path, algorithm: str) -> None:
    payload = b"the quick brown fox jumps over the lazy dog" * 100
    path = tmp_path / "data.bin"
    path.write_bytes(payload)
    result = hash_file(path, algorithm=algorithm)
    assert result.error is None
    assert result.digest == hashlib.new(algorithm, payload).hexdigest()


def test_empty_file_hashes_to_empty_digest(tmp_path) -> None:
    path = tmp_path / "empty.bin"
    path.write_bytes(b"")
    result = hash_file(path)
    assert result.error is None
    assert result.digest == hashlib.sha256(b"").hexdigest()
    assert result.size == 0


@pytest.mark.parametrize("chunk_size", [1, 7, 4096, 8192, 1_000_000])
def test_chunk_size_does_not_change_digest(tmp_path, chunk_size: int) -> None:
    payload = bytes(range(256)) * 100  # 25.6 KB
    path = tmp_path / "data.bin"
    path.write_bytes(payload)
    reference = hash_file(path, chunk_size=8192)
    for chunk in (chunk_size,):
        result = hash_file(path, chunk_size=chunk)
        assert result.digest == reference.digest
        assert result.digest == hashlib.sha256(payload).hexdigest()


def test_hash_file_missing_returns_error_not_raise(tmp_path) -> None:
    result = hash_file(tmp_path / "does-not-exist.bin")
    assert isinstance(result, HashResult)
    assert result.digest is None
    assert result.error is not None


def test_hash_file_on_directory_returns_error(tmp_path) -> None:
    directory = tmp_path / "adir"
    directory.mkdir()
    result = hash_file(directory)
    assert result.digest is None
    assert result.error is not None


def test_hash_file_invalid_algorithm_returns_error(tmp_path) -> None:
    path = tmp_path / "data.bin"
    path.write_bytes(b"x")
    result = hash_file(path, algorithm="sha999")
    assert result.digest is None
    assert "unsupported" in result.error