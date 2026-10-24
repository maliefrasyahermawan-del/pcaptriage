"""SHA-256 utilities used across analyzers for chain-of-custody."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Union


_CHUNK = 1024 * 1024  # 1 MiB


def sha256_bytes(data: bytes) -> str:
    """Return hex SHA-256 digest of an in-memory byte string.

    Args:
        data: Raw bytes to hash.

    Returns:
        Lowercase hexadecimal digest (64 chars).
    """
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Union[str, Path]) -> str:
    """Stream-hash a file on disk.

    Args:
        path: Filesystem path to read.

    Returns:
        Lowercase hexadecimal SHA-256 digest of the file contents.

    Raises:
        FileNotFoundError: When ``path`` does not exist.
    """
    h = hashlib.sha256()
    with open(path, "rb") as fp:
        for chunk in iter(lambda: fp.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()
