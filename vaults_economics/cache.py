"""Caching functionality for vault economics analysis."""

import hashlib
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

from vaults_economics.constants import CACHE_DIR_NAME, CACHE_VERSION


def get_cache_dir() -> Path:
    """Get the cache directory path. Uses XDG_CACHE_HOME if available, otherwise ~/.cache."""
    cache_home = os.getenv("XDG_CACHE_HOME")
    if cache_home:
        base = Path(cache_home)
    else:
        base = Path.home() / ".cache"
    cache_dir = base / CACHE_DIR_NAME
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def clear_cache() -> None:
    """Clear all cached data."""
    cache_dir = get_cache_dir()
    if cache_dir.exists():
        shutil.rmtree(cache_dir)
        print("✅ Cache cleared successfully.", file=sys.stderr)
    else:
        print("ℹ️  Cache directory does not exist (nothing to clear).", file=sys.stderr)


def cache_key(prefix: str, *parts: Any) -> str:
    """Generate a deterministic cache key from prefix and parts."""
    key_str = f"{prefix}:{CACHE_VERSION}:" + ":".join(str(p) for p in parts)
    return hashlib.sha256(key_str.encode()).hexdigest()


def get_cached(cache_key: str) -> Any | None:
    """Get cached data by key. Returns None if not found or invalid."""
    cache_dir = get_cache_dir()
    cache_file = cache_dir / f"{cache_key}.json"
    if not cache_file.exists():
        return None
    try:
        with cache_file.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:  # pylint: disable=broad-exception-caught
        # If cache file is corrupted, ignore it
        return None


def set_cached(cache_key: str, data: Any) -> None:
    """Store data in cache."""
    cache_dir = get_cache_dir()
    cache_file = cache_dir / f"{cache_key}.json"
    try:
        with cache_file.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=None, separators=(",", ":"))
    except Exception:  # pylint: disable=broad-exception-caught
        # If caching fails, continue without cache
        pass
