"""Vault economics analysis package."""

from typing import NoReturn

__version__ = "0.1.0"


def _entry_point() -> NoReturn:
    """Entry point for the vaults-economics-dtd script."""
    import sys

    from vaults_economics.cli import main

    raise SystemExit(main(sys.argv[1:]))


def _clear_cache_entry_point() -> NoReturn:
    """Entry point for clearing the cache."""
    from vaults_economics.cache import clear_cache

    clear_cache()
    raise SystemExit(0)
