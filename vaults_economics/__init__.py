"""Vault economics analysis package."""

__version__ = "0.1.0"


def _entry_point():
    """Entry point for the vaults-economics-dtd script."""
    import sys

    from vaults_economics.vaults_economics_dtd import main

    raise SystemExit(main(sys.argv[1:]))
