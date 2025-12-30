#!/usr/bin/env python3
"""Entry point for vaults_economics CLI."""

import sys

from vaults_economics.cli import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
