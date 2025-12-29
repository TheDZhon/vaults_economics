"""Allow running the package as a module: python -m vaults_economics"""

import sys

from vaults_economics.cli import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
