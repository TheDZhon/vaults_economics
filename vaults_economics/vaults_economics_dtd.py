#!/usr/bin/env python3
"""
Standalone: Vault economics day-to-date analysis from Lido AccountingOracle daily reports (Ethereum mainnet).

What it does
- Finds recent AccountingOracle daily reports by scanning `ProcessingStarted(uint256,bytes32)` logs.
- For each log's transaction, decodes `submitReportData(data, contractVersion)` input.
- Extracts `data.vaultsDataTreeCid` (an IPFS CID pointing to a JSON Merkle-tree dump).
- Downloads the JSON from IPFS gateways and validates report invariants (format/root checks, fee consistency,
  maxLiabilityShares >= liabilityShares, non-negative fee components).
- Fetches on-chain vault metrics from LazyOracle/VaultHub (reserve ratios, minting capacity, locked/withdrawable, etc.).
- Can read on-chain metrics at each report's block (archive nodes required) or latest state.
- Prints per-vault economics + delta vs previous/first report + aggregates summary.

Validation
By default, the script validates:
- Fee consistency: cumulative_lido_fees_wei == prevFee + infraFee + liquidityFee + reservationFee
- maxLiabilityShares >= liabilityShares (contract invariant)
- Cumulative fees are non-decreasing across reports (for same vault, when prevFee matches the prior report)
- Non-negative values for total value, fee components, fees, shares, and slashing reserve
- Report metadata sanity (tree root + format when present)

This script is self-contained: it does NOT import anything from the parent repository.
"""

import sys

from vaults_economics.cli import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
