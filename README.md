# Vault Economics (Lido AccountingOracle) — standalone script

This folder is **fully standalone**: it does not import anything from the parent repo.

It scans Lido **AccountingOracle** daily `submitReportData(...)` submissions on Ethereum mainnet, extracts
the `vaultsDataTreeCid` IPFS CID, downloads the Merkle-tree JSON, and prints a simple vault-economics
summary + delta vs previous report (similar to the reference screenshot).

## Setup

```bash
uv sync
```

## Run

After installing, you can run the script using the entry point:

```bash
export ETH_RPC_URL="https://your-mainnet-rpc"
uv run vaults-economics-dtd --rpc-url "$ETH_RPC_URL" --reports 2
```

Or run it directly as a module:

```bash
uv run python -m vaults_economics.vaults_economics_dtd --rpc-url "$ETH_RPC_URL" --reports 2
```

If you omit `--rpc-url` and `ETH_RPC_URL`, the script will try a small list of public mainnet RPC endpoints by default.

## Test

```bash
uv sync --all-extras
uv run pytest -q
```

Analyze a specific transaction:

```bash
uv run vaults-economics-dtd --rpc-url "$ETH_RPC_URL" \
  --tx-hash 0xb1168ee90b001b3e04e76618a085c9dbb7eddb1415f462c839c6728110a4b86f
```

Export CSV for day-to-date analysis:

```bash
uv run vaults-economics-dtd --rpc-url "$ETH_RPC_URL" --reports 30 --out-csv /tmp/vaults.csv
```

## Notes

- **CID source**: the CID is the `vaultsDataTreeCid` string inside the `submitReportData` tx input.
- **Report discovery**: the script finds recent reports by scanning `ProcessingStarted(uint256,bytes32)` logs
  and decoding the corresponding transactions.
- **IPFS gateways**: you can add fallbacks with repeated `--ipfs-gateway ...`.

