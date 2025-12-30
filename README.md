## Vault Economics (stVaults)

[![CI](https://github.com/TheDZhon/vaults_economics/actions/workflows/ci.yml/badge.svg)](https://github.com/TheDZhon/vaults_economics/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python: 3.10+](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)
![Packaging: uv](https://img.shields.io/badge/packaging-uv-6f42c1)
![Code Style: Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)
![Type Checked: mypy](https://img.shields.io/badge/mypy-checked-blue)

CLI tool for Lido stVaults economics analysis from AccountingOracle reports.

> **WIP** — not audited, outputs should be independently verified.

### Requirements

- Python 3.10+
- Ethereum RPC URL (archive node recommended for historical metrics)

### Quick start

```bash
uv sync
export ETH_RPC_URL="https://your-mainnet-rpc"
uv run ve
```

HTML report (opens browser):

```bash
uv run ve --html
```

Clear cache:

```bash
uv run cc
```

### How it works

1. Resolve contracts via LidoLocator
1. Scan `ProcessingStarted` logs from genesis block
1. Decode `submitReportData(...)` to extract IPFS CID
1. Download and parse the Merkle-tree JSON
1. Fetch on-chain metrics at each report block
1. Render CLI or HTML report with analytics

### CLI flags

| Flag | Description |
|------|-------------|
| `--rpc-url URL` | RPC URL (or set `ETH_RPC_URL`) |
| `--html` | Generate HTML report |
| `--no-cache` | Disable caching |
| `--locator ADDR` | Override LidoLocator |

### Development

```bash
uv sync --all-extras
uv run pre-commit install
uv run pytest -q
```

### License

MIT
