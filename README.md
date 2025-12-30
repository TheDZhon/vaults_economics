## Vault Economics (stVaults)

[![CI](https://github.com/TheDZhon/vaults_economics/actions/workflows/ci.yml/badge.svg)](https://github.com/TheDZhon/vaults_economics/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

CLI tool for Lido stVaults economics analysis from AccountingOracle reports.

> **WIP** — not audited, outputs should be independently verified.

### Usage

```bash
uv sync
export ETH_RPC_URL="https://your-mainnet-rpc"
uv run ve          # CLI report
uv run ve --html   # HTML report (opens browser)
uv run cc          # clear cache
```

### Flags

- `--rpc-url URL` — RPC URL (or set `ETH_RPC_URL`)
- `--html` — generate HTML report
- `--no-cache` — disable caching
- `--locator ADDR` — override LidoLocator

### Development

```bash
uv sync --all-extras
uv run pre-commit install
uv run pytest -q
```

### License

MIT
