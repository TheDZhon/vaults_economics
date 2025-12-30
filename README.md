## Vault Economics (stVaults) — day‑to‑date report tool

[![Status: WIP](https://img.shields.io/badge/status-WIP-orange)](#wip--disclaimer)
[![CI](https://github.com/TheDZhon/vaults_economics/actions/workflows/ci.yml/badge.svg)](https://github.com/TheDZhon/vaults_economics/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python: 3.10+](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)
![Packaging: uv](https://img.shields.io/badge/packaging-uv-6f42c1)
![Code Style: Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)
![Type Checked: mypy](https://img.shields.io/badge/mypy-checked-blue)

Standalone CLI that scans Lido AccountingOracle report submissions on Ethereum mainnet, decodes
`submitReportData(...)` to extract `vaultsDataTreeCid`, downloads the IPFS Merkle-tree JSON,
and prints per-vault economics, deltas, aggregates, and analytics.

It can also generate a dark-themed HTML report (`--html`) and always attempts to fetch on-chain metrics
from LazyOracle/VaultHub at each report block (archive RPC recommended; failures surface as warnings).

### WIP / Disclaimer

- **Work in progress**: this project is built for ad-hoc runs and may change without notice.
- **May contain bugs**: outputs are best-effort and should be independently verified.
- **Not audited / not production-ready**: do not use for automated decision making or financial operations.
- **Network privacy**: uses your RPC endpoint and public IPFS gateways for data fetches.

### Highlights

- **Per-vault economics**: total value, stETH liability (shares), fee components, annualized projections.
- **Deltas**: changes since the last report.
- **Aggregates** across all vaults (totals + deltas).
- **Analytics** (always enabled): adoption, revenue, capital efficiency, risk metrics, growth trends, rankings.
- **On-chain metrics**: total value, locked/withdrawable, minting capacity, utilization, health factor, reserve ratios.
- **HTML report**: dashboard + vault cards + mobile-friendly layout (served locally).
- **Caching** for IPFS, logs, txs, blocks, and on-chain metrics.

### Contents

- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Requirements](#requirements)
- [CLI entrypoints](#cli-entrypoints)
- [Usage notes](#usage-notes)
- [Handy CLI flags (cheat sheet)](#handy-cli-flags-cheat-sheet)
- [HTML report](#html-report)
- [Caching](#caching)
- [Vault report field semantics (important)](#vault-report-field-semantics-important)
- [Validation (warnings-only)](#validation-warnings-only)
- [Output overview](#output-overview)
- [Development](#development)
- [CI & quality](#ci--quality)
- [Contributing](#contributing)
- [Code of Conduct](#code-of-conduct)
- [Security](#security)
- [License](#license)

### Quick start

Install runtime dependencies:

```bash
uv sync
```

Run (scans from the first known vault report block and caches results for faster reruns):

```bash
export ETH_RPC_URL="https://your-mainnet-rpc"
uv run ve
```

Or specify RPC URL directly:

```bash
uv run ve --rpc-url "https://your-mainnet-rpc"
```

HTML report (starts a local server and opens a browser tab):

```bash
uv run ve --html
```

Stop the HTML server with `Ctrl+C`.

### How it works

1. Resolve Lido contract addresses (AccountingOracle, LazyOracle, VaultHub, Lido) via **LidoLocator**.
1. Scan `ProcessingStarted(uint256,bytes32)` logs from block `24089645` to latest.
1. Decode each `submitReportData(...)` input to extract `vaultsDataTreeCid`, `vaultsDataTreeRoot`, and `simulatedShareRate`.
1. Download the IPFS report JSON via HTTP gateways; parse `values` + `extraValues`, using `leafIndexToData` when present.
1. Validate metadata and per-vault invariants; emit warnings to stderr.
1. Fetch on-chain metrics at each report block via LazyOracle and VaultHub (archive RPC recommended).
1. Render the CLI report, analytics summary, growth trends, and (optionally) the HTML dashboard.

### Requirements

- Python 3.10+
- Execution-layer RPC URL (`--rpc-url` or `ETH_RPC_URL`)
- Archive-capable RPC for historical on-chain metrics (non-archive nodes will emit warnings and omit metrics)
- Outbound HTTPS access to public IPFS gateways

### CLI entrypoints

- `ve` / `vaults` / `vaults-economics-dtd`: run the report
- `cc` / `vaults-clear-cache`: clear local cache

### Usage notes

- **Report discovery**: scans `ProcessingStarted` logs and decodes `submitReportData` tx inputs.
- **IPFS fetch**: tries multiple gateways (default includes ipfs.io, Cloudflare, Pinata); CID content is cached.
- **Report parsing**: reads `values` and honors `leafIndexToData` when present; `extraValues` supply fee deltas + `inOutDelta`.
- **Share rate**: uses `simulatedShareRate` from each report to convert shares → wei (prints `n/a` if invalid).
- **On-chain metrics**: fetched per report block via LazyOracle `batchVaultsInfo` + VaultHub `totalValue`, `locked`, `withdrawableValue`, `obligations`, `isVaultHealthy`.
- **Historical reads**: require an archive-capable RPC; missing data is reported as warnings.
- **Contract resolution**: resolves AccountingOracle/LazyOracle/VaultHub/Lido dynamically via **LidoLocator**.
- **RPC required**: must provide an RPC URL via `--rpc-url` or `ETH_RPC_URL` environment variable.

### Handy CLI flags (cheat sheet)

- **`--rpc-url URL`**: execution-layer RPC URL (required if `ETH_RPC_URL` is not set).
- **`--html`**: generate and serve HTML report in browser.
- **`--no-cache`**: disable caching for this run.
- **`--locator ADDRESS`**: override LidoLocator (testnets).

### HTML report

- Served from a local HTTP server (`127.0.0.1` on a random port) and opened in your default browser.
- Static HTML/CSS with hover tooltips and Etherscan/Beaconcha links (no client-side JS).

### Caching

Cached items:

- **IPFS content** (by CID)
- **On-chain logs** (by filter parameters)
- **Transactions** (by transaction hash)
- **Blocks** (by block identifier)
- **On-chain metrics** (by block identifier and vault keys)

Cache location:

- `~/.cache/.vaults_economics_cache/` (or `XDG_CACHE_HOME/.vaults_economics_cache/`)

Clear cache:

```bash
uv run cc
```

Disable cache for a run:

```bash
uv run ve --no-cache
```

### Vault report field semantics (important)

The IPFS JSON is a Merkle-tree dump consumed by `LazyOracle.updateVaultData(...)` → `VaultHub.applyVaultReport(...)`.

- **`totalValueWei`**: oracle-reported total value at `refSlot` (may be partially quarantined on-chain by LazyOracle).
- **`fee`**: cumulative Lido protocol fees accrued (wei) as of `refSlot` (not “unsettled”).
- **`liabilityShares`**: current stETH liability in shares.
- **`maxLiabilityShares`**: high-water mark of liability shares within the oracle period (used to compute `locked`).
- **`slashingReserve`**: extra ETH locked due to slashing risk; contributes to minimal reserve.

The report’s `extraValues` are convenience fields (not part of the Merkle root):

- **`inOutDelta`**: cumulative deposits − withdrawals counter (wei, can be negative).
- **`prevFee`** + fee components explain the delta in cumulative `fee`.
- **`infraFee` / `liquidityFee` / `reservationFee`**: per-period Lido fee components.
- **This report’s fee** is computed as `infraFee + liquidityFee + reservationFee`.

### Validation (warnings-only)

By default, the tool validates common invariants (warnings go to stderr):

- Fee consistency: `fee == prevFee + infraFee + liquidityFee + reservationFee`
- `maxLiabilityShares >= liabilityShares`
- Non-negative values for fee components, value, shares, and slashing reserve
- IPFS metadata checks: `format`, `refSlot`, and `tree` root when present
- Cross-report checks: cumulative fees non-decreasing when `prevFee` links to the previous report

### Output overview

- **CLI (default)**: prints IPFS report sources, per-vault economics, changes since the last report, aggregates,
  analytics summary, growth trends (if 2+ reports), and top-performing vaults.
- **HTML (`--html`)**: generates a full-page dashboard (analytics, aggregates, vault cards), serves it locally,
  and opens your browser. In HTML mode, the CLI report is not printed.

### Development

Install dev dependencies:

```bash
uv sync --all-extras
```

Run checks locally:

```bash
uv run ruff check .
uv run mypy .
uv run ruff format .
uv run mdformat README.md
uv run pytest -q
```

Install pre-commit hooks (automatically runs linting and formatting on commit):

```bash
uv run pre-commit install
```

### CI & quality

CI runs on pushes/PRs (GitHub Actions) and enforces:

- **Linting**: `ruff` (imports, bugbear, pyupgrade, builtins, comprehensions, etc.)
- **Type Checking**: `mypy` (strict mode, fully typed)
- **Formatting**: `ruff format` and `mdformat`
- **Security**: `pip-audit` for dependency vulnerabilities
- **Testing**: `pytest`
- **Compatibility**: Tested on Python 3.10, 3.11, 3.12, 3.13

### Contributing

Please see `CONTRIBUTING.md` for setup, quality checks, and PR guidelines.

### Code of Conduct

Please see `CODE_OF_CONDUCT.md`.

### Security

Please see `SECURITY.md` for vulnerability reporting guidance.

### License

- **This tool**: MIT — see `LICENSE`.
