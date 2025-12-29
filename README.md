## Vault Economics (stVaults) — day‑to‑date report tool

[![Status: WIP](https://img.shields.io/badge/status-WIP-orange)](#wip--disclaimer)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python: 3.10+](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)
![Tests: pytest](https://img.shields.io/badge/tests-pytest-brightgreen?logo=pytest&logoColor=white)
![Packaging: uv](https://img.shields.io/badge/packaging-uv-6f42c1)

Standalone tool that scans Lido **AccountingOracle** daily `submitReportData(...)` submissions (Ethereum mainnet), extracts
the `vaultsDataTreeCid` IPFS CID, downloads the Merkle-tree JSON, and prints a vault economics summary.

It can also generate an interactive (dark-themed) **HTML report** and optionally fetch **on-chain metrics** from LazyOracle/VaultHub.

### WIP / Disclaimer

- **Work in progress**: this project is built for ad-hoc runs and may change without notice.
- **May contain bugs**: outputs are best-effort and should be independently verified.
- **Not audited / not production-ready**: do not use for automated decision making or financial operations.
- **Network privacy**: requires an RPC endpoint to be provided via `--rpc-url` or `ETH_RPC_URL` environment variable.

### Highlights

- **Per-vault economics**: Total Value, stETH Liability (shares), Lido fee components, annualized projections.
- **Deltas**: changes since last report.
- **Aggregates footer** across all vaults (totals + deltas).
- **Analytics** (always enabled): adoption metrics, revenue, capital efficiency, risk metrics, and vault rankings.
- **On-chain metrics (optional)**: locked, withdrawable, minting capacity, utilization, health factor, pending disconnect, etc.
- **HTML report (optional)**: dashboard + vault cards + mobile-friendly layout.
- **Caching** for IPFS, logs, txs, blocks, metrics.

### Contents

- [Quick start](#quick-start)
- [Usage notes](#usage-notes)
- [Handy CLI flags (cheat sheet)](#handy-cli-flags-cheat-sheet)
- [Caching](#caching)
- [Vault report field semantics (important)](#vault-report-field-semantics-important)
- [Validation (warnings-only)](#validation-warnings-only)
- [Development](#development)
- [License](#license)

### Quick start

Install:

```bash
uv sync
```

Run (fetches all reports from genesis, cached for fast subsequent runs):

```bash
export ETH_RPC_URL="https://your-mainnet-rpc"
uv run ve
```

Or specify RPC URL directly:

```bash
uv run ve --rpc-url "https://your-mainnet-rpc"
```

HTML report (opens browser):

```bash
uv run ve --html
```

### Usage notes

- **Report discovery**: finds reports by scanning `ProcessingStarted(uint256,bytes32)` logs and decoding the corresponding tx input.
- **Contract resolution**: resolves AccountingOracle/LazyOracle/VaultHub/Lido dynamically via **LidoLocator** (no hardcoded addresses).
- **Historical on-chain reads**: reads on-chain metrics at each report's tx block (requires archive-capable RPC).
- **RPC required**: must provide an RPC URL via `--rpc-url` or `ETH_RPC_URL` environment variable.

### Handy CLI flags (cheat sheet)

- **`--rpc-url URL`**: execution-layer RPC URL (required if `ETH_RPC_URL` is not set).
- **`--html`**: generate and serve HTML report in browser.
- **`--no-cache`**: disable caching for this run.
- **`--locator ADDRESS`**: override LidoLocator (testnets).

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

The IPFS JSON is a Merkle-tree dump used by `LazyOracle.updateVaultData(...)` → `VaultHub.applyVaultReport(...)`.

- **`totalValueWei`**: oracle-reported total value at `refSlot` (may be partially quarantined on-chain by LazyOracle).
- **`fee`**: cumulative Lido protocol fees accrued (wei) as of `refSlot` (not “unsettled”).
- **`liabilityShares`**: current stETH liability nominated in shares.
- **`maxLiabilityShares`**: high-water mark of liability shares within the oracle period (used to compute `locked`).
- **`slashingReserve`**: extra ETH locked due to slashing risk; contributes to minimal reserve.

The report’s `extraValues` are convenience fields (not part of the Merkle root):

- **`inOutDelta`**: cumulative deposits − withdrawals counter (wei, can be negative).
- **`prevFee`** + fee components explain the delta in cumulative `fee`.
- **`infraFee` / `liquidityFee` / `reservationFee`**: per-period Lido fee components.

### Validation (warnings-only)

By default, the tool validates common contract invariants (warnings go to stderr):

- Fee consistency: `fee == prevFee + infraFee + liquidityFee + reservationFee`
- `maxLiabilityShares >= liabilityShares`
- Cumulative fees non-decreasing across reports when `prevFee` links correctly
- Non-negative values + basic metadata checks (format/root/refSlot)

### Development

Run tests:

```bash
uv sync --all-extras
uv run pytest -q
```

Install pre-commit:

```bash
uv sync --all-extras
uv run pre-commit install
```

### License

- **This tool**: MIT — see `LICENSE`.
