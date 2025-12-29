# Vault Economics (Lido AccountingOracle) — standalone script

This folder is **fully standalone**: it does not import anything from the parent repo.

It scans Lido **AccountingOracle** daily `submitReportData(...)` submissions on Ethereum mainnet, extracts
the `vaultsDataTreeCid` IPFS CID, downloads the Merkle-tree JSON, and prints a simple vault-economics
summary for the latest report, plus:

- per-vault deltas **since last report**
- per-vault deltas **since first report** (when `--reports >= 3`)
- a final **aggregates** footer across all stVaults (totals + delta vs last/first)
- **projected annual revenue** based on current daily fees (per-vault and aggregate)

For scale (50–100 vaults), the "changes" sections omit unchanged vaults.

By default, the script also fetches **on-chain metrics** from LazyOracle/VaultHub:

- Not Staked stVault Balance, Staked on validators
- Collateral (locked), Total Lock (collateral + unsettled Lido fees), Unsettled Lido fees
- Available to withdraw
- stETH minting limit, Total/Remaining stETH minting capacity, Utilization Ratio, Health Factor
- Reserve Ratio, Forced Rebalance Threshold, Healthy/pending disconnect flags

Contract addresses are resolved dynamically via **LidoLocator** (no hardcoded addresses).

## Setup

```bash
uv sync
```

## Run

After installing, you can run the script using the entry point:

```bash
export ETH_RPC_URL="https://your-mainnet-rpc"
uv run vaults-economics-dtd --rpc-url "$ETH_RPC_URL" --reports 7
```

Or run it directly as a module:

```bash
uv run python -m vaults_economics.vaults_economics_dtd --rpc-url "$ETH_RPC_URL" --reports 7
```

**Quick start (latest report only):**

```bash
uv run vaults-economics-dtd --reports 1
```

**HTML report (opens in browser):**

```bash
uv run vaults-economics-dtd --reports 1 --html
```

Notes:

- Use `--reports 1` to focus on the latest report.
- Use `--reports 2` for "since last report".
- Use `--reports >= 3` to also get "since first report".
- Use `--html` to generate and serve an interactive HTML report (opens default browser).
- Use `--html-port PORT` to specify a custom port for the HTML server.
- Use `--no-onchain` to skip on-chain metrics (fewer RPC calls).
- Use `--onchain-block report` (default) to read on-chain data at each report's tx block, or
  `--onchain-block latest` for non-archive nodes.
- Use `--locator ADDRESS` to override the LidoLocator address for testnets.

If you omit `--rpc-url` and `ETH_RPC_URL`, the script will try a small list of public mainnet RPC endpoints by default.

## Caching

The script caches fetched data to avoid redundant network requests:

- **IPFS content** (by CID)
- **Onchain logs** (by filter parameters)
- **Transactions** (by transaction hash)
- **Blocks** (by block identifier)
- **Onchain metrics** (by block identifier and vault keys)

**Cache location**: `~/.cache/.vaults_economics_cache/` (or `XDG_CACHE_HOME/.vaults_economics_cache/` if `XDG_CACHE_HOME` is set)

**Clear cache**:

```bash
uv run vaults-economics-dtd --clear-cache
```

**Disable caching** (fetch fresh data):

```bash
uv run vaults-economics-dtd --no-cache --reports 7
```

Caching is enabled by default and significantly speeds up repeated runs when analyzing the same reports or blocks. The cache is versioned, so you can safely clear it if you encounter issues with stale data.

## Test

```bash
uv sync --all-extras
uv run pytest -q
```

## Pre-commit

```bash
uv sync --all-extras
uv run pre-commit install
```

Run hooks manually:

```bash
uv run pre-commit run --all-files
```

## HTML Report

Generate a beautiful dark-themed HTML report and view it in your browser:

```bash
uv run vaults-economics-dtd --reports 1 --html
```

The HTML report includes:

- **Aggregates dashboard**: total vaults, economic modes, total value, fees, and projected annual revenue
- **Individual vault cards**: status badges, metrics, fee breakdown with annual projections, on-chain data
- **Responsive design**: works on desktop and mobile
- **Modern styling**: dark theme with Outfit + JetBrains Mono fonts

The server runs locally on `127.0.0.1` (auto-selects an available port). Press `Ctrl+C` to stop.

## Notes

- **CID source**: the CID is the `vaultsDataTreeCid` string inside the `submitReportData` tx input.
- **Report discovery**: the script finds recent reports by scanning `ProcessingStarted(uint256,bytes32)` logs
  and decoding the corresponding transactions. Use `--reports` and `--days` to bound the scan window.
- **Contract resolution**: all contract addresses (AccountingOracle, LazyOracle, VaultHub, Lido) are resolved
  dynamically via LidoLocator. Use `--locator ADDRESS` for testnets.
- **IPFS gateways**: uses a small default list of public gateways (see `vaults_economics/constants.py`).
- **On-chain metrics**: derived from LazyOracle/VaultHub view calls; historical reads (`--onchain-block report`)
  require an archive-capable RPC provider.
- **Annual projections**: calculated by multiplying daily fees by 365, assuming current fees continue.
- **Caching**: by default, the script caches IPFS content, onchain logs, transactions, blocks, and metrics to avoid
  redundant network requests. Use `--clear-cache` to clear all cached data, or `--no-cache` to disable caching for a run.
- **Validation**: the script validates report invariants and metadata (format/root checks, fee consistency,
  maxLiabilityShares >= liabilityShares, non-negative fee components).

## Vault report field semantics (important)

The IPFS JSON is a Merkle-tree dump used by `LazyOracle.updateVaultData(...)` → `VaultHub.applyVaultReport(...)`.
Some fields are easy to misread:

- **`totalValueWei`**: *oracle-reported* total value for the vault at `refSlot` (may be partially quarantined on-chain by `LazyOracle`).
- **`fee`**: cumulative **Lido protocol fees** accrued on the vault (wei) as of `refSlot` (not “unsettled”).
- **`liabilityShares`**: current **stETH Liability** for the vault, nominated in shares, as of `refSlot`.
- **`maxLiabilityShares`**: **NOT a “capacity/share limit”**. It is a *high-water mark* of liability shares within the
  current oracle period (used by `VaultHub` to compute `locked`). It can be **greater than** `liabilityShares` if the
  vault reduced liability (burn/rebalance) after reaching a higher peak during the period.
- **`slashingReserve`**: extra ETH (wei) that must remain locked due to slashing risk; contributes to the **Minimal Reserve**
  (on-chain minimal reserve = max(1 ETH, slashingReserve)).

The report’s `extraValues` are convenience fields (not part of the Merkle root):

- **`inOutDelta`**: cumulative **deposits − withdrawals** counter (wei) tracked by `VaultHub` (can be negative).
- **`prevFee`**: previous cumulative fee value; together with `infraFee`/`liquidityFee`/`reservationFee` it explains the
  delta in `fee` for this report.
- **`infraFee`**: Lido **Infrastructure fee** accrued during this report period.
- **`liquidityFee`**: Lido **Liquidity fee** accrued during this report period.
- **`reservationFee`**: Lido **Reservation liquidity fee** accrued during this report period.

## Validation

By default, the script validates report invariants enforced by the on-chain contracts:

- **Fee consistency**: `cumulative_lido_fees_wei == prevFee + infraFee + liquidityFee + reservationFee`
  (the Merkle tree `fee` field should equal the sum of previous fees plus this period's fee components)
- **maxLiabilityShares >= liabilityShares**: contract enforces this within each report
- **Cumulative fees non-decreasing**: when comparing the same vault across reports, cumulative fees should only increase
  **if** the report’s `prevFee` matches the prior report’s cumulative fee (reconnects reset fees)
- **Non-negative values**: totalValue, fees (including fee components), shares, and slashing reserve should be non-negative
- **Report metadata sanity**: when present, `format` is `standard-v1`, `refSlot` matches the tx, and
  the report root matches `vaultsDataTreeRoot`

Validation warnings are printed to stderr but do not stop execution.

## Limitations

- **Quarantine**: `totalValueWei` in reports may be partially quarantined on-chain by `LazyOracle` for sudden increases.
  The report section shows the *reported* value; the on-chain section (when enabled) shows applied `totalValue`.
- **Vault lifecycle**: Vaults can disconnect and reconnect, which resets their fee counters. Cross-report validation
  accounts for this by only checking vaults present in both reports.
- **Share rate**: `simulatedShareRate` is used for display conversions (shares → ETH). If invalid (≤ 0), conversions show "n/a".
- **Metrics scope**: The report contains Total Value, stETH Liability, Lido fees, and slashing reserve. The script
  augments this with on-chain metrics (LazyOracle/VaultHub). It does **not** compute Node Operator fee, APR,
  or stETH rebase; those require additional off-chain data and consensus-layer inputs.
