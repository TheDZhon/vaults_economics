# Vault Economics (Lido AccountingOracle) — standalone script

This folder is **fully standalone**: it does not import anything from the parent repo.

It scans Lido **AccountingOracle** daily `submitReportData(...)` submissions on Ethereum mainnet, extracts
the `vaultsDataTreeCid` IPFS CID, downloads the Merkle-tree JSON, and prints a simple vault-economics
summary for the latest report, plus:

- per-vault deltas **since last report**
- per-vault deltas **since first report** (when `--reports >= 3`)
- a final **aggregates** footer across all stVaults (totals + delta vs last/first)

For scale (50–100 vaults), the “changes” sections omit unchanged vaults.

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

Notes:

- Use `--reports 2` for “since last report”.
- Use `--reports >= 3` to also get “since first report”.

If you omit `--rpc-url` and `ETH_RPC_URL`, the script will try a small list of public mainnet RPC endpoints by default.

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
- **Validation**: by default, the script validates report invariants and metadata (format/root checks, fee consistency,
  maxLiabilityShares >= liabilityShares, non-negative fee components).
  Use `--no-validate` to skip validation (useful for debugging corrupted reports).

## Vault report field semantics (important)

The IPFS JSON is a Merkle-tree dump used by `LazyOracle.updateVaultData(...)` → `VaultHub.applyVaultReport(...)`.
Some fields are easy to misread:

- **`totalValueWei`**: *oracle-reported* total value for the vault at `refSlot` (may be partially quarantined on-chain by `LazyOracle`).
- **`fee`**: cumulative **Lido protocol fees** accrued on the vault (wei) as of `refSlot`.
- **`liabilityShares`**: current stETH **liability** for the vault, nominated in shares, as of `refSlot`.
- **`maxLiabilityShares`**: **NOT a “capacity/share limit”**. It is a *high-water mark* of liability shares within the
  current oracle period (used by `VaultHub` to compute `locked`). It can be **greater than** `liabilityShares` if the
  vault reduced liability (burn/rebalance) after reaching a higher peak during the period.
- **`slashingReserve`**: extra ETH (wei) that must remain locked due to slashing risk; contributes to the minimal reserve floor.

The report’s `extraValues` are convenience fields (not part of the Merkle root):

- **`inOutDelta`**: cumulative **deposits − withdrawals** counter (wei) tracked by `VaultHub` (can be negative).
- **`prevFee`**: previous cumulative fee value; together with `infraFee`/`liquidityFee`/`reservationFee` it explains the
  delta in `fee` for this report.

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

Validation warnings are printed to stderr but do not stop execution. Use `--no-validate` to skip validation
(useful for debugging corrupted reports or testing).

## Limitations

- **Quarantine**: `totalValueWei` in reports may be partially quarantined on-chain by `LazyOracle` for sudden increases.
  The script shows the *reported* value, not the on-chain applied value.
- **Vault lifecycle**: Vaults can disconnect and reconnect, which resets their fee counters. Cross-report validation
  accounts for this by only checking vaults present in both reports.
- **Share rate**: `simulatedShareRate` is used for display conversions (shares → ETH). If invalid (≤ 0), conversions show "n/a".
