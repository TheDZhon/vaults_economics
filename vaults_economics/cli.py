"""CLI and main logic."""

import argparse
import os
import sys
from datetime import datetime, timezone

from tqdm import tqdm

from vaults_economics.blockchain import collect_recent_report_submissions
from vaults_economics.console import print_report_with_deltas
from vaults_economics.constants import (
    ACCOUNTING_ORACLE_MIN_ABI,
    DEFAULT_IPFS_GATEWAYS,
    LAZY_ORACLE_MIN_ABI,
    LIDO_LOCATOR_MAINNET,
    VAULT_HUB_MIN_ABI,
)
from vaults_economics.contracts import resolve_lido_contracts
from vaults_economics.ipfs import fetch_ipfs_bytes
from vaults_economics.models import OnchainVaultMetrics, VaultSnapshot
from vaults_economics.onchain import collect_onchain_metrics
from vaults_economics.parsing import parse_ipfs_report, parse_report_to_snapshots
from vaults_economics.validation import validate_cross_report_consistency, validate_ipfs_report_metadata

# Internal defaults (not exposed as CLI flags)
DEFAULT_TIMEOUT = 30
DEFAULT_VAULTS_PAGE_SIZE = 200


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse command-line arguments."""
    p = argparse.ArgumentParser(description="Standalone vault economics analysis from Lido AccountingOracle reports.")
    p.add_argument(
        "--rpc-url",
        default=None,
        help="Execution-layer RPC URL. Required if ETH_RPC_URL environment variable is not set.",
    )
    p.add_argument(
        "--locator",
        default=LIDO_LOCATOR_MAINNET,
        help="LidoLocator address (resolves all other contract addresses). Default: mainnet locator.",
    )
    p.add_argument(
        "--html",
        action="store_true",
        help="Generate an HTML report and serve it locally, opening the default browser.",
    )
    p.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable caching for this run (fetch all data fresh from network).",
    )
    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    """Main entry point."""
    args = parse_args(argv)

    use_cache = not args.no_cache

    try:
        from web3 import Web3
    except ImportError as ex:  # pragma: no cover
        print("Missing dependency. Run: uv sync", file=sys.stderr)
        raise SystemExit(2) from ex

    # Require RPC URL to be provided either via --rpc-url or ETH_RPC_URL environment variable
    rpc_url = args.rpc_url or os.getenv("ETH_RPC_URL")
    if not rpc_url:
        print(
            "Error: RPC URL is required. Provide --rpc-url or set ETH_RPC_URL environment variable.",
            file=sys.stderr,
        )
        return 2

    # Test connection
    w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": DEFAULT_TIMEOUT}))
    if not w3.is_connected():
        print(f"Error: failed to connect to RPC at {rpc_url}", file=sys.stderr)
        return 2

    # Resolve all contract addresses from LidoLocator.
    # This follows the pattern from lido-staking-vault-cli.
    try:
        contracts = resolve_lido_contracts(w3, args.locator)
        print(f"ℹ️ Resolved contracts from LidoLocator ({args.locator[:10]}...)", file=sys.stderr)
    except Exception as ex:
        print(f"Error: failed to resolve contracts from LidoLocator ({args.locator}): {ex}", file=sys.stderr)
        return 2

    oracle_addr = Web3.to_checksum_address(contracts.accounting_oracle)
    accounting_contract = w3.eth.contract(address=oracle_addr, abi=ACCOUNTING_ORACLE_MIN_ABI)

    lazy_oracle_addr = Web3.to_checksum_address(contracts.lazy_oracle)
    vault_hub_addr = Web3.to_checksum_address(contracts.vault_hub)
    lazy_oracle_contract = w3.eth.contract(address=lazy_oracle_addr, abi=LAZY_ORACLE_MIN_ABI)
    vault_hub_contract = w3.eth.contract(address=vault_hub_addr, abi=VAULT_HUB_MIN_ABI)

    gateways = DEFAULT_IPFS_GATEWAYS

    # Scan blockchain logs for all report submissions since genesis.
    submissions = collect_recent_report_submissions(
        w3,
        accounting_contract,
        oracle_addr,
        use_cache=use_cache,
    )

    if not submissions:
        print("No submitReportData transactions found in the scanned range.", file=sys.stderr)
        return 1

    # Download + parse reports.
    snapshots: list[dict[str, VaultSnapshot]] = []
    with tqdm(submissions, desc="📥 Downloading IPFS reports", unit="report", file=sys.stderr) as pbar:
        for sub in pbar:
            pbar.set_postfix(refSlot=sub.ref_slot)
            raw = fetch_ipfs_bytes(sub.vaults_tree_cid, gateways, timeout_s=DEFAULT_TIMEOUT, use_cache=use_cache)
            report_json = parse_ipfs_report(raw)
            meta_issues = validate_ipfs_report_metadata(
                report_json,
                expected_ref_slot=sub.ref_slot,
                expected_tree_root=sub.vaults_tree_root,
                warn_only=True,
            )
            if meta_issues:
                tqdm.write("⚠️  IPFS report metadata warnings:", file=sys.stderr)
                for issue in meta_issues:
                    tqdm.write(f"   {issue}", file=sys.stderr)
            snapshots.append(parse_report_to_snapshots(report_json, ref_slot=sub.ref_slot))

            # Validate simulated_share_rate (should be > 0 for meaningful conversions)
            if sub.simulated_share_rate <= 0:
                tqdm.write(
                    f"⚠️  Warning: refSlot={sub.ref_slot} has invalid simulatedShareRate: {sub.simulated_share_rate}",
                    file=sys.stderr,
                )

    onchain_metrics_list: list[dict[str, OnchainVaultMetrics]] = []
    onchain_blocks: list[int] = []
    with tqdm(
        zip(submissions, snapshots, strict=True),
        total=len(submissions),
        desc="🔗 Fetching on-chain metrics",
        unit="report",
        file=sys.stderr,
    ) as pbar:
        for sub, snap in pbar:
            pbar.set_postfix(refSlot=sub.ref_slot, vaults=len(snap))
            block_id = sub.block_number
            try:
                metrics = collect_onchain_metrics(
                    w3,
                    lazy_oracle_contract,
                    vault_hub_contract,
                    snap.keys(),
                    block_identifier=block_id,
                    page_size=DEFAULT_VAULTS_PAGE_SIZE,
                    use_cache=use_cache,
                )
            except Exception as ex:  # pylint: disable=broad-exception-caught
                tqdm.write(f"⚠️  On-chain metrics failed at block {block_id}: {ex}", file=sys.stderr)
                metrics = {}

            onchain_metrics_list.append(metrics)
            onchain_blocks.append(block_id)

    # Cross-report validation: cumulative fees should be non-decreasing (older → newer)
    if len(snapshots) > 1:
        for i in range(len(snapshots) - 1):
            # Compare older (i+1) to newer (i) report
            issues = validate_cross_report_consistency(
                snapshots[i + 1],  # older (baseline)
                snapshots[i],  # newer (current)
                prev_ref_slot=submissions[i + 1].ref_slot,
                cur_ref_slot=submissions[i].ref_slot,
                warn_only=True,
            )
            if issues:
                print("⚠️  Cross-report validation warnings:", file=sys.stderr)
                for issue in issues:
                    print(f"   {issue}", file=sys.stderr)

    # HTML mode: generate and serve
    if args.html:
        # Lazy import: HTML reporting is an optional, heavier feature.
        from vaults_economics.html_report import generate_html_report, serve_html_and_open_browser

        html_content = generate_html_report(submissions, snapshots, onchain_metrics_list, onchain_blocks)
        serve_html_and_open_browser(html_content)
        return 0

    # Print a header with extracted CIDs.
    print("\n🔗 IPFS Report Sources (latest first):")
    print("─" * 70)
    for i, sub in enumerate(submissions):
        ts = datetime.fromtimestamp(sub.block_timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        marker = "📍" if i == 0 else "  "
        print(f"{marker} {ts}  •  refSlot={sub.ref_slot}")
        print(f"   CID: {sub.vaults_tree_cid}")
    print("")

    # Show screenshot-style summary for latest report + deltas vs previous/first + aggregates.
    print_report_with_deltas(submissions, snapshots, onchain_metrics_list, onchain_blocks)

    # Analytics (always enabled)
    from vaults_economics.analytics import (
        calculate_growth_metrics,
        calculate_protocol_analytics,
        format_analytics_summary,
        rank_vaults_by_performance,
    )

    current = submissions[0]
    cur_snap = snapshots[0]
    onchain_cur = onchain_metrics_list[0]

    analytics = calculate_protocol_analytics(cur_snap, onchain_cur, current.simulated_share_rate)
    print(format_analytics_summary(analytics))

    # Growth trends
    growth = calculate_growth_metrics(submissions, snapshots)
    if growth.get("has_trend_data"):
        from decimal import Decimal

        from vaults_economics.constants import WEI_PER_ETH

        print("📈 GROWTH TRENDS")
        print(f"   Period: {growth['period_days']} days ({growth['reports_count']} reports)")
        tvl_change_sign = "+" if growth["tvl_change_wei"] >= 0 else ""
        print(
            f"   TVL: {Decimal(growth['tvl_first_wei']) / WEI_PER_ETH:.2f} → {Decimal(growth['tvl_latest_wei']) / WEI_PER_ETH:.2f} ETH ({tvl_change_sign}{growth['tvl_growth_pct']:.1f}%)"
        )
        print(f"   Vaults: {growth['vaults_first']} → {growth['vaults_latest']} ({growth['vaults_change']:+d})")
        fee_sign = "+" if growth["fee_change_wei"] >= 0 else ""
        print(f"   Daily Fee: {fee_sign}{growth['fee_growth_pct']:.1f}% change")
        print(f"   Total Fees (period): {Decimal(growth['total_fees_period_wei']) / WEI_PER_ETH:.4f} ETH")
        print("")

    # Top performers
    rankings = rank_vaults_by_performance(cur_snap, onchain_cur, current.simulated_share_rate)
    if rankings:
        print("🏆 TOP PERFORMING VAULTS")
        print("   " + "-" * 60)
        for r in rankings[:5]:
            from decimal import Decimal

            from vaults_economics.constants import WEI_PER_ETH

            fee_eth = Decimal(r.daily_fee_wei) / WEI_PER_ETH
            print(f"   #{r.rank} {r.vault[:10]}...{r.vault[-6:]}")
            print(
                f"      Score: {r.score:.3f} | Fee: {fee_eth:.6f} ETH/day | Util: {r.utilization * 100:.1f}% | Risk: {r.risk_tier}"
            )
        print("")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
