"""CLI and main logic."""

import argparse
import os
import sys
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Iterable

from tqdm import tqdm

from vaults_economics.blockchain import collect_recent_report_submissions
from vaults_economics.cache import clear_cache
from vaults_economics.console import print_report_with_deltas
from vaults_economics.analytics import (
    calculate_protocol_analytics,
    calculate_growth_metrics,
    rank_vaults_by_performance,
    format_analytics_summary,
)
from vaults_economics.constants import (
    ACCOUNTING_ORACLE_MIN_ABI,
    DEFAULT_BLOCKS_PER_DAY,
    DEFAULT_IPFS_GATEWAYS,
    DEFAULT_PUBLIC_ETH_RPC_URLS,
    LAZY_ORACLE_MIN_ABI,
    LIDO_LOCATOR_MAINNET,
    VAULT_HUB_MIN_ABI,
)
from vaults_economics.contracts import resolve_lido_contracts
from vaults_economics.html_report import generate_html_report, serve_html_and_open_browser
from vaults_economics.ipfs import fetch_ipfs_bytes
from vaults_economics.models import OnchainVaultMetrics, VaultSnapshot
from vaults_economics.onchain import collect_onchain_metrics
from vaults_economics.parsing import parse_ipfs_report, parse_report_to_snapshots
from vaults_economics.validation import validate_cross_report_consistency, validate_ipfs_report_metadata

if TYPE_CHECKING:
    from web3 import Web3  # pragma: no cover


def unique_nonempty(values: Iterable[str | None]) -> list[str]:
    """Filter out empty values and duplicates."""
    out: list[str] = []
    seen: set[str] = set()
    for v in values:
        if not v:
            continue
        if v in seen:
            continue
        seen.add(v)
        out.append(v)
    return out


def default_rpc_urls(env_rpc_url: str | None) -> list[str]:
    """Default RPC URL candidates when user did not explicitly provide --rpc-url."""
    return unique_nonempty([env_rpc_url, *DEFAULT_PUBLIC_ETH_RPC_URLS])


def resolve_onchain_block(value: str, report_block: int) -> int | str:
    """Resolve onchain block identifier from string."""
    mode = str(value).strip().lower()
    if mode == "latest":
        return "latest"
    if mode == "report":
        return int(report_block)
    return int(mode, 0)


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse command-line arguments."""
    p = argparse.ArgumentParser(description="Standalone vault economics analysis from Lido AccountingOracle reports.")
    p.add_argument(
        "--rpc-url",
        default=None,
        help="Execution-layer RPC URL. Defaults to ETH_RPC_URL if set, otherwise tries a small list of public RPCs.",
    )
    p.add_argument(
        "--locator",
        default=LIDO_LOCATOR_MAINNET,
        help="LidoLocator address (resolves all other contract addresses). Default: mainnet locator.",
    )
    p.add_argument("--no-onchain", action="store_true", help="Skip on-chain metrics (LazyOracle/VaultHub).")
    p.add_argument(
        "--onchain-block",
        default="report",
        help="On-chain read block: 'report' (default), 'latest', or a specific block number.",
    )
    p.add_argument(
        "--vaults-page-size",
        type=int,
        default=200,
        help="Page size for LazyOracle.batchVaultsInfo (default: 200).",
    )
    p.add_argument(
        "--reports",
        type=int,
        default=None,
        help="How many latest reports to analyze. If not specified, retrieves all reports in the scanned range.",
    )
    p.add_argument("--days", type=int, default=14, help="How many days back to scan for reports (default: 14).")
    p.add_argument(
        "--blocks-per-day", type=int, default=DEFAULT_BLOCKS_PER_DAY, help="Approx blocks/day (default: 7200)."
    )
    p.add_argument(
        "--log-chunk-size", type=int, default=1_000, help="Block chunk size for eth_getLogs (default: 1000)."
    )
    p.add_argument("--timeout", type=int, default=30, help="HTTP timeout seconds (RPC/IPFS).")
    p.add_argument(
        "--html",
        action="store_true",
        help="Generate an HTML report and serve it locally, opening the default browser.",
    )
    p.add_argument(
        "--html-port",
        type=int,
        default=0,
        help="Port for the HTML server (default: auto-select available port).",
    )
    p.add_argument(
        "--analytics",
        action="store_true",
        help="Show strategic analytics summary (revenue, efficiency, risk metrics, vault rankings).",
    )
    p.add_argument(
        "--clear-cache",
        action="store_true",
        help="Clear all cached data (onchain logs, IPFS content, transactions, blocks, metrics) and exit. "
        "Cache is stored in ~/.cache/.vaults_economics_cache/ (or XDG_CACHE_HOME if set).",
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

    # Handle --clear-cache flag
    if args.clear_cache:
        clear_cache()
        return 0

    use_cache = not args.no_cache

    try:
        from web3 import Web3  # type: ignore[import-not-found]
    except ImportError as ex:  # pragma: no cover
        print("Missing dependency. Run: uv sync", file=sys.stderr)
        raise SystemExit(2) from ex

    rpc_candidates = [args.rpc_url] if args.rpc_url else default_rpc_urls(os.getenv("ETH_RPC_URL"))
    w3: "Web3" | None = None
    rpc_url: str | None = None
    for candidate in rpc_candidates:
        probe = Web3(Web3.HTTPProvider(candidate, request_kwargs={"timeout": args.timeout}))
        if probe.is_connected():
            w3 = probe
            rpc_url = candidate
            break

    if w3 is None or rpc_url is None:
        hint = "Provide --rpc-url or set ETH_RPC_URL."
        if not args.rpc_url and not os.getenv("ETH_RPC_URL"):
            hint = f"{hint} Tried defaults: {', '.join(DEFAULT_PUBLIC_ETH_RPC_URLS)}"
        print(f"Error: failed to connect to an RPC. {hint}", file=sys.stderr)
        return 2

    if not args.rpc_url and rpc_url in DEFAULT_PUBLIC_ETH_RPC_URLS:
        print(f"ℹ️ Using default public RPC: {rpc_url}", file=sys.stderr)

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

    lazy_oracle_contract = None
    vault_hub_contract = None
    if not args.no_onchain:
        try:
            lazy_oracle_addr = Web3.to_checksum_address(contracts.lazy_oracle)
            vault_hub_addr = Web3.to_checksum_address(contracts.vault_hub)
            lazy_oracle_contract = w3.eth.contract(address=lazy_oracle_addr, abi=LAZY_ORACLE_MIN_ABI)
            vault_hub_contract = w3.eth.contract(address=vault_hub_addr, abi=VAULT_HUB_MIN_ABI)
        except Exception as ex:  # pylint: disable=broad-exception-caught
            print(f"⚠️  On-chain metrics disabled (invalid addresses): {ex}", file=sys.stderr)
            lazy_oracle_contract = None
            vault_hub_contract = None

    gateways = DEFAULT_IPFS_GATEWAYS

    # Scan blockchain logs for report submissions.
    submissions = collect_recent_report_submissions(
        w3,
        accounting_contract,
        oracle_addr,
        want_reports=max(1, int(args.reports)) if args.reports is not None else None,
        days=max(1, int(args.days)),
        blocks_per_day=max(1, int(args.blocks_per_day)),
        log_chunk_size=max(100, int(args.log_chunk_size)),
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
            raw = fetch_ipfs_bytes(sub.vaults_tree_cid, gateways, timeout_s=args.timeout, use_cache=use_cache)
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

    onchain_metrics_list: list[dict[str, OnchainVaultMetrics]] | None = None
    onchain_blocks: list[int | str] | None = None
    if lazy_oracle_contract is not None and vault_hub_contract is not None:
        onchain_metrics_list = []
        onchain_blocks = []
        with tqdm(
            zip(submissions, snapshots),
            total=len(submissions),
            desc="🔗 Fetching on-chain metrics",
            unit="report",
            file=sys.stderr,
        ) as pbar:
            for sub, snap in pbar:
                pbar.set_postfix(refSlot=sub.ref_slot, vaults=len(snap))
                block_id = resolve_onchain_block(args.onchain_block, sub.block_number)
                try:
                    metrics = collect_onchain_metrics(
                        w3,
                        lazy_oracle_contract,
                        vault_hub_contract,
                        snap.keys(),
                        block_identifier=block_id,
                        page_size=max(1, int(args.vaults_page_size)),
                        use_cache=use_cache,
                    )
                except Exception as ex:  # pylint: disable=broad-exception-caught
                    if block_id != "latest":
                        tqdm.write(
                            f"⚠️  On-chain metrics failed at block {block_id}, falling back to latest: {ex}",
                            file=sys.stderr,
                        )
                        block_id = "latest"
                        metrics = collect_onchain_metrics(
                            w3,
                            lazy_oracle_contract,
                            vault_hub_contract,
                            snap.keys(),
                            block_identifier=block_id,
                            page_size=max(1, int(args.vaults_page_size)),
                            use_cache=use_cache,
                        )
                    else:
                        tqdm.write(f"⚠️  On-chain metrics failed: {ex}", file=sys.stderr)
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
        html_content = generate_html_report(submissions, snapshots, onchain_metrics_list, onchain_blocks)
        serve_html_and_open_browser(html_content, port=args.html_port)
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

    # Strategic analytics
    if args.analytics:
        current = submissions[0]
        cur_snap = snapshots[0]
        onchain_cur = onchain_metrics_list[0] if onchain_metrics_list else None

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
            print(f"   TVL: {Decimal(growth['tvl_first_wei']) / WEI_PER_ETH:.2f} → {Decimal(growth['tvl_latest_wei']) / WEI_PER_ETH:.2f} ETH ({tvl_change_sign}{growth['tvl_growth_pct']:.1f}%)")
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
                print(f"      Score: {r.score:.3f} | Fee: {fee_eth:.6f} ETH/day | Util: {r.utilization*100:.1f}% | Risk: {r.risk_tier}")
            print("")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
