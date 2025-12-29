"""Console output formatting."""

from datetime import datetime, timezone
from decimal import Decimal

from vaults_economics.constants import CONNECT_DEPOSIT_WEI, TOTAL_BASIS_POINTS
from vaults_economics.formatters import (
    delta_indicator,
    economic_mode,
    format_annual_projection,
    format_bp,
    format_eth,
    format_shares,
    format_wei_sci,
    locked_value_wei,
    shares_to_wei,
    vault_status,
)
from vaults_economics.models import OnchainVaultMetrics, ReportSubmission, VaultAggregates, VaultSnapshot
from vaults_economics.reports import compute_aggregates, fee_delta_wei, zero_snapshot


def print_current_report(
    current: ReportSubmission,
    cur_snap: dict[str, VaultSnapshot],
    onchain: dict[str, OnchainVaultMetrics] | None = None,
    *,
    onchain_block: int | str | None = None,
) -> None:
    """Print current report details."""
    ts = datetime.fromtimestamp(current.block_timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print("=" * 70)
    print("📊 VAULT ECONOMICS REPORT")
    print(f"   🕐 {ts}  •  refSlot={current.ref_slot}")
    print("=" * 70)

    for _, s in sorted(cur_snap.items(), key=lambda kv: kv[1].vault.lower()):
        status_emoji, status_text, action_hint = vault_status(s)
        mode_emoji, mode_text = economic_mode(s)

        print(f"\n{status_emoji} Vault: {s.vault}")
        print(f"   Status: {status_text}  •  Mode: {mode_emoji} {mode_text}")
        print("   " + "─" * 50)

        # Financials
        print(f"   💰 Total Value (reported): {format_eth(s.total_value_wei, decimals=2, approx=True)}")
        print(f"   🔁 Net deposits (inOutDelta, cumulative): {format_eth(s.in_out_delta_wei, decimals=6)}")

        # Fees breakdown
        print("   💸 Lido Fees (cumulative, not unsettled):")
        fee_delta = fee_delta_wei(s)
        print(f"      • Cumulative:         {format_wei_sci(s.cumulative_lido_fees_wei)} wei")
        print(f"      • This report:        {format_wei_sci(fee_delta)} wei")
        print(f"         - Infrastructure:  {format_wei_sci(s.infra_fee_wei)} wei")
        liq_indicator = "🔴" if s.liquidity_fee_wei > 0 else "⚪"
        print(f"         - Liquidity:       {liq_indicator} {format_wei_sci(s.liquidity_fee_wei)} wei")
        if s.reservation_fee_wei:
            print(f"         - Reservation liq: {format_wei_sci(s.reservation_fee_wei)} wei")
        if s.prev_cumulative_lido_fees_wei:
            print(f"      • Prev cumulative:   {format_wei_sci(s.prev_cumulative_lido_fees_wei)} wei")
        # Annual projection (assuming same daily fees)
        print(f"   📅 Projected Annual Revenue (if daily fees continue):")
        print(f"      • Total Lido fees:    {format_annual_projection(fee_delta)}")
        print(f"         - Infrastructure:  {format_annual_projection(s.infra_fee_wei)}")
        print(f"         - Liquidity:       {format_annual_projection(s.liquidity_fee_wei)}")
        if s.reservation_fee_wei:
            print(f"         - Reservation:     {format_annual_projection(s.reservation_fee_wei)}")

        # stETH liability (shares)
        print("   📊 stETH Liability (shares):")
        liab_wei = shares_to_wei(s.liability_shares, current.simulated_share_rate)
        liab_hint = format_eth(liab_wei, decimals=6, approx=True) if current.simulated_share_rate else "n/a"
        print(f"      • Current (refSlot): {format_wei_sci(s.liability_shares)} shares  ({liab_hint})")
        peak_wei = shares_to_wei(s.max_liability_shares, current.simulated_share_rate)
        peak_hint = format_eth(peak_wei, decimals=6, approx=True) if current.simulated_share_rate else "n/a"
        print(f"      • Peak (period):     {format_wei_sci(s.max_liability_shares)} shares  ({peak_hint})")
        if s.max_liability_shares > s.liability_shares:
            below_peak_shares = s.max_liability_shares - s.liability_shares
            below_peak_wei = shares_to_wei(below_peak_shares, current.simulated_share_rate)
            below_peak_hint = (
                format_eth(below_peak_wei, decimals=6, approx=True) if current.simulated_share_rate else "n/a"
            )
            print(f"      • Below peak by:     {format_wei_sci(below_peak_shares)} shares  ({below_peak_hint})")
        print(f"      • Slashing reserve: {format_wei_sci(s.slashing_reserve_wei)} wei (part of Minimal Reserve)")
        minimal_reserve_wei = max(s.slashing_reserve_wei, CONNECT_DEPOSIT_WEI)
        print(f"      • Minimal Reserve:  {format_eth(minimal_reserve_wei, decimals=6)} (max(1 ETH, slashing reserve))")

        onchain_metrics = onchain.get(s.vault.lower()) if onchain is not None else None
        if onchain_metrics is not None:
            block_label = f"{onchain_block}" if onchain_block is not None else "latest"
            print(f"   🧮 On-chain metrics (block {block_label}):")
            onchain_total = onchain_metrics.onchain_total_value_wei
            not_staked = onchain_metrics.aggregated_balance_wei
            staked = max(onchain_total - not_staked, 0)
            print(f"      • Total Value (on-chain): {format_eth(onchain_total, decimals=6)}")
            print(f"      • Not Staked stVault Balance: {format_eth(not_staked, decimals=6)}")
            print(f"      • Staked on validators: {format_eth(staked, decimals=6)}")
            print(f"      • Collateral (locked): {format_eth(onchain_metrics.locked_wei, decimals=6)}")
            total_lock = onchain_metrics.locked_wei + onchain_metrics.unsettled_lido_fees_wei
            print(f"      • Total Lock (collateral + unsettled Lido fees): {format_eth(total_lock, decimals=6)}")
            print(
                f"      • Locked by fees obligations (unsettled Lido fees): {format_eth(onchain_metrics.unsettled_lido_fees_wei, decimals=6)}"
            )
            print(f"      • Available to withdraw: {format_eth(onchain_metrics.withdrawable_wei, decimals=6)}")
            if current.simulated_share_rate > 0:
                max_liability_wei = shares_to_wei(s.max_liability_shares, current.simulated_share_rate)
                reserve_wei = max(onchain_metrics.locked_wei - max_liability_wei, 0)
                print(f"      • Reserve (locked - peak liability): {format_eth(reserve_wei, decimals=6)}")

                share_limit_wei = shares_to_wei(onchain_metrics.share_limit, current.simulated_share_rate)
                liability_wei = shares_to_wei(s.liability_shares, current.simulated_share_rate)
                mintable_wei = onchain_metrics.mintable_steth_wei
                remaining_wei = max(mintable_wei - liability_wei, 0)
                utilization = Decimal(liability_wei) / Decimal(mintable_wei) if mintable_wei > 0 else None
                health_factor = (
                    (Decimal(onchain_total) * (Decimal(TOTAL_BASIS_POINTS - onchain_metrics.forced_rebalance_threshold_bp)
                     / Decimal(TOTAL_BASIS_POINTS)))
                    / Decimal(liability_wei)
                    if liability_wei > 0
                    else None
                )
                locked_current = locked_value_wei(
                    s.liability_shares,
                    minimal_reserve_wei,
                    onchain_metrics.reserve_ratio_bp,
                    current.simulated_share_rate,
                )
                pending_unlock = max(onchain_metrics.locked_wei - locked_current, 0)

                print(f"      • stETH minting limit: {format_eth(share_limit_wei, decimals=6)}")
                print(f"      • Total stETH minting capacity: {format_eth(mintable_wei, decimals=6)}")
                print(f"      • Remaining stETH minting capacity: {format_eth(remaining_wei, decimals=6)}")
                util_text = f"{(utilization * Decimal(100)):.2f}%" if utilization is not None else "n/a"
                print(f"      • Utilization Ratio: {util_text}")
                hf_text = f"{health_factor:.3f}" if health_factor is not None else "n/a"
                print(f"      • Health Factor: {hf_text}")
                print(f"      • Pending unlock (cooldown buffer): {format_eth(pending_unlock, decimals=6)}")
            else:
                print("      • stETH minting limit: n/a (invalid simulatedShareRate)")
                print("      • Total stETH minting capacity: n/a (invalid simulatedShareRate)")
                print("      • Remaining stETH minting capacity: n/a (invalid simulatedShareRate)")
                print("      • Utilization Ratio: n/a (invalid simulatedShareRate)")
                print("      • Health Factor: n/a (invalid simulatedShareRate)")
                print("      • Pending unlock (cooldown buffer): n/a (invalid simulatedShareRate)")

            print(f"      • Reserve Ratio: {format_bp(onchain_metrics.reserve_ratio_bp)}")
            print(f"      • Forced Rebalance Threshold: {format_bp(onchain_metrics.forced_rebalance_threshold_bp)}")
            print(f"      • Healthy: {'Yes' if onchain_metrics.is_healthy else 'No'}")
            if onchain_metrics.pending_disconnect:
                print("      • Pending disconnect: Yes")

        # Action hint
        print(f"\n   💡 {action_hint}")

    print_peak_help()


def print_peak_help() -> None:
    """Print help text about peak liability."""
    print(
        "\nℹ️ Peak (period) = `maxLiabilityShares`: the highest stETH liability (shares) within the current oracle period."
    )
    print(
        "   VaultHub computes on-chain `locked` using this high-water mark, so a vault can be 'Below Peak (cooldown)' after burning shares."
    )


def print_changes_section(
    *,
    title: str,
    current: ReportSubmission,
    cur_snap: dict[str, VaultSnapshot],
    baseline: ReportSubmission,
    base_snap: dict[str, VaultSnapshot],
) -> None:
    """Print changes section comparing current and baseline reports."""
    base_ts = datetime.fromtimestamp(baseline.block_timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    cur_ts = datetime.fromtimestamp(current.block_timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    print("\n" + "=" * 70)
    print(title)
    print(f"   Baseline: {base_ts}  •  refSlot={baseline.ref_slot}")
    print(f"   Current:  {cur_ts}  •  refSlot={current.ref_slot}")
    print("=" * 70)
    print(
        "ℹ️ Vault sets can change over time (🆕 new vault / 🕳️ missing vault). Missing baseline values are treated as 0."
    )

    keys = set(cur_snap.keys()) | set(base_snap.keys())
    if not keys:
        print("\nℹ️ No vaults found in either report.")
        return

    def _vault_sort_key(k: str) -> str:
        s = cur_snap.get(k) or base_snap.get(k)
        return (s.vault if s else k).lower()

    unchanged = 0
    printed = 0

    for key in sorted(keys, key=_vault_sort_key):
        cur = cur_snap.get(key)
        base = base_snap.get(key)

        is_new = base is None and cur is not None
        is_missing = cur is None and base is not None

        if is_new:
            base = zero_snapshot(cur.vault)
        elif is_missing:
            cur = zero_snapshot(base.vault)

        # NOTE: now both exist for printing/diffs
        assert cur is not None  # noqa: S101
        assert base is not None  # noqa: S101

        base_fee_delta = fee_delta_wei(base)
        cur_fee_delta = fee_delta_wei(cur)

        changed = (
            is_new
            or is_missing
            or base.cumulative_lido_fees_wei != cur.cumulative_lido_fees_wei
            or base_fee_delta != cur_fee_delta
            or base.liquidity_fee_wei != cur.liquidity_fee_wei
            or base.liability_shares != cur.liability_shares
            or base.max_liability_shares != cur.max_liability_shares
        )
        if not changed:
            unchanged += 1
            continue

        printed += 1
        mode_emoji, mode_text = economic_mode(cur)
        fee_total_delta = delta_indicator(base.cumulative_lido_fees_wei, cur.cumulative_lido_fees_wei)
        fee_delta = delta_indicator(base_fee_delta, cur_fee_delta)
        liq_delta = delta_indicator(base.liquidity_fee_wei, cur.liquidity_fee_wei)

        print(f"\n🔹 {cur.vault}")
        print("   " + "─" * 50)
        if is_new:
            print("   🆕 New vault (not present in baseline report)")
        elif is_missing:
            print("   🕳️ Missing in current report (present in baseline report)")

        print(
            f"   {fee_total_delta} Lido Fees (cumulative): {format_wei_sci(base.cumulative_lido_fees_wei)} → {format_wei_sci(cur.cumulative_lido_fees_wei)} wei"
        )
        print(
            f"   {fee_delta} Lido Fees (this report): {format_wei_sci(base_fee_delta)} → {format_wei_sci(cur_fee_delta)} wei"
        )
        print(
            f"   {liq_delta} Liquidity fee (this report): {format_wei_sci(base.liquidity_fee_wei)} → {format_wei_sci(cur.liquidity_fee_wei)} wei"
        )

        if base.liability_shares == cur.liability_shares:
            print("   ➡️  stETH Liability (shares): Unchanged")
        else:
            liab_delta = delta_indicator(base.liability_shares, cur.liability_shares)
            print(
                f"   {liab_delta} stETH Liability (shares): {format_shares(base.liability_shares)} → {format_shares(cur.liability_shares)}"
            )

        if base.max_liability_shares == cur.max_liability_shares:
            print("   ➡️  Peak stETH liability (shares): Unchanged")
        else:
            peak_delta = delta_indicator(base.max_liability_shares, cur.max_liability_shares)
            print(
                f"   {peak_delta} Peak stETH liability (shares): {format_shares(base.max_liability_shares)} → {format_shares(cur.max_liability_shares)}"
            )

        print(f"   {mode_emoji} Mode:           {mode_text}")

    if printed == 0:
        print("\nℹ️ No changes detected in the tracked metrics.")
    elif unchanged > 0:
        print(f"\nℹ️ {unchanged} vault(s) unchanged in the tracked metrics (omitted).")


def print_aggregates_section(
    *,
    current: ReportSubmission,
    cur_snap: dict[str, VaultSnapshot],
    prev: tuple[ReportSubmission, dict[str, VaultSnapshot]] | None,
    first: tuple[ReportSubmission, dict[str, VaultSnapshot]] | None,
    onchain_cur: dict[str, OnchainVaultMetrics] | None = None,
    onchain_block: int | str | None = None,
) -> None:
    """Print aggregates section."""
    cur_agg = compute_aggregates(cur_snap)
    cur_ts = datetime.fromtimestamp(current.block_timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    print("\n" + "=" * 70)
    print("🧾 stVaults AGGREGATES (all vaults)")
    print(f"   🕐 {cur_ts}  •  refSlot={current.ref_slot}")
    print("=" * 70)

    print(
        f"🏦 Vaults: {cur_agg.vaults_total} total  •  {cur_agg.vaults_active} active  •  {cur_agg.vaults_passive} passive  •  {cur_agg.vaults_slashing_reserve} slashing-reserve"
    )
    print(
        f"🎚️ Modes:  {cur_agg.mode_at_peak} at-peak(locked)  •  {cur_agg.mode_below_peak} below-peak(cooldown)  •  {cur_agg.mode_unlevered} unlevered"
    )
    print(f"💰 Total Value (reported): {format_eth(cur_agg.total_value_wei, decimals=2, approx=True)}")
    print(f"🔁 Net deposits (inOutDelta, cumulative): {format_eth(cur_agg.in_out_delta_wei, decimals=6)}")

    print("💸 Lido Fees (cumulative, not unsettled):")
    print(f"   • Cumulative:     {format_wei_sci(cur_agg.cumulative_lido_fees_wei)} wei")
    print(f"   • This report:    {format_wei_sci(cur_agg.lido_fees_this_report_wei)} wei")
    print(f"      - Infrastructure:  {format_wei_sci(cur_agg.infra_fee_wei)} wei")
    print(f"      - Liquidity:       {format_wei_sci(cur_agg.liquidity_fee_wei)} wei")
    if cur_agg.reservation_fee_wei:
        print(f"      - Reservation liq: {format_wei_sci(cur_agg.reservation_fee_wei)} wei")

    # Annual projection for all vaults combined
    print("📅 Projected Annual Revenue (all vaults, if daily fees continue):")
    print(f"   • Total Lido fees:    {format_annual_projection(cur_agg.lido_fees_this_report_wei)}")
    print(f"      - Infrastructure:  {format_annual_projection(cur_agg.infra_fee_wei)}")
    print(f"      - Liquidity:       {format_annual_projection(cur_agg.liquidity_fee_wei)}")
    if cur_agg.reservation_fee_wei:
        print(f"      - Reservation:     {format_annual_projection(cur_agg.reservation_fee_wei)}")

    print("📊 stETH Liability (shares):")
    liab_wei = shares_to_wei(cur_agg.liability_shares, current.simulated_share_rate)
    liab_hint = format_eth(liab_wei, decimals=6, approx=True) if current.simulated_share_rate else "n/a"
    print(f"   • Current (refSlot): {format_wei_sci(cur_agg.liability_shares)} shares  ({liab_hint})")
    peak_wei = shares_to_wei(cur_agg.max_liability_shares, current.simulated_share_rate)
    peak_hint = format_eth(peak_wei, decimals=6, approx=True) if current.simulated_share_rate else "n/a"
    print(f"   • Peak (period):     {format_wei_sci(cur_agg.max_liability_shares)} shares  ({peak_hint})")
    print(f"🛡️ Slashing reserve (total): {format_wei_sci(cur_agg.slashing_reserve_wei)} wei (part of Minimal Reserve)")
    minimal_reserve_total = sum(max(s.slashing_reserve_wei, CONNECT_DEPOSIT_WEI) for s in cur_snap.values())
    print(f"🧱 Minimal Reserve (sum): {format_eth(minimal_reserve_total, decimals=6)} (sum of max(1 ETH, slashing reserve))")
    if onchain_cur:
        block_label = f"{onchain_block}" if onchain_block is not None else "latest"
        onchain_total = sum(m.onchain_total_value_wei for m in onchain_cur.values())
        not_staked_total = sum(m.aggregated_balance_wei for m in onchain_cur.values())
        staked_total = max(onchain_total - not_staked_total, 0)
        locked_total = sum(m.locked_wei for m in onchain_cur.values())
        unsettled_total = sum(m.unsettled_lido_fees_wei for m in onchain_cur.values())
        withdrawable_total = sum(m.withdrawable_wei for m in onchain_cur.values())
        mintable_total = sum(m.mintable_steth_wei for m in onchain_cur.values())
        liability_total_wei = shares_to_wei(cur_agg.liability_shares, current.simulated_share_rate)
        remaining_total = max(mintable_total - liability_total_wei, 0)
        utilization_total = (
            Decimal(liability_total_wei) / Decimal(mintable_total) if mintable_total > 0 else None
        )

        print(f"\n🧮 On-chain aggregates (block {block_label}):")
        print(f"   • Total Value (on-chain): {format_eth(onchain_total, decimals=6)}")
        print(f"   • Not Staked stVault Balance: {format_eth(not_staked_total, decimals=6)}")
        print(f"   • Staked on validators: {format_eth(staked_total, decimals=6)}")
        print(f"   • Collateral (locked): {format_eth(locked_total, decimals=6)}")
        print(f"   • Unsettled Lido fees: {format_eth(unsettled_total, decimals=6)}")
        print(f"   • Total Lock (collateral + unsettled Lido fees): {format_eth(locked_total + unsettled_total, decimals=6)}")
        print(f"   • Available to withdraw: {format_eth(withdrawable_total, decimals=6)}")
        if current.simulated_share_rate > 0:
            print(f"   • Total stETH minting capacity: {format_eth(mintable_total, decimals=6)}")
            print(f"   • Remaining stETH minting capacity: {format_eth(remaining_total, decimals=6)}")
            util_text = f"{(utilization_total * Decimal(100)):.2f}%" if utilization_total is not None else "n/a"
            print(f"   • Utilization Ratio: {util_text}")

    def _print_agg_delta(label: str, base_sub: ReportSubmission, base_snap: dict[str, VaultSnapshot]) -> None:
        base_agg = compute_aggregates(base_snap)
        print(f"\n📈 Aggregates change {label}:")
        print(
            f"   💰 Total Value (reported): {format_eth(base_agg.total_value_wei, decimals=2, approx=True)} → {format_eth(cur_agg.total_value_wei, decimals=2, approx=True)}"
        )
        print(
            f"   🔁 Net deposits (inOutDelta): {format_eth(base_agg.in_out_delta_wei, decimals=6)} → {format_eth(cur_agg.in_out_delta_wei, decimals=6)}"
        )
        print(
            f"   💸 Lido Fees (cumulative): {format_wei_sci(base_agg.cumulative_lido_fees_wei)} → {format_wei_sci(cur_agg.cumulative_lido_fees_wei)} wei"
        )
        print(
            f"   📊 stETH Liability (shares): {format_shares(base_agg.liability_shares)} → {format_shares(cur_agg.liability_shares)}"
        )

    if prev is not None:
        _print_agg_delta("since last report", prev[0], prev[1])
    if first is not None:
        _print_agg_delta("since first report", first[0], first[1])


def print_report_with_deltas(
    submissions: list[ReportSubmission],
    snapshots: list[dict[str, VaultSnapshot]],
    onchain_metrics: list[dict[str, OnchainVaultMetrics]] | None = None,
    onchain_blocks: list[int | str] | None = None,
) -> None:
    """Print report with deltas."""
    current = submissions[0]
    cur_snap = snapshots[0]
    cur_onchain = onchain_metrics[0] if onchain_metrics else None
    cur_block = onchain_blocks[0] if onchain_blocks else None
    prev = (submissions[1], snapshots[1]) if len(submissions) > 1 else None
    first = (submissions[-1], snapshots[-1]) if len(submissions) > 1 else None

    print_current_report(current, cur_snap, cur_onchain, onchain_block=cur_block)

    if prev is not None:
        print_changes_section(
            title="📈 CHANGES SINCE LAST REPORT",
            current=current,
            cur_snap=cur_snap,
            baseline=prev[0],
            base_snap=prev[1],
        )

    if first is not None:
        # Avoid duplicating the previous-report comparison when only 2 reports are available.
        if len(submissions) > 2:
            print_changes_section(
                title="📈 CHANGES SINCE FIRST REPORT",
                current=current,
                cur_snap=cur_snap,
                baseline=first[0],
                base_snap=first[1],
            )
        elif prev is not None:
            print("\n" + "=" * 70)
            print("📈 CHANGES SINCE FIRST REPORT")
            print(
                "   ℹ️ Only 2 reports available — first report equals previous report; see 'CHANGES SINCE LAST REPORT' above."
            )
            print("=" * 70)

    print_aggregates_section(
        current=current,
        cur_snap=cur_snap,
        prev=prev,
        first=first if len(submissions) > 2 else None,
        onchain_cur=cur_onchain,
        onchain_block=cur_block,
    )

