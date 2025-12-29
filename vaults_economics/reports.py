"""Report collection and aggregation."""

from vaults_economics.models import VaultAggregates, VaultSnapshot


def fee_delta_wei(s: VaultSnapshot) -> int:
    """Calculate fee delta (fees accrued this report period)."""
    return s.infra_fee_wei + s.liquidity_fee_wei + s.reservation_fee_wei


def zero_snapshot(vault: str) -> VaultSnapshot:
    """Create a zero-initialized VaultSnapshot."""
    return VaultSnapshot(
        vault=vault,
        total_value_wei=0,
        in_out_delta_wei=0,
        cumulative_lido_fees_wei=0,
        prev_cumulative_lido_fees_wei=0,
        infra_fee_wei=0,
        liquidity_fee_wei=0,
        reservation_fee_wei=0,
        liability_shares=0,
        max_liability_shares=0,
        slashing_reserve_wei=0,
    )


def compute_aggregates(snap: dict[str, VaultSnapshot]) -> VaultAggregates:
    """Compute aggregated metrics across all vaults."""
    vaults_total = len(snap)
    vaults_active = 0
    vaults_passive = 0
    vaults_slashing_reserve = 0

    mode_unlevered = 0
    mode_below_peak = 0
    mode_at_peak = 0

    total_value_wei = 0
    in_out_delta_wei = 0
    cumulative_lido_fees_wei = 0
    lido_fees_this_report_wei = 0
    infra_fee_wei = 0
    liquidity_fee_wei = 0
    reservation_fee_wei = 0
    liability_shares = 0
    max_liability_shares = 0
    slashing_reserve_wei = 0

    for s in snap.values():
        total_value_wei += int(s.total_value_wei)
        in_out_delta_wei += int(s.in_out_delta_wei)
        cumulative_lido_fees_wei += int(s.cumulative_lido_fees_wei)
        infra_fee_wei += int(s.infra_fee_wei)
        liquidity_fee_wei += int(s.liquidity_fee_wei)
        reservation_fee_wei += int(s.reservation_fee_wei)
        lido_fees_this_report_wei += fee_delta_wei(s)
        liability_shares += int(s.liability_shares)
        max_liability_shares += int(s.max_liability_shares)
        slashing_reserve_wei += int(s.slashing_reserve_wei)

        if s.slashing_reserve_wei > 0:
            vaults_slashing_reserve += 1
        elif s.liability_shares == 0:
            vaults_passive += 1
        else:
            vaults_active += 1

        if s.liability_shares == 0:
            mode_unlevered += 1
        elif s.max_liability_shares > s.liability_shares:
            mode_below_peak += 1
        else:
            mode_at_peak += 1

    return VaultAggregates(
        vaults_total=vaults_total,
        vaults_active=vaults_active,
        vaults_passive=vaults_passive,
        vaults_slashing_reserve=vaults_slashing_reserve,
        mode_unlevered=mode_unlevered,
        mode_below_peak=mode_below_peak,
        mode_at_peak=mode_at_peak,
        total_value_wei=total_value_wei,
        in_out_delta_wei=in_out_delta_wei,
        cumulative_lido_fees_wei=cumulative_lido_fees_wei,
        lido_fees_this_report_wei=lido_fees_this_report_wei,
        infra_fee_wei=infra_fee_wei,
        liquidity_fee_wei=liquidity_fee_wei,
        reservation_fee_wei=reservation_fee_wei,
        liability_shares=liability_shares,
        max_liability_shares=max_liability_shares,
        slashing_reserve_wei=slashing_reserve_wei,
    )
