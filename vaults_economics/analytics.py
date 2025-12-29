"""Analytics for stVaults economics.

This module provides metrics and analysis for scaling stVaults development:
- Growth & Adoption metrics
- Revenue & Fee analysis
- Capital Efficiency metrics
- Risk assessment
- Vault performance ranking
"""

from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from vaults_economics.constants import DAYS_PER_YEAR, TOTAL_BASIS_POINTS, WEI_PER_ETH
from vaults_economics.formatters import shares_to_wei
from vaults_economics.models import OnchainVaultMetrics, ReportSubmission, VaultSnapshot
from vaults_economics.reports import compute_aggregates, fee_delta_wei


@dataclass(frozen=True)
class VaultPerformanceMetrics:
    """Performance metrics for a single vault."""

    vault: str
    # Revenue metrics
    daily_fee_wei: int
    annual_fee_projection_wei: int
    fee_yield_bps: int  # Annual fee as basis points of total value
    infra_fee_ratio: float  # Infrastructure fee as % of total fee
    liquidity_fee_ratio: float  # Liquidity fee as % of total fee
    # Capital efficiency
    utilization_ratio: float  # liability / mintable capacity
    collateralization_ratio: float  # total value / liability
    locked_ratio: float  # locked / total value
    # Risk metrics
    health_factor: float | None
    distance_to_rebalance_bps: int  # How far from forced rebalance threshold
    is_at_peak: bool
    # Classification
    risk_tier: str  # "low", "medium", "high"
    efficiency_tier: str  # "high", "medium", "low"


@dataclass(frozen=True)
class ProtocolAnalytics:
    """Protocol-wide analytics for stVaults."""

    # Adoption metrics
    total_vaults: int
    active_vaults: int
    passive_vaults: int
    at_peak_vaults: int
    below_peak_vaults: int
    # TVL metrics
    total_value_wei: int
    total_liability_wei: int
    total_locked_wei: int
    total_withdrawable_wei: int
    # Revenue metrics
    daily_revenue_wei: int
    annual_revenue_projection_wei: int
    avg_fee_per_active_vault_wei: int
    median_fee_per_vault_wei: int
    revenue_concentration_top3: float  # % of revenue from top 3 vaults
    # Capital efficiency
    protocol_utilization: float  # total liability / total mintable
    avg_collateralization: float
    capital_locked_ratio: float  # locked / total value
    # Risk metrics
    vaults_near_rebalance: int  # Within 500 bps of forced rebalance
    avg_health_factor: float | None
    high_risk_vault_count: int
    # Growth indicators
    net_deposits_wei: int
    cumulative_fees_wei: int


@dataclass(frozen=True)
class VaultRanking:
    """Ranked vault for comparative analysis."""

    vault: str
    rank: int
    score: float
    daily_fee_wei: int
    utilization: float
    health_factor: float | None
    risk_tier: str


def calculate_vault_performance(
    s: VaultSnapshot,
    onchain: OnchainVaultMetrics | None,
    simulated_share_rate: int,
) -> VaultPerformanceMetrics:
    """Calculate performance metrics for a single vault."""
    daily_fee = fee_delta_wei(s)
    annual_fee = daily_fee * DAYS_PER_YEAR

    # Fee yield (annual fee / total value in bps)
    fee_yield_bps = 0
    if s.total_value_wei > 0:
        fee_yield_bps = int((annual_fee * TOTAL_BASIS_POINTS) // s.total_value_wei)

    # Fee composition
    total_fee = daily_fee if daily_fee > 0 else 1  # Avoid division by zero
    infra_ratio = s.infra_fee_wei / total_fee if daily_fee > 0 else 0.0
    liquidity_ratio = s.liquidity_fee_wei / total_fee if daily_fee > 0 else 0.0

    # Capital efficiency
    liability_wei = shares_to_wei(s.liability_shares, simulated_share_rate)
    mintable_wei = onchain.mintable_steth_wei if onchain else 0
    utilization = liability_wei / mintable_wei if mintable_wei > 0 else 0.0

    collateralization = s.total_value_wei / liability_wei if liability_wei > 0 else float("inf")

    locked_wei = onchain.locked_wei if onchain else 0
    locked_ratio = locked_wei / s.total_value_wei if s.total_value_wei > 0 else 0.0

    # Risk metrics
    health_factor = None
    distance_to_rebalance = 0
    if onchain and liability_wei > 0:
        # Health factor = (total_value * (1 - forced_threshold)) / liability
        threshold_factor = (TOTAL_BASIS_POINTS - onchain.forced_rebalance_threshold_bp) / TOTAL_BASIS_POINTS
        health_factor = float((onchain.onchain_total_value_wei * threshold_factor) / liability_wei)

        # Distance to rebalance in bps
        current_ratio = int((onchain.onchain_total_value_wei * TOTAL_BASIS_POINTS) // liability_wei)
        distance_to_rebalance = current_ratio - onchain.forced_rebalance_threshold_bp

    is_at_peak = s.liability_shares > 0 and s.liability_shares == s.max_liability_shares

    # Risk tier classification
    if health_factor is None or s.liability_shares == 0:
        risk_tier = "low"
    elif health_factor < 1.1:
        risk_tier = "high"
    elif health_factor < 1.3:
        risk_tier = "medium"
    else:
        risk_tier = "low"

    # Efficiency tier classification
    if utilization > 0.7:
        efficiency_tier = "high"
    elif utilization > 0.3:
        efficiency_tier = "medium"
    else:
        efficiency_tier = "low"

    return VaultPerformanceMetrics(
        vault=s.vault,
        daily_fee_wei=daily_fee,
        annual_fee_projection_wei=annual_fee,
        fee_yield_bps=fee_yield_bps,
        infra_fee_ratio=infra_ratio,
        liquidity_fee_ratio=liquidity_ratio,
        utilization_ratio=utilization,
        collateralization_ratio=collateralization,
        locked_ratio=locked_ratio,
        health_factor=health_factor,
        distance_to_rebalance_bps=distance_to_rebalance,
        is_at_peak=is_at_peak,
        risk_tier=risk_tier,
        efficiency_tier=efficiency_tier,
    )


def calculate_protocol_analytics(
    snapshots: dict[str, VaultSnapshot],
    onchain_metrics: dict[str, OnchainVaultMetrics] | None,
    simulated_share_rate: int,
) -> ProtocolAnalytics:
    """Calculate protocol-wide analytics."""
    agg = compute_aggregates(snapshots)

    # Calculate per-vault fees for distribution analysis
    vault_fees: list[int] = []
    for s in snapshots.values():
        vault_fees.append(fee_delta_wei(s))
    vault_fees.sort(reverse=True)

    # Revenue concentration (top 3 vaults)
    total_fees = sum(vault_fees)
    top3_fees = sum(vault_fees[:3]) if len(vault_fees) >= 3 else total_fees
    revenue_concentration = top3_fees / total_fees if total_fees > 0 else 0.0

    # Median fee
    median_fee = 0
    if vault_fees:
        mid = len(vault_fees) // 2
        median_fee = vault_fees[mid] if len(vault_fees) % 2 else (vault_fees[mid - 1] + vault_fees[mid]) // 2

    # Average fee per active vault
    active_count = sum(1 for s in snapshots.values() if s.liability_shares > 0)
    avg_fee = total_fees // active_count if active_count > 0 else 0

    # On-chain aggregates
    total_locked = 0
    total_withdrawable = 0
    total_mintable = 0
    total_liability_for_utilization = 0
    health_factors: list[float] = []
    vaults_near_rebalance = 0
    high_risk_count = 0

    if onchain_metrics:
        for key, s in snapshots.items():
            om = onchain_metrics.get(key)
            if om:
                total_locked += om.locked_wei
                total_withdrawable += om.withdrawable_wei
                total_mintable += om.mintable_steth_wei
                # Compute utilization over the same vault set as the minting capacity sum
                total_liability_for_utilization += shares_to_wei(s.liability_shares, simulated_share_rate)

                liability_wei = shares_to_wei(s.liability_shares, simulated_share_rate)
                if liability_wei > 0:
                    threshold_factor = (TOTAL_BASIS_POINTS - om.forced_rebalance_threshold_bp) / TOTAL_BASIS_POINTS
                    hf = float((om.onchain_total_value_wei * threshold_factor) / liability_wei)
                    health_factors.append(hf)

                    if hf < 1.1:
                        high_risk_count += 1

                    # Check if within 500 bps of forced rebalance
                    current_ratio = int((om.onchain_total_value_wei * TOTAL_BASIS_POINTS) // liability_wei)
                    if current_ratio - om.forced_rebalance_threshold_bp < 500:
                        vaults_near_rebalance += 1

    # Protocol utilization
    total_liability = shares_to_wei(agg.liability_shares, simulated_share_rate)
    protocol_utilization = total_liability_for_utilization / total_mintable if total_mintable > 0 else 0.0

    # Average health factor
    avg_hf = sum(health_factors) / len(health_factors) if health_factors else None

    # Average collateralization
    avg_collat = agg.total_value_wei / total_liability if total_liability > 0 else 0.0

    # Capital locked ratio
    capital_locked = total_locked / agg.total_value_wei if agg.total_value_wei > 0 else 0.0

    return ProtocolAnalytics(
        total_vaults=agg.vaults_total,
        active_vaults=agg.vaults_active,
        passive_vaults=agg.vaults_passive,
        at_peak_vaults=agg.mode_at_peak,
        below_peak_vaults=agg.mode_below_peak,
        total_value_wei=agg.total_value_wei,
        total_liability_wei=total_liability,
        total_locked_wei=total_locked,
        total_withdrawable_wei=total_withdrawable,
        daily_revenue_wei=agg.lido_fees_this_report_wei,
        annual_revenue_projection_wei=agg.lido_fees_this_report_wei * DAYS_PER_YEAR,
        avg_fee_per_active_vault_wei=avg_fee,
        median_fee_per_vault_wei=median_fee,
        revenue_concentration_top3=revenue_concentration,
        protocol_utilization=protocol_utilization,
        avg_collateralization=avg_collat,
        capital_locked_ratio=capital_locked,
        vaults_near_rebalance=vaults_near_rebalance,
        avg_health_factor=avg_hf,
        high_risk_vault_count=high_risk_count,
        net_deposits_wei=agg.in_out_delta_wei,
        cumulative_fees_wei=agg.cumulative_lido_fees_wei,
    )


def rank_vaults_by_performance(
    snapshots: dict[str, VaultSnapshot],
    onchain_metrics: dict[str, OnchainVaultMetrics] | None,
    simulated_share_rate: int,
) -> list[VaultRanking]:
    """Rank vaults by a composite performance score.

    Score components:
    - Revenue contribution (40%)
    - Capital efficiency / utilization (30%)
    - Health factor / risk (30%)
    """
    vault_scores: list[tuple[str, float, VaultPerformanceMetrics]] = []

    # Calculate metrics for all vaults
    for key, s in snapshots.items():
        om = onchain_metrics.get(key) if onchain_metrics else None
        perf = calculate_vault_performance(s, om, simulated_share_rate)

        # Only rank active vaults
        if s.liability_shares == 0:
            continue

        # Normalize components (0-1 scale)
        # Revenue: log scale to handle large differences
        import math

        revenue_score = math.log1p(perf.daily_fee_wei) / 50  # Normalize to ~0-1
        revenue_score = min(1.0, revenue_score)

        # Utilization: direct (higher is better for Lido)
        util_score = min(1.0, perf.utilization_ratio)

        # Health: inverse (higher health = lower risk = better)
        if perf.health_factor is not None:
            health_score = min(1.0, (perf.health_factor - 1.0) / 0.5)  # 1.0-1.5 maps to 0-1
            health_score = max(0.0, health_score)
        else:
            health_score = 0.5  # Default for vaults without health data

        # Composite score
        score = (0.4 * revenue_score) + (0.3 * util_score) + (0.3 * health_score)
        vault_scores.append((key, score, perf))

    # Sort by score descending
    vault_scores.sort(key=lambda x: x[1], reverse=True)

    # Build rankings
    rankings: list[VaultRanking] = []
    for rank, (key, score, perf) in enumerate(vault_scores, start=1):
        rankings.append(
            VaultRanking(
                vault=perf.vault,
                rank=rank,
                score=score,
                daily_fee_wei=perf.daily_fee_wei,
                utilization=perf.utilization_ratio,
                health_factor=perf.health_factor,
                risk_tier=perf.risk_tier,
            )
        )

    return rankings


def calculate_growth_metrics(
    submissions: list[ReportSubmission],
    snapshots: list[dict[str, VaultSnapshot]],
) -> dict[str, Any]:
    """Calculate growth metrics across multiple reports.

    Returns trends and changes over the report period.
    """
    if len(submissions) < 2:
        return {
            "has_trend_data": False,
            "message": "Need at least 2 reports for trend analysis",
        }

    first_sub = submissions[-1]
    first_snap = snapshots[-1]
    first_agg = compute_aggregates(first_snap)

    latest_sub = submissions[0]
    latest_snap = snapshots[0]
    latest_agg = compute_aggregates(latest_snap)

    # Calculate period (in days)
    period_seconds = latest_sub.block_timestamp - first_sub.block_timestamp
    period_days = max(1, period_seconds // 86400)

    # TVL growth
    tvl_change = latest_agg.total_value_wei - first_agg.total_value_wei
    tvl_growth_pct = (tvl_change * 100) / first_agg.total_value_wei if first_agg.total_value_wei > 0 else 0

    # Vault count change
    vault_count_change = latest_agg.vaults_total - first_agg.vaults_total

    # Active vault change
    active_change = latest_agg.vaults_active - first_agg.vaults_active

    # Fee growth
    fee_change = latest_agg.lido_fees_this_report_wei - first_agg.lido_fees_this_report_wei
    fee_growth_pct = (
        (fee_change * 100) / first_agg.lido_fees_this_report_wei if first_agg.lido_fees_this_report_wei > 0 else 0
    )

    # Liability growth
    liability_change = latest_agg.liability_shares - first_agg.liability_shares
    liability_growth_pct = (
        (liability_change * 100) / first_agg.liability_shares if first_agg.liability_shares > 0 else 0
    )

    # Cumulative fees over period
    total_fees_period = sum(compute_aggregates(snap).lido_fees_this_report_wei for snap in snapshots)

    return {
        "has_trend_data": True,
        "period_days": period_days,
        "reports_count": len(submissions),
        # TVL
        "tvl_first_wei": first_agg.total_value_wei,
        "tvl_latest_wei": latest_agg.total_value_wei,
        "tvl_change_wei": tvl_change,
        "tvl_growth_pct": tvl_growth_pct,
        # Vault counts
        "vaults_first": first_agg.vaults_total,
        "vaults_latest": latest_agg.vaults_total,
        "vaults_change": vault_count_change,
        "active_first": first_agg.vaults_active,
        "active_latest": latest_agg.vaults_active,
        "active_change": active_change,
        # Fees
        "daily_fee_first_wei": first_agg.lido_fees_this_report_wei,
        "daily_fee_latest_wei": latest_agg.lido_fees_this_report_wei,
        "fee_change_wei": fee_change,
        "fee_growth_pct": fee_growth_pct,
        "total_fees_period_wei": total_fees_period,
        # Liability
        "liability_first_shares": first_agg.liability_shares,
        "liability_latest_shares": latest_agg.liability_shares,
        "liability_change_shares": liability_change,
        "liability_growth_pct": liability_growth_pct,
    }


def format_analytics_summary(analytics: ProtocolAnalytics) -> str:
    """Format analytics as a text summary for console output."""
    lines = [
        "",
        "=" * 70,
        "📊 ANALYTICS SUMMARY",
        "=" * 70,
        "",
        "🏦 ADOPTION METRICS",
        f"   Total Vaults: {analytics.total_vaults}",
        f"   Active Vaults: {analytics.active_vaults} ({100 * analytics.active_vaults / max(1, analytics.total_vaults):.1f}%)",
        f"   At Peak: {analytics.at_peak_vaults} | Below Peak: {analytics.below_peak_vaults}",
        "",
        "💰 TVL & CAPITAL",
        f"   Total Value: {Decimal(analytics.total_value_wei) / WEI_PER_ETH:.2f} ETH",
        f"   Total Liability: {Decimal(analytics.total_liability_wei) / WEI_PER_ETH:.2f} ETH",
        f"   Locked Collateral: {Decimal(analytics.total_locked_wei) / WEI_PER_ETH:.2f} ETH",
        f"   Available to Withdraw: {Decimal(analytics.total_withdrawable_wei) / WEI_PER_ETH:.2f} ETH",
        "",
        "💸 REVENUE METRICS",
        f"   Daily Revenue: {Decimal(analytics.daily_revenue_wei) / WEI_PER_ETH:.6f} ETH",
        f"   Projected Annual: {Decimal(analytics.annual_revenue_projection_wei) / WEI_PER_ETH:.2f} ETH",
        f"   Avg per Active Vault: {Decimal(analytics.avg_fee_per_active_vault_wei) / WEI_PER_ETH:.6f} ETH/day",
        f"   Revenue Concentration (Top 3): {analytics.revenue_concentration_top3 * 100:.1f}%",
        "",
        "📈 CAPITAL EFFICIENCY",
        f"   Protocol Utilization: {analytics.protocol_utilization * 100:.1f}%",
        f"   Avg Collateralization: {analytics.avg_collateralization:.2f}x",
        f"   Capital Locked Ratio: {analytics.capital_locked_ratio * 100:.1f}%",
        "",
        "⚠️  RISK METRICS",
        f"   Avg Health Factor: {analytics.avg_health_factor:.2f}"
        if analytics.avg_health_factor
        else "   Avg Health Factor: N/A",
        f"   High Risk Vaults: {analytics.high_risk_vault_count}",
        f"   Near Rebalance Threshold: {analytics.vaults_near_rebalance}",
        "",
    ]
    return "\n".join(lines)
