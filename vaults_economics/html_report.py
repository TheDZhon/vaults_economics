"""HTML report generation."""

import html
import http.server
import socketserver
import sys
import threading
import webbrowser
from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any

from vaults_economics.analytics import (
    ProtocolAnalytics,
    calculate_growth_metrics,
    calculate_protocol_analytics,
    rank_vaults_by_performance,
)
from vaults_economics.constants import BEACONCHA_BASE, ETHERSCAN_BASE
from vaults_economics.formatters import (
    economic_mode,
    format_annual_projection,
    format_bp,
    format_eth,
    format_shares,
    format_wei_sci,
    shares_to_wei,
    vault_status,
)
from vaults_economics.models import OnchainVaultMetrics, ReportSubmission, VaultSnapshot
from vaults_economics.reports import compute_aggregates, fee_delta_wei

# HTML Template
_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>stVaults Economics Report</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0a0e14;
            --bg-secondary: #12171f;
            --bg-card: #171d26;
            --bg-card-hover: #1c232e;
            --accent-cyan: #39bae6;
            --accent-green: #7fd962;
            --accent-yellow: #ffb454;
            --accent-orange: #ff8f40;
            --accent-red: #f07178;
            --accent-purple: #d4bfff;
            --text-primary: #e6e1cf;
            --text-secondary: #959da5;
            --text-muted: #5c6773;
            --border-color: #1f2733;
            --shadow: 0 4px 24px rgba(0, 0, 0, 0.4);
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Outfit', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }
        header {
            text-align: center;
            padding: 3rem 0;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 2rem;
            background: linear-gradient(180deg, var(--bg-secondary) 0%, transparent 100%);
        }
        header h1 {
            font-size: 2.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 0.5rem;
        }
        header .timestamp {
            font-family: 'JetBrains Mono', monospace;
            color: var(--text-secondary);
            font-size: 0.95rem;
        }
        .aggregates {
            background: var(--bg-card);
            border-radius: 16px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: var(--shadow);
            border: 1px solid var(--border-color);
        }
        .aggregates h2 {
            color: var(--accent-cyan);
            font-size: 1.4rem;
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1.5rem;
        }
        .metric-box {
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 1.25rem;
            border: 1px solid var(--border-color);
        }
        .metric-box .label {
            color: var(--text-secondary);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.5rem;
        }
        .label-with-hint {
            position: relative;
            display: inline-flex;
            align-items: center;
            gap: 0.25rem;
            cursor: help;
        }
        .hint-icon {
            font-size: 0.7rem;
            opacity: 0.6;
            transition: opacity 0.2s;
        }
        .label-with-hint:hover .hint-icon {
            opacity: 1;
        }
        .hint-tooltip {
            position: absolute;
            bottom: 100%;
            left: 50%;
            transform: translateX(-50%);
            margin-bottom: 0.5rem;
            padding: 0.5rem 0.75rem;
            background: var(--bg-card);
            color: var(--text-primary);
            font-size: 0.75rem;
            font-weight: normal;
            text-transform: none;
            letter-spacing: normal;
            line-height: 1.4;
            white-space: normal;
            width: max-content;
            max-width: 280px;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            box-shadow: var(--shadow);
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.2s;
            z-index: 1000;
        }
        .label-with-hint:hover .hint-tooltip {
            opacity: 1;
        }
        .hint-tooltip::after {
            content: "";
            position: absolute;
            top: 100%;
            left: 50%;
            transform: translateX(-50%);
            border: 6px solid transparent;
            border-top-color: var(--bg-card);
        }
        .metric-box .value {
            font-family: 'JetBrains Mono', monospace;
            font-size: 1.3rem;
            font-weight: 600;
            color: var(--text-primary);
        }
        .metric-box .value.eth { color: var(--accent-cyan); }
        .metric-box .value.positive { color: var(--accent-green); }
        .metric-box .value.negative { color: var(--accent-red); }
        .metric-box .sub {
            font-size: 0.85rem;
            color: var(--text-muted);
            margin-top: 0.25rem;
        }
        .annual-projection {
            background: linear-gradient(135deg, rgba(57, 186, 230, 0.1), rgba(212, 191, 255, 0.1));
            border: 1px solid var(--accent-cyan);
        }
        .annual-projection .value { color: var(--accent-purple); }
        .vaults-section h2 {
            color: var(--text-primary);
            font-size: 1.4rem;
            margin-bottom: 1.5rem;
        }
        .vault-card {
            background: var(--bg-card);
            border-radius: 16px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: var(--shadow);
            border: 1px solid var(--border-color);
            transition: border-color 0.2s, transform 0.2s;
        }
        .vault-card:hover {
            border-color: var(--accent-cyan);
            transform: translateY(-2px);
        }
        .vault-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            flex-wrap: wrap;
            gap: 1rem;
            margin-bottom: 1rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--border-color);
        }
        .vault-address {
            font-family: 'JetBrains Mono', monospace;
            font-size: 1rem;
            color: var(--accent-cyan);
            word-break: break-all;
        }
        .vault-badges {
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
        }
        .badge {
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.03em;
        }
        .badge.active { background: rgba(127, 217, 98, 0.2); color: var(--accent-green); }
        .badge.passive { background: rgba(149, 157, 165, 0.2); color: var(--text-secondary); }
        .badge.at-peak { background: rgba(240, 113, 120, 0.2); color: var(--accent-red); }
        .badge.below-peak { background: rgba(255, 180, 84, 0.2); color: var(--accent-yellow); }
        .badge.unlevered { background: rgba(127, 217, 98, 0.2); color: var(--accent-green); }
        .badge-with-hint {
            position: relative;
            cursor: help;
        }
        .badge-with-hint .badge-tooltip {
            position: absolute;
            bottom: 100%;
            left: 50%;
            transform: translateX(-50%);
            margin-bottom: 0.5rem;
            padding: 0.5rem 0.75rem;
            background: var(--bg-card);
            color: var(--text-primary);
            font-size: 0.7rem;
            font-weight: normal;
            text-transform: none;
            letter-spacing: normal;
            line-height: 1.4;
            white-space: normal;
            width: max-content;
            max-width: 260px;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            box-shadow: var(--shadow);
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.2s;
            z-index: 1000;
        }
        .badge-with-hint:hover .badge-tooltip {
            opacity: 1;
        }
        .badge-with-hint .badge-tooltip::after {
            content: "";
            position: absolute;
            top: 100%;
            left: 50%;
            transform: translateX(-50%);
            border: 6px solid transparent;
            border-top-color: var(--bg-card);
        }
        .vault-metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }
        .vault-metric {
            padding: 0.75rem;
            background: var(--bg-secondary);
            border-radius: 8px;
        }
        .vault-metric .label {
            font-size: 0.75rem;
            color: var(--text-muted);
            margin-bottom: 0.25rem;
        }
        .vault-metric .label-with-hint {
            font-size: 0.75rem;
        }
        .vault-metric .hint-tooltip {
            max-width: 240px;
            font-size: 0.7rem;
        }
        .vault-metric .value {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.95rem;
            color: var(--text-primary);
        }
        .fee-breakdown {
            margin-top: 1rem;
            padding-top: 1rem;
            border-top: 1px solid var(--border-color);
        }
        .fee-breakdown h4 {
            color: var(--accent-yellow);
            font-size: 0.9rem;
            margin-bottom: 0.75rem;
        }
        .fee-row {
            display: flex;
            justify-content: space-between;
            padding: 0.35rem 0;
            font-size: 0.85rem;
        }
        .fee-row .fee-label { color: var(--text-secondary); }
        .fee-row .fee-value {
            font-family: 'JetBrains Mono', monospace;
            color: var(--text-primary);
        }
        .fee-row.liquidity-active .fee-value { color: var(--accent-red); }
        .fee-row.annual {
            background: rgba(212, 191, 255, 0.1);
            margin: 0.25rem -0.5rem;
            padding: 0.35rem 0.5rem;
            border-radius: 4px;
        }
        .fee-row.annual .fee-value { color: var(--accent-purple); }
        .onchain-section {
            margin-top: 1rem;
            padding: 1rem;
            background: var(--bg-secondary);
            border-radius: 8px;
            border-left: 3px solid var(--accent-orange);
        }
        .onchain-section h4 {
            color: var(--accent-orange);
            font-size: 0.85rem;
            margin-bottom: 0.75rem;
        }
        .onchain-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 0.75rem;
        }
        .onchain-item .label { font-size: 0.7rem; color: var(--text-muted); }
        .onchain-item .label-with-hint {
            font-size: 0.7rem;
        }
        .onchain-item .hint-tooltip {
            max-width: 220px;
            font-size: 0.65rem;
        }
        .onchain-item .value {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
        }
        footer {
            text-align: center;
            padding: 2rem;
            color: var(--text-muted);
            font-size: 0.85rem;
            border-top: 1px solid var(--border-color);
            margin-top: 2rem;
        }
        footer a { color: var(--accent-cyan); text-decoration: none; }
        footer a:hover { text-decoration: underline; }
        a[href^="https://etherscan.io"], a[href^="https://beaconcha.in"] {
            color: var(--accent-cyan);
            text-decoration: none;
            transition: opacity 0.2s;
        }
        a[href^="https://etherscan.io"]:hover, a[href^="https://beaconcha.in"]:hover {
            opacity: 0.8;
            text-decoration: underline;
        }
        @media (max-width: 768px) {
            .container { padding: 1rem; }
            header h1 { font-size: 1.8rem; }
            .vault-header { flex-direction: column; }
        }
        /* Analytics Section */
        .analytics-section {
            margin-bottom: 2rem;
        }
        .analytics-section h2 {
            color: var(--accent-purple);
            font-size: 1.4rem;
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .analytics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 1.5rem;
        }
        .analytics-card {
            background: var(--bg-card);
            border-radius: 16px;
            padding: 1.5rem;
            box-shadow: var(--shadow);
            border: 1px solid var(--border-color);
        }
        .analytics-card h3 {
            color: var(--text-primary);
            font-size: 1rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--border-color);
        }
        .analytics-card h3 .emoji { margin-right: 0.5rem; }
        .stat-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.4rem 0;
            font-size: 0.9rem;
        }
        .stat-row .stat-label { color: var(--text-secondary); }
        .stat-row .stat-value {
            font-family: 'JetBrains Mono', monospace;
            color: var(--text-primary);
            font-weight: 600;
        }
        .stat-row .stat-value.positive { color: var(--accent-green); }
        .stat-row .stat-value.negative { color: var(--accent-red); }
        .stat-row .stat-value.warning { color: var(--accent-yellow); }
        .stat-row .stat-value.highlight { color: var(--accent-cyan); }
        .progress-bar {
            height: 8px;
            background: var(--bg-secondary);
            border-radius: 4px;
            overflow: hidden;
            margin: 0.5rem 0;
        }
        .progress-bar .fill {
            height: 100%;
            border-radius: 4px;
            transition: width 0.3s ease;
        }
        .progress-bar .fill.green { background: var(--accent-green); }
        .progress-bar .fill.yellow { background: var(--accent-yellow); }
        .progress-bar .fill.red { background: var(--accent-red); }
        .progress-bar .fill.cyan { background: var(--accent-cyan); }
        .risk-indicator {
            display: inline-flex;
            align-items: center;
            gap: 0.25rem;
            padding: 0.15rem 0.5rem;
            border-radius: 10px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        .risk-indicator.low { background: rgba(127, 217, 98, 0.2); color: var(--accent-green); }
        .risk-indicator.medium { background: rgba(255, 180, 84, 0.2); color: var(--accent-yellow); }
        .risk-indicator.high { background: rgba(240, 113, 120, 0.2); color: var(--accent-red); }
        .ranking-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
        }
        .ranking-table th {
            text-align: left;
            padding: 0.75rem 0.5rem;
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.7rem;
            letter-spacing: 0.05em;
            border-bottom: 1px solid var(--border-color);
        }
        .ranking-table td {
            padding: 0.75rem 0.5rem;
            border-bottom: 1px solid var(--border-color);
        }
        .ranking-table tr:hover td { background: var(--bg-secondary); }
        .ranking-table .rank {
            font-weight: 700;
            color: var(--accent-cyan);
            width: 40px;
        }
        .ranking-table .vault-addr {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
        }
        .ranking-table .score {
            font-family: 'JetBrains Mono', monospace;
            color: var(--accent-purple);
        }
    </style>
</head>
<body>
    <div class="container">
        <!--CONTENT_PLACEHOLDER-->
    </div>
</body>
</html>
"""

_HTML_CONTENT_PLACEHOLDER = "<!--CONTENT_PLACEHOLDER-->"


def link_address(address: str, text: str | None = None) -> str:
    """Generate an Etherscan link for an Ethereum address."""
    if text is None:
        text = address
    url = f"{ETHERSCAN_BASE}/address/{address}"
    return f'<a href="{url}" target="_blank" rel="noopener noreferrer" style="color: var(--accent-cyan); text-decoration: none;">{html.escape(text)}</a>'


def link_block(block_number: int | str, text: str | None = None) -> str:
    """Generate an Etherscan link for a block number."""
    if text is None:
        text = str(block_number)
    url = f"{ETHERSCAN_BASE}/block/{block_number}"
    return f'<a href="{url}" target="_blank" rel="noopener noreferrer" style="color: var(--accent-cyan); text-decoration: none;">{html.escape(text)}</a>'


def link_tx(tx_hash: str, text: str | None = None) -> str:
    """Generate an Etherscan link for a transaction hash."""
    if text is None:
        text = tx_hash[:10] + "..." + tx_hash[-8:] if len(tx_hash) > 18 else tx_hash
    url = f"{ETHERSCAN_BASE}/tx/{tx_hash}"
    return f'<a href="{url}" target="_blank" rel="noopener noreferrer" style="color: var(--accent-cyan); text-decoration: none;">{html.escape(text)}</a>'


def link_slot(slot: int, text: str | None = None) -> str:
    """Generate a Beaconcha.in link for a slot number."""
    if text is None:
        text = str(slot)
    url = f"{BEACONCHA_BASE}/slot/{slot}"
    return f'<a href="{url}" target="_blank" rel="noopener noreferrer" style="color: var(--accent-cyan); text-decoration: none;">{html.escape(text)}</a>'


def link_timestamp(timestamp: int, block_number: int | None = None, slot: int | None = None) -> str:
    """Generate a clickable timestamp. Links to block if available, otherwise slot, otherwise just formatted time."""
    ts_formatted = datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if block_number is not None:
        url = f"{ETHERSCAN_BASE}/block/{block_number}"
        return f'<a href="{url}" target="_blank" rel="noopener noreferrer" style="color: var(--accent-cyan); text-decoration: none;">{html.escape(ts_formatted)}</a>'
    if slot is not None:
        url = f"{BEACONCHA_BASE}/slot/{slot}"
        return f'<a href="{url}" target="_blank" rel="noopener noreferrer" style="color: var(--accent-cyan); text-decoration: none;">{html.escape(ts_formatted)}</a>'
    return html.escape(ts_formatted)


def label_with_hint(label: str, hint: str) -> str:
    """Generate a label with a tooltip hint."""
    escaped_label = html.escape(label)
    escaped_hint = html.escape(hint)
    return f'<span class="label-with-hint">{escaped_label}<span class="hint-icon">ℹ️</span><span class="hint-tooltip">{escaped_hint}</span></span>'


def badge_with_hint(text: str, css_class: str, hint: str) -> str:
    """Generate a badge with a tooltip hint."""
    escaped_text = html.escape(text)
    escaped_hint = html.escape(hint)
    return f'<span class="badge-with-hint"><span class="badge {css_class}">{escaped_text}</span><span class="badge-tooltip">{escaped_hint}</span></span>'


# Hint text for status badges
STATUS_HINTS = {
    "Active": "Vault has stETH minted against it (liability > 0). Actively generating fees for Lido.",
    "Active (At Peak)": "Vault liability equals the period high-water mark (`maxLiabilityShares`). VaultHub computes `locked` from this peak value.",
    "Active (Below Peak)": "Vault liability decreased since period peak. Locked collateral may still be based on peak until next report (cooldown).",
    "Passive": "No stETH is minted against this vault. No action needed.",
    "Slashing Reserve": "Vault has slashing reserve locked due to validator penalties. Monitor validator status.",
}

# Hint text for economic mode badges
MODE_HINTS = {
    "At Peak (locked)": "Liability equals maxLiabilityShares (period high-water mark). VaultHub computes locked collateral based on this peak value.",
    "Below Peak (cooldown)": "Liability is below the period peak (maxLiabilityShares). After burning shares, locked collateral remains based on peak until next oracle report.",
    "Unlevered": "No stETH liability. Vault operates without leverage - no collateral is locked for stETH backing.",
}


def generate_analytics_section(
    analytics: ProtocolAnalytics,
    growth: dict[str, Any],
    rankings: list[Any],
    _simulated_share_rate: int,
) -> str:
    """Generate the analytics section HTML."""
    from decimal import Decimal

    from vaults_economics.constants import WEI_PER_ETH

    # Utilization progress bar color - cap the bar at 100% but keep the displayed value uncapped
    util_ratio = float(analytics.protocol_utilization) if analytics.protocol_utilization else 0.0
    util_pct_raw = max(0.0, util_ratio * 100)
    util_pct_bar = min(100.0, util_pct_raw)
    util_color = "green" if util_pct_raw < 60 else ("yellow" if util_pct_raw < 85 else "red")

    # Locked ratio progress bar - ensure it's a sane percentage
    locked_ratio = float(analytics.capital_locked_ratio) if analytics.capital_locked_ratio else 0.0
    locked_pct = min(100.0, max(0.0, locked_ratio * 100))

    # Revenue concentration indicator
    conc_pct = analytics.revenue_concentration_top3 * 100
    conc_class = "positive" if conc_pct < 50 else ("warning" if conc_pct < 70 else "negative")

    # Health factor class
    hf_class = "positive"
    if analytics.avg_health_factor:
        if analytics.avg_health_factor < 1.1:
            hf_class = "negative"
        elif analytics.avg_health_factor < 1.3:
            hf_class = "warning"

    # Format large ETH values
    def fmt_eth(wei: int, decimals: int = 2) -> str:
        value = Decimal(wei) / WEI_PER_ETH
        format_str = f",.{decimals}f"
        return format(value, format_str)

    # Growth section
    growth_html = ""
    if growth.get("has_trend_data"):
        tvl_change_class = "positive" if growth["tvl_change_wei"] >= 0 else "negative"
        fee_change_class = "positive" if growth["fee_change_wei"] >= 0 else "negative"
        tvl_change_sign = "+" if growth["tvl_change_wei"] >= 0 else ""
        fee_change_sign = "+" if growth["fee_change_wei"] >= 0 else ""

        growth_html = f"""
        <div class="analytics-card">
            <h3><span class="emoji">📈</span> Growth Trends ({growth["period_days"]} days)</h3>
            <div class="stat-row">
                <span class="stat-label">{label_with_hint("TVL Change", "Change in total reported value across all vaults between the latest and first report in the selected window.")}</span>
                <span class="stat-value {tvl_change_class}">{tvl_change_sign}{fmt_eth(growth["tvl_change_wei"])} ETH ({growth["tvl_growth_pct"]:+.1f}%)</span>
            </div>
            <div class="stat-row">
                <span class="stat-label">{label_with_hint("Vault Count Change", "Change in the number of vaults present in the reports over the selected window (latest vs first).")}</span>
                <span class="stat-value">{growth["vaults_first"]} → {growth["vaults_latest"]} ({growth["vaults_change"]:+d})</span>
            </div>
            <div class="stat-row">
                <span class="stat-label">{label_with_hint("Daily Fee Change", "Change in total Lido fees accrued during the report period (latest vs first). This is the per-report fee delta aggregated across vaults.")}</span>
                <span class="stat-value {fee_change_class}">{fee_change_sign}{fmt_eth(growth["fee_change_wei"], 6)} ETH ({growth["fee_growth_pct"]:+.1f}%)</span>
            </div>
            <div class="stat-row">
                <span class="stat-label">{label_with_hint("Total Fees (Period)", "Sum of Lido fees accrued across all reports in the selected window (i.e., sum of per-report fee deltas).")}</span>
                <span class="stat-value highlight">{fmt_eth(growth["total_fees_period_wei"], 4)} ETH</span>
            </div>
        </div>
        """

    # Pre-compute values that need conditional formatting
    avg_hf_display = f"{analytics.avg_health_factor:.2f}" if analytics.avg_health_factor else "N/A"
    high_risk_class = "negative" if analytics.high_risk_vault_count > 0 else "positive"
    near_rebalance_class = "warning" if analytics.vaults_near_rebalance > 0 else "positive"
    # Bar width is bounded above; displayed value is not
    util_pct_capped = f"{util_pct_bar:.1f}"
    util_pct_display = f"{min(util_pct_raw, 999.9):.1f}{'+' if util_pct_raw > 999.9 else ''}"
    locked_pct_capped = f"{locked_pct:.1f}"

    # Top performers table
    top_performers_rows = ""
    for r in rankings[:5]:  # Top 5
        risk_class = r.risk_tier
        vault_short = r.vault[:8] + "..." + r.vault[-6:]
        util_display = f"{r.utilization * 100:.1f}"
        top_performers_rows += f"""
        <tr>
            <td class="rank">#{r.rank}</td>
            <td class="vault-addr">{vault_short}</td>
            <td class="score">{r.score:.3f}</td>
            <td>{fmt_eth(r.daily_fee_wei, 6)}</td>
            <td>{util_display}%</td>
            <td><span class="risk-indicator {risk_class}">{risk_class.upper()}</span></td>
        </tr>
        """

    return f"""
    <section class="analytics-section">
        <h2>🎯 Analytics</h2>
        <div class="analytics-grid">
            <div class="analytics-card">
                <h3><span class="emoji">💰</span> Revenue Metrics</h3>
                <div class="stat-row">
                    <span class="stat-label">{label_with_hint("Daily Revenue", "Total Lido fees accrued during the latest report period across all vaults (infrastructure + liquidity + reservation liquidity).")}</span>
                    <span class="stat-value highlight">{fmt_eth(analytics.daily_revenue_wei, 6)} ETH</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">{label_with_hint("Projected Annual", "Simple projection assuming the latest report-period fees repeat daily: daily fees × 365.")}</span>
                    <span class="stat-value positive">{fmt_eth(analytics.annual_revenue_projection_wei)} ETH</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">{label_with_hint("Avg per Active Vault", "Average daily Lido fees per active vault (vaults with stETH liability > 0) in the latest report period.")}</span>
                    <span class="stat-value">{fmt_eth(analytics.avg_fee_per_active_vault_wei, 6)} ETH/day</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">{label_with_hint("Revenue Concentration (Top 3)", "Share of total daily fees contributed by the top 3 vaults by fees in the latest report period.")}</span>
                    <span class="stat-value {conc_class}">{conc_pct:.1f}%</span>
                </div>
            </div>

            <div class="analytics-card">
                <h3><span class="emoji">⚡</span> Capital Efficiency</h3>
                <div class="stat-row">
                    <span class="stat-label">{label_with_hint("Protocol Utilization", "Protocol-wide capacity usage: Σ(stETH Liability) ÷ Σ(total stETH minting capacity), summed across vaults. Values > 100% mean liabilities exceed current minting capacity (some vaults are over-utilized / unhealthy). The progress bar is capped at 100% for display.")}</span>
                    <span class="stat-value">{util_pct_display}%</span>
                </div>
                <div class="progress-bar">
                    <div class="fill {util_color}" style="width: {util_pct_capped}%"></div>
                </div>
                <div class="stat-row">
                    <span class="stat-label">{label_with_hint("Avg Collateralization", "Average collateralization across the protocol: total value ÷ total stETH liability (both aggregated across vaults).")}</span>
                    <span class="stat-value">{analytics.avg_collateralization:.2f}x</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">{label_with_hint("Capital Locked Ratio", "Share of total value that is locked as collateral: Σ(locked) ÷ Σ(total value). Locked is computed by VaultHub (includes liability + reserve; excludes unsettled fees).")}</span>
                    <span class="stat-value">{locked_pct:.1f}%</span>
                </div>
                <div class="progress-bar">
                    <div class="fill cyan" style="width: {locked_pct_capped}%"></div>
                </div>
            </div>

            <div class="analytics-card">
                <h3><span class="emoji">⚠️</span> Risk Assessment</h3>
                <div class="stat-row">
                    <span class="stat-label">{label_with_hint("Avg Health Factor", "Average vault Health Factor across vaults with liability. Health Factor = (Total Value × (1 − Forced Rebalance Threshold)) ÷ stETH Liability.")}</span>
                    <span class="stat-value {hf_class}">{avg_hf_display}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">{label_with_hint("High Risk Vaults", "Count of vaults classified as high risk (Health Factor < 1.1).")}</span>
                    <span class="stat-value {high_risk_class}">{analytics.high_risk_vault_count}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">{label_with_hint("Near Rebalance Threshold", "Count of vaults within 500 bps of their forced rebalance threshold (based on on-chain total value, liability, and the configured threshold).")}</span>
                    <span class="stat-value {near_rebalance_class}">{analytics.vaults_near_rebalance}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">{label_with_hint("At Peak (Locked)", "Number of active vaults whose current liability equals the period high-water mark (`maxLiabilityShares`). These vaults are in the 'At Peak' economic mode.")}</span>
                    <span class="stat-value">{analytics.at_peak_vaults} / {analytics.active_vaults}</span>
                </div>
            </div>

            {growth_html}

            <div class="analytics-card" style="grid-column: span 2;">
                <h3><span class="emoji">🏆</span> Top Performing Vaults</h3>
                <table class="ranking-table">
                    <thead>
                        <tr>
                            <th>{label_with_hint("Rank", "Rank among active vaults by composite performance score (higher is better).")}</th>
                            <th>{label_with_hint("Vault", "Vault address (shortened).")}</th>
                            <th>{label_with_hint("Score", "Composite score: 40% revenue contribution + 30% utilization + 30% health factor (risk).")}</th>
                            <th>{label_with_hint("Daily Fee", "Lido fees accrued during the latest report period for the vault (infrastructure + liquidity + reservation liquidity).")}</th>
                            <th>{label_with_hint("Utilization", "Vault utilization: stETH Liability ÷ total stETH minting capacity for the vault.")}</th>
                            <th>{label_with_hint("Risk", "Risk tier based on Health Factor: LOW/MEDIUM/HIGH.")}</th>
                        </tr>
                    </thead>
                    <tbody>
                        {top_performers_rows if top_performers_rows else '<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No active vaults</td></tr>'}
                    </tbody>
                </table>
            </div>
        </div>
    </section>
    """


def generate_html_report(
    submissions: list[ReportSubmission],
    snapshots: list[dict[str, VaultSnapshot]],
    onchain_metrics_list: list[dict[str, OnchainVaultMetrics]] | None = None,
    onchain_blocks: Sequence[int | str] | None = None,
) -> str:
    """Generate a complete HTML report from the collected data."""
    if not submissions or not snapshots:
        return _HTML_TEMPLATE.replace(_HTML_CONTENT_PLACEHOLDER, "<p>No data available.</p>")

    current = submissions[0]
    cur_snap = snapshots[0]
    cur_agg = compute_aggregates(cur_snap)
    onchain_cur = onchain_metrics_list[0] if onchain_metrics_list else None
    onchain_block = onchain_blocks[0] if onchain_blocks else None

    parts: list[str] = []

    # Header
    slot_link = link_slot(current.ref_slot, f"refSlot={current.ref_slot}")
    timestamp_link = link_timestamp(current.block_timestamp, current.block_number, current.ref_slot)
    parts.append(f"""
    <header>
        <h1>📊 stVaults Economics Report</h1>
        <div class="timestamp">{slot_link} • {timestamp_link}</div>
    </header>
    """)

    # Analytics Section
    protocol_analytics = calculate_protocol_analytics(cur_snap, onchain_cur, current.simulated_share_rate)
    growth_metrics = calculate_growth_metrics(submissions, snapshots)
    vault_rankings = rank_vaults_by_performance(cur_snap, onchain_cur, current.simulated_share_rate)

    parts.append(
        generate_analytics_section(protocol_analytics, growth_metrics, vault_rankings, current.simulated_share_rate)
    )

    # Aggregates Section
    parts.append(f"""
    <section class="aggregates">
        <h2>🧾 Aggregates (All Vaults)</h2>
        <div class="metrics-grid">
            <div class="metric-box">
                <div class="label">{label_with_hint("Total Vaults", "Total number of stVaults in the system. Active vaults have stETH liability > 0, passive vaults have no liability.")}</div>
                <div class="value">{cur_agg.vaults_total}</div>
                <div class="sub">{cur_agg.vaults_active} active • {cur_agg.vaults_passive} passive</div>
            </div>
            <div class="metric-box">
                <div class="label">{label_with_hint("Economic Modes", "At-peak: liability equals period peak (locked). Below-peak: liability decreased (cooldown). Unlevered: no liability.")}</div>
                <div class="value">{cur_agg.mode_at_peak + cur_agg.mode_below_peak + cur_agg.mode_unlevered}</div>
                <div class="sub">{cur_agg.mode_at_peak} at-peak • {cur_agg.mode_below_peak} cooldown • {cur_agg.mode_unlevered} unlevered</div>
            </div>
            <div class="metric-box">
                <div class="label">{label_with_hint("Total Value (Reported)", "Oracle-reported total value across all vaults at refSlot. May be partially quarantined on-chain by LazyOracle for sudden increases.")}</div>
                <div class="value eth">{format_eth(cur_agg.total_value_wei, decimals=2)}</div>
            </div>
            <div class="metric-box">
                <div class="label">{label_with_hint("Net Deposits (Cumulative)", "Cumulative deposits minus withdrawals (inOutDelta) across all vaults. Can be negative if withdrawals exceed deposits.")}</div>
                <div class="value eth">{format_eth(cur_agg.in_out_delta_wei, decimals=4)}</div>
            </div>
            <div class="metric-box">
                <div class="label">{label_with_hint("Lido Fees (This Report)", "Total Lido protocol fees accrued during this report period. Infrastructure fee: based on Total Value. Liquidity fee: based on stETH Liability (utilized liquidity). Reservation liquidity fee: based on total stETH minting capacity (reserved liquidity).")}</div>
                <div class="value">{format_eth(cur_agg.lido_fees_this_report_wei, decimals=6)}</div>
                <div class="sub">Infra: {format_wei_sci(cur_agg.infra_fee_wei)} • Liq: {format_wei_sci(cur_agg.liquidity_fee_wei)}{(" • Res: " + format_wei_sci(cur_agg.reservation_fee_wei)) if cur_agg.reservation_fee_wei else ""}</div>
            </div>
            <div class="metric-box annual-projection">
                <div class="label">{label_with_hint("📅 Projected Annual Revenue", "Estimated annual revenue if current daily fees continue unchanged. Calculated as daily fees × 365 days.")}</div>
                <div class="value">{format_annual_projection(cur_agg.lido_fees_this_report_wei)}</div>
                <div class="sub">Assuming same daily fees continue</div>
            </div>
        </div>
    </section>
    """)

    # Individual Vaults Section
    parts.append('<section class="vaults-section"><h2>🏦 Individual Vaults</h2>')

    for _, s in sorted(cur_snap.items(), key=lambda kv: kv[1].vault.lower()):
        _, status_text, _ = vault_status(s)
        _, mode_text = economic_mode(s)

        is_active = s.liability_shares > 0
        status_class = "active" if is_active else "passive"

        mode_class = "unlevered"
        if s.liability_shares > 0:
            mode_class = "at-peak" if s.max_liability_shares == s.liability_shares else "below-peak"

        fee_delta = fee_delta_wei(s)
        liab_wei = shares_to_wei(s.liability_shares, current.simulated_share_rate)

        liquidity_class = "liquidity-active" if s.liquidity_fee_wei > 0 else ""

        # Get hints for badges
        status_hint = STATUS_HINTS.get(status_text, STATUS_HINTS.get("Active", ""))
        mode_hint = MODE_HINTS.get(mode_text, "")

        # Generate badges with hints
        status_badge = badge_with_hint(status_text, status_class, status_hint)
        mode_badge = badge_with_hint(mode_text, mode_class, mode_hint)

        vault_address_link = link_address(s.vault, s.vault)
        vault_html = f"""
        <div class="vault-card">
            <div class="vault-header">
                <div class="vault-address">{vault_address_link}</div>
                <div class="vault-badges">
                    {status_badge}
                    {mode_badge}
                </div>
            </div>
            <div class="vault-metrics">
                <div class="vault-metric">
                    <div class="label">{label_with_hint("Total Value", "Oracle-reported total value for this vault at refSlot. May be partially quarantined on-chain.")}</div>
                    <div class="value">{format_eth(s.total_value_wei, decimals=4)}</div>
                </div>
                <div class="vault-metric">
                    <div class="label">{label_with_hint("Net Deposits", "Cumulative deposits minus withdrawals (inOutDelta). Can be negative if withdrawals exceed deposits.")}</div>
                    <div class="value">{format_eth(s.in_out_delta_wei, decimals=4)}</div>
                </div>
                <div class="vault-metric">
                    <div class="label">{label_with_hint("stETH Liability", "Current stETH liability converted from shares using simulatedShareRate. Represents stETH minted against this vault.")}</div>
                    <div class="value">{format_eth(liab_wei, decimals=6) if current.simulated_share_rate else "n/a"}</div>
                </div>
                <div class="vault-metric">
                    <div class="label">{label_with_hint("Liability Shares", "Current stETH liability in shares (Lido's internal accounting unit). Used to calculate locked collateral.")}</div>
                    <div class="value">{format_shares(s.liability_shares)}</div>
                </div>
            </div>
            <div class="fee-breakdown">
                <h4>💸 Lido Fees (This Report)</h4>
                <div class="fee-row">
                    <span class="fee-label">{label_with_hint("Total", "Total Lido protocol fees accrued during this report period (infrastructure + liquidity + reservation liquidity).")}</span>
                    <span class="fee-value">{format_wei_sci(fee_delta)} wei</span>
                </div>
                <div class="fee-row">
                    <span class="fee-label">{label_with_hint("Infrastructure", "Infrastructure fee (base protocol fee) calculated from Total Value: Total Value × Lido Core APR × Infrastructure Fee %.")}</span>
                    <span class="fee-value">{format_wei_sci(s.infra_fee_wei)} wei</span>
                </div>
                <div class="fee-row {liquidity_class}">
                    <span class="fee-label">{label_with_hint(f"Liquidity {'🔴' if s.liquidity_fee_wei > 0 else ''}", "Liquidity fee (actual liquidity usage) calculated from stETH Liability: stETH Liability × Lido Core APR × Liquidity Fee %.")}</span>
                    <span class="fee-value">{format_wei_sci(s.liquidity_fee_wei)} wei</span>
                </div>"""

        if s.reservation_fee_wei:
            vault_html += f"""
                <div class="fee-row">
                    <span class="fee-label">{label_with_hint("Reservation", "Reservation liquidity fee (liquidity on demand) calculated from total stETH minting capacity: minting capacity × Lido Core APR × Reservation Liquidity Fee %.")}</span>
                    <span class="fee-value">{format_wei_sci(s.reservation_fee_wei)} wei</span>
                </div>"""

        # Annual projections
        vault_html += f"""
                <div class="fee-row annual">
                    <span class="fee-label">{label_with_hint("📅 Projected Annual", "Estimated annual revenue if current daily fees continue unchanged. Calculated as daily fees × 365 days.")}</span>
                    <span class="fee-value">{format_annual_projection(fee_delta)}</span>
                </div>
            </div>"""

        # On-chain metrics
        onchain_metrics = onchain_cur.get(s.vault.lower()) if onchain_cur else None
        if onchain_metrics is not None:
            if onchain_block is not None and isinstance(onchain_block, int):
                block_label = link_block(onchain_block, str(onchain_block))
            else:
                block_label = html.escape(str(onchain_block) if onchain_block is not None else "latest")
            vault_html += f"""
            <div class="onchain-section">
                <h4>🧮 On-chain Metrics (block {block_label})</h4>
                <div class="onchain-grid">
                    <div class="onchain-item">
                        <div class="label">{label_with_hint("Total Value", "On-chain total value applied by VaultHub. May differ from reported value if quarantined.")}</div>
                        <div class="value">{format_eth(onchain_metrics.onchain_total_value_wei, decimals=4)}</div>
                    </div>
                    <div class="onchain-item">
                        <div class="label">{label_with_hint("Locked", "Collateral that cannot be withdrawn. Locked = liability + reserve. Reserve ensures overcollateralization.")}</div>
                        <div class="value">{format_eth(onchain_metrics.locked_wei, decimals=4)}</div>
                    </div>
                    <div class="onchain-item">
                        <div class="label">{label_with_hint("Withdrawable", "ETH available for withdrawal. Withdrawable = total value - locked - unsettled fees.")}</div>
                        <div class="value">{format_eth(onchain_metrics.withdrawable_wei, decimals=4)}</div>
                    </div>
                    <div class="onchain-item">
                        <div class="label">{label_with_hint("Total stETH minting capacity", "Total stETH minting capacity for the vault at this block. Computed by VaultHub from (Total Value − Unsettled Fees), Reserve Ratio, Minimal Reserve, and share limits. Remaining capacity = total capacity − current stETH liability.")}</div>
                        <div class="value">{format_eth(onchain_metrics.mintable_steth_wei, decimals=4)}</div>
                    </div>
                    <div class="onchain-item">
                        <div class="label">{label_with_hint("Reserve Ratio", "Reserve ratio in basis points (10000 = 100%). Higher ratio means more collateral locked per unit of liability.")}</div>
                        <div class="value">{format_bp(onchain_metrics.reserve_ratio_bp)}</div>
                    </div>
                    <div class="onchain-item">
                        <div class="label">{label_with_hint("Healthy", "Vault health status. Unhealthy vaults may be subject to forced rebalance if reserve ratio falls below forced rebalance threshold.")}</div>
                        <div class="value">{"✅ Yes" if onchain_metrics.is_healthy else "❌ No"}</div>
                    </div>
                </div>
            </div>"""

        vault_html += "</div>"
        parts.append(vault_html)

    parts.append("</section>")

    # Footer
    tx_link = ""
    if current.tx_hash:
        tx_link = f" • Tx: {link_tx(current.tx_hash)}"
    block_link = link_block(current.block_number, str(current.block_number))
    parts.append(f"""
    <footer>
        <p>Generated by <a href="https://github.com/lidofinance" target="_blank">Lido</a> stVaults Economics DTD Tool</p>
        <p>Block: {block_link}{tx_link} • Report CID: <code>{html.escape(current.vaults_tree_cid)}</code></p>
    </footer>
    """)

    return _HTML_TEMPLATE.replace(_HTML_CONTENT_PLACEHOLDER, "\n".join(parts))


def serve_html_and_open_browser(html_content: str, port: int = 0) -> None:
    """Serve HTML content on a local server and open the default browser."""

    class QuietHandler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args: Any, html_data: bytes, **kwargs: Any) -> None:
            self.html_data = html_data
            super().__init__(*args, **kwargs)

        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(self.html_data)))
            self.end_headers()
            self.wfile.write(self.html_data)

        def log_message(self, fmt: str, *args: Any) -> None:
            pass  # Suppress logging

    html_bytes = html_content.encode("utf-8")

    # Use a partial function to pass html_data to the handler
    def handler_factory(*args: Any, **kwargs: Any) -> QuietHandler:
        return QuietHandler(*args, html_data=html_bytes, **kwargs)

    # Find an available port
    with socketserver.TCPServer(("127.0.0.1", port), handler_factory) as httpd:
        actual_port = httpd.server_address[1]
        url = f"http://127.0.0.1:{actual_port}/"

        print(f"\n🌐 Serving HTML report at: {url}", file=sys.stderr)
        print("   Press Ctrl+C to stop the server.", file=sys.stderr)

        # Open browser in a separate thread to not block
        def open_browser() -> None:
            webbrowser.open(url)

        threading.Timer(0.5, open_browser).start()

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n\n🛑 Server stopped.", file=sys.stderr)
