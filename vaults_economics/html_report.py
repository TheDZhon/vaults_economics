"""HTML report generation."""

import html
import http.server
import socketserver
import sys
import threading
import webbrowser
from datetime import datetime, timezone
from typing import Any

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


def generate_html_report(
    submissions: list[ReportSubmission],
    snapshots: list[dict[str, VaultSnapshot]],
    onchain_metrics_list: list[dict[str, OnchainVaultMetrics]] | None = None,
    onchain_blocks: list[int | str] | None = None,
) -> str:
    """Generate a complete HTML report from the collected data."""
    if not submissions or not snapshots:
        return _HTML_TEMPLATE.replace(_HTML_CONTENT_PLACEHOLDER, "<p>No data available.</p>")

    current = submissions[0]
    cur_snap = snapshots[0]
    cur_agg = compute_aggregates(cur_snap)
    onchain_cur = onchain_metrics_list[0] if onchain_metrics_list else None
    onchain_block = onchain_blocks[0] if onchain_blocks else None

    ts_formatted = datetime.fromtimestamp(current.block_timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

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
                <div class="label">{label_with_hint("Lido Fees (This Report)", "Total Lido protocol fees accrued during this report period. Infrastructure fee: base protocol fee. Liquidity fee: charged when vault is at peak liability.")}</div>
                <div class="value">{format_eth(cur_agg.lido_fees_this_report_wei, decimals=6)}</div>
                <div class="sub">Infra: {format_wei_sci(cur_agg.infra_fee_wei)} • Liq: {format_wei_sci(cur_agg.liquidity_fee_wei)}</div>
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
        status_emoji, status_text, _ = vault_status(s)
        mode_emoji, mode_text = economic_mode(s)

        is_active = s.liability_shares > 0
        status_class = "active" if is_active else "passive"

        mode_class = "unlevered"
        if s.liability_shares > 0:
            mode_class = "at-peak" if s.max_liability_shares == s.liability_shares else "below-peak"

        fee_delta = fee_delta_wei(s)
        liab_wei = shares_to_wei(s.liability_shares, current.simulated_share_rate)

        liquidity_class = "liquidity-active" if s.liquidity_fee_wei > 0 else ""

        vault_address_link = link_address(s.vault, s.vault)
        vault_html = f"""
        <div class="vault-card">
            <div class="vault-header">
                <div class="vault-address">{vault_address_link}</div>
                <div class="vault-badges">
                    <span class="badge {status_class}">{status_text}</span>
                    <span class="badge {mode_class}">{mode_text}</span>
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
                    <div class="value">{format_eth(liab_wei, decimals=6) if current.simulated_share_rate else 'n/a'}</div>
                </div>
                <div class="vault-metric">
                    <div class="label">{label_with_hint("Liability Shares", "Current stETH liability in shares (Lido's internal accounting unit). Used to calculate locked collateral.")}</div>
                    <div class="value">{format_shares(s.liability_shares)}</div>
                </div>
            </div>
            <div class="fee-breakdown">
                <h4>💸 Lido Fees (This Report)</h4>
                <div class="fee-row">
                    <span class="fee-label">{label_with_hint("Total", "Total Lido protocol fees accrued during this report period (infrastructure + liquidity + reservation).")}</span>
                    <span class="fee-value">{format_wei_sci(fee_delta)} wei</span>
                </div>
                <div class="fee-row">
                    <span class="fee-label">{label_with_hint("Infrastructure", "Base Lido protocol infrastructure fee charged to all active vaults.")}</span>
                    <span class="fee-value">{format_wei_sci(s.infra_fee_wei)} wei</span>
                </div>
                <div class="fee-row {liquidity_class}">
                    <span class="fee-label">{label_with_hint(f"Liquidity {'🔴' if s.liquidity_fee_wei > 0 else ''}", "Additional fee charged when vault is at peak liability (locked). Indicates vault is fully utilized.")}</span>
                    <span class="fee-value">{format_wei_sci(s.liquidity_fee_wei)} wei</span>
                </div>"""

        if s.reservation_fee_wei:
            vault_html += f"""
                <div class="fee-row">
                    <span class="fee-label">{label_with_hint("Reservation", "Reservation liquidity fee charged when vault reserves are utilized.")}</span>
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
                        <div class="label">{label_with_hint("Mintable stETH", "Remaining stETH minting capacity. Limited by share limit and reserve ratio requirements.")}</div>
                        <div class="value">{format_eth(onchain_metrics.mintable_steth_wei, decimals=4)}</div>
                    </div>
                    <div class="onchain-item">
                        <div class="label">{label_with_hint("Reserve Ratio", "Reserve ratio in basis points (10000 = 100%). Higher ratio means more collateral locked per unit of liability.")}</div>
                        <div class="value">{format_bp(onchain_metrics.reserve_ratio_bp)}</div>
                    </div>
                    <div class="onchain-item">
                        <div class="label">{label_with_hint("Healthy", "Vault health status. Unhealthy vaults may be subject to forced rebalance if reserve ratio falls below forced rebalance threshold.")}</div>
                        <div class="value">{'✅ Yes' if onchain_metrics.is_healthy else '❌ No'}</div>
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

        def log_message(self, format: str, *args: Any) -> None:
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
