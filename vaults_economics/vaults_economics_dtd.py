#!/usr/bin/env python3
"""
Standalone: Vault economics day-to-date analysis from Lido AccountingOracle daily reports (Ethereum mainnet).

What it does
- Finds recent AccountingOracle daily reports by scanning `ProcessingStarted(uint256,bytes32)` logs.
- For each log's transaction, decodes `submitReportData(data, contractVersion)` input.
- Extracts `data.vaultsDataTreeCid` (an IPFS CID pointing to a JSON Merkle-tree dump).
- Downloads the JSON from IPFS gateways and prints per-vault economics + delta vs previous report.

This script is self-contained: it does NOT import anything from the parent repository.
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Iterable


ACCOUNTING_ORACLE_MAINNET = "0x852deD011285fe67063a08005c71a85690503Cee"

# Minimal ABI needed to decode `submitReportData` tx input.
# Source: AccountingOracle ABI on Etherscan (same structure as in Lido oracle codebase).
ACCOUNTING_ORACLE_MIN_ABI: list[dict[str, Any]] = [
    {
        "type": "function",
        "name": "submitReportData",
        "stateMutability": "nonpayable",
        "inputs": [
            {
                "name": "data",
                "type": "tuple",
                "internalType": "struct AccountingOracle.ReportData",
                "components": [
                    {"name": "consensusVersion", "type": "uint256", "internalType": "uint256"},
                    {"name": "refSlot", "type": "uint256", "internalType": "uint256"},
                    {"name": "numValidators", "type": "uint256", "internalType": "uint256"},
                    {"name": "clBalanceGwei", "type": "uint256", "internalType": "uint256"},
                    {
                        "name": "stakingModuleIdsWithNewlyExitedValidators",
                        "type": "uint256[]",
                        "internalType": "uint256[]",
                    },
                    {"name": "numExitedValidatorsByStakingModule", "type": "uint256[]", "internalType": "uint256[]"},
                    {"name": "withdrawalVaultBalance", "type": "uint256", "internalType": "uint256"},
                    {"name": "elRewardsVaultBalance", "type": "uint256", "internalType": "uint256"},
                    {"name": "sharesRequestedToBurn", "type": "uint256", "internalType": "uint256"},
                    {"name": "withdrawalFinalizationBatches", "type": "uint256[]", "internalType": "uint256[]"},
                    {"name": "simulatedShareRate", "type": "uint256", "internalType": "uint256"},
                    {"name": "isBunkerMode", "type": "bool", "internalType": "bool"},
                    {"name": "vaultsDataTreeRoot", "type": "bytes32", "internalType": "bytes32"},
                    {"name": "vaultsDataTreeCid", "type": "string", "internalType": "string"},
                    {"name": "extraDataFormat", "type": "uint256", "internalType": "uint256"},
                    {"name": "extraDataHash", "type": "bytes32", "internalType": "bytes32"},
                    {"name": "extraDataItemsCount", "type": "uint256", "internalType": "uint256"},
                ],
            },
            {"name": "contractVersion", "type": "uint256", "internalType": "uint256"},
        ],
        "outputs": [],
    }
]

# Approx blocks/day on mainnet.
DEFAULT_BLOCKS_PER_DAY = 7200

# Used only when neither --rpc-url nor ETH_RPC_URL are provided.
# Keep this list short and comprised of generally-available public endpoints.
DEFAULT_PUBLIC_ETH_RPC_URLS = (
    "https://eth.llamarpc.com",
    "https://ethereum.publicnode.com",
)

# First vault report block (tx: 0xc79165e96f1d3267ef86f0c3d0156a2d060167f76c2549072b670eea9d16cc72)
# No need to scan blocks before this - no vault reports exist.
FIRST_VAULT_REPORT_BLOCK = 24089645

DEFAULT_IPFS_GATEWAYS = (
    "https://ipfs.io/ipfs/",
    "https://cloudflare-ipfs.com/ipfs/",
    "https://gateway.pinata.cloud/ipfs/",
)

WEI_PER_ETH = Decimal(10**18)
SHARE_SCALE = Decimal(10**18)
SHARE_RATE_SCALE = 10**27  # Lido simulatedShareRate is a ray (1e27)


@dataclass(frozen=True)
class ReportSubmission:
    ref_slot: int
    block_number: int
    block_timestamp: int
    tx_hash: str
    vaults_tree_root: str
    vaults_tree_cid: str
    simulated_share_rate: int


@dataclass(frozen=True)
class VaultSnapshot:
    vault: str
    tvl_wei: int
    net_inflow_wei: int
    total_fees_wei: int
    prev_fee_wei: int
    infra_fee_wei: int
    liquidity_fee_wei: int
    reservation_fee_wei: int
    liabilities_shares: int
    max_liabilities_shares: int
    slashing_reserve_wei: int


def _unique_nonempty(values: Iterable[str | None]) -> list[str]:
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


def _default_rpc_urls(env_rpc_url: str | None) -> list[str]:
    """Default RPC URL candidates when user did not explicitly provide --rpc-url."""
    return _unique_nonempty([env_rpc_url, *DEFAULT_PUBLIC_ETH_RPC_URLS])


def _topic0(w3: Web3, signature: str) -> str:
    result = w3.keccak(text=signature)
    hex_str = result.hex()
    # Ensure 0x prefix is present
    return hex_str if hex_str.startswith("0x") else f"0x{hex_str}"


def _iter_block_ranges(start: int, end: int, chunk_size: int) -> Iterable[tuple[int, int]]:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be > 0")
    cur = start
    while cur <= end:
        yield cur, min(end, cur + chunk_size - 1)
        cur += chunk_size


def _build_gateway_url(gateway: str, cid: str) -> str:
    gw = gateway.rstrip("/")
    # Accept:
    # - https://ipfs.io/ipfs/
    # - https://ipfs.io/ipfs
    # - https://ipfs.io
    if gw.endswith("/ipfs"):
        return f"{gw}/{cid}"
    if "/ipfs/" in gw:
        return f"{gw.rstrip('/')}/{cid}"
    return f"{gw}/ipfs/{cid}"


def _fetch_ipfs_bytes(cid: str, gateways: Iterable[str], *, timeout_s: int) -> bytes:
    try:
        import requests  # type: ignore[import-not-found]
    except ImportError as ex:  # pragma: no cover
        raise RuntimeError("Missing dependency. Run: uv sync") from ex

    last_err: Exception | None = None
    for gw in gateways:
        url = _build_gateway_url(gw, cid)
        try:
            resp = requests.get(url, timeout=timeout_s)
            resp.raise_for_status()
            return resp.content
        except Exception as ex:  # pylint: disable=broad-exception-caught
            last_err = ex
    raise RuntimeError(f"Failed to fetch CID {cid} from all configured gateways") from last_err


def _as_int(value: Any, *, default: int = 0) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        v = value.strip()
        if v.startswith("0x"):
            return int(v, 16)
        return int(v)
    return int(value)


def _format_wei_sci(value: int, *, sig: int = 3) -> str:
    if value == 0:
        return "0"
    s = format(Decimal(abs(value)), f".{max(0, sig - 1)}e")  # 1.69e+13
    mant, exp = s.split("e")
    mant = mant.rstrip("0").rstrip(".")
    exp_i = int(exp)
    sign = "-" if value < 0 else ""
    return f"{sign}{mant}e{exp_i}"


def _format_eth(value_wei: int, *, decimals: int = 9, approx: bool = False) -> str:
    eth = Decimal(value_wei) / WEI_PER_ETH
    s = f"{eth:.{decimals}f}".rstrip("0").rstrip(".")
    prefix = "~" if approx else ""
    return f"{prefix}{s} ETH"


def _format_shares(value: int, *, decimals: int = 3) -> str:
    shares = Decimal(value) / SHARE_SCALE
    s = f"{shares:.{decimals}f}".rstrip("0").rstrip(".")
    return f"{s} shares"


def _shares_to_wei(shares: int, simulated_share_rate: int) -> int:
    """Convert Lido shares to wei using simulatedShareRate (ray, 1e27)."""
    if shares <= 0 or simulated_share_rate <= 0:
        return 0
    return int((shares * simulated_share_rate) // SHARE_RATE_SCALE)


def _economic_mode(s: VaultSnapshot) -> tuple[str, str]:
    """Returns (emoji, mode_description)."""
    if s.max_liabilities_shares == 0:
        return "🌱", "Unlevered"
    if s.liabilities_shares == 0:
        return "🌱", "Unlevered"
    if s.liabilities_shares >= s.max_liabilities_shares:
        return "🔥", "Steady-State Leveraged"
    return "⚡", "Partially Leveraged"


def _vault_status(s: VaultSnapshot) -> tuple[str, str, str]:
    """Returns (emoji, status, action_hint)."""
    if s.slashing_reserve_wei > 0:
        return "🟠", "Slashing Reserve", "⚠️  Slashing reserve locked — monitor validator penalties"
    if s.liabilities_shares == 0:
        return "💤", "Passive", "No action needed — vault is idle with minimal growth"
    if s.max_liabilities_shares and s.liabilities_shares >= s.max_liabilities_shares:
        if s.liquidity_fee_wei > 0:
            return "🔴", "Active (Maxed)", "⚠️  Liquidity fee accruing — consider monitoring costs"
        return "🟡", "Active (Maxed)", "Leverage at capacity — stable state"
    return "🟢", "Active (Building)", "Leverage building/unwinding — monitor position"


def _delta_indicator(prev_val: int, cur_val: int) -> str:
    """Returns emoji indicator for value change."""
    if cur_val > prev_val:
        return "📈"
    elif cur_val < prev_val:
        return "📉"
    return "➡️"


def _parse_ipfs_report(raw_bytes: bytes) -> dict[str, Any]:
    # Keep it lightweight: parse only the fields we need.
    import json  # local import keeps the top of file minimal

    data = json.loads(raw_bytes.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Unexpected IPFS report format (expected JSON object)")
    return data


def _parse_report_to_snapshots(report_json: dict[str, Any]) -> dict[str, VaultSnapshot]:
    extra_values_raw = report_json.get("extraValues", {}) or {}
    extra_by_vault = {str(k).lower(): v for k, v in extra_values_raw.items()}

    out: dict[str, VaultSnapshot] = {}
    for entry in report_json.get("values", []) or []:
        # Each entry: {"value": [vault, totalValueWei, fee, liabilityShares, maxLiabilityShares, slashingReserve], ...}
        value = entry.get("value")
        if not isinstance(value, (list, tuple)) or len(value) < 6:
            continue

        vault = str(value[0])
        key = vault.lower()
        extra = extra_by_vault.get(key) or {}

        out[key] = VaultSnapshot(
            vault=vault,
            tvl_wei=_as_int(value[1]),
            total_fees_wei=_as_int(value[2]),
            liabilities_shares=_as_int(value[3]),
            max_liabilities_shares=_as_int(value[4]),
            slashing_reserve_wei=_as_int(value[5]),
            net_inflow_wei=_as_int(extra.get("inOutDelta")),
            prev_fee_wei=_as_int(extra.get("prevFee")),
            infra_fee_wei=_as_int(extra.get("infraFee")),
            liquidity_fee_wei=_as_int(extra.get("liquidityFee")),
            reservation_fee_wei=_as_int(extra.get("reservationFee")),
        )
    return out


def _decode_submit_report_data_tx(contract, tx_input: str) -> tuple[int, str, str, int]:
    """
    Returns: (ref_slot, vaults_tree_root_hex, vaults_tree_cid, simulated_share_rate)
    """
    fn, args = contract.decode_function_input(tx_input)
    if fn.fn_name != "submitReportData":
        raise ValueError(f"Unexpected function: {fn.fn_name}")

    data = args["data"]

    # web3.py may decode tuples into dict-like or plain tuples depending on version/config.
    if isinstance(data, dict):
        ref_slot = _as_int(data.get("refSlot"))
        root = data.get("vaultsDataTreeRoot")
        cid = str(data.get("vaultsDataTreeCid") or "")
        simulated_share_rate = _as_int(data.get("simulatedShareRate"))
    else:
        # ABI component order is fixed (see ACCOUNTING_ORACLE_MIN_ABI).
        ref_slot = _as_int(data[1])
        simulated_share_rate = _as_int(data[10])
        root = data[12]
        cid = str(data[13])

    if not cid:
        raise ValueError("Empty vaultsDataTreeCid decoded from tx input")

    root_hex = root.hex() if hasattr(root, "hex") else str(root)
    if not root_hex.startswith("0x"):
        root_hex = f"0x{root_hex}"
    return ref_slot, root_hex, cid, simulated_share_rate


def _collect_recent_report_submissions(
    w3: Web3,
    contract,
    oracle_address: str,
    *,
    want_reports: int | None,
    days: int,
    blocks_per_day: int,
    log_chunk_size: int,
) -> list[ReportSubmission]:
    """Collect recent report submissions. If want_reports is None, collect all in the scanned range."""
    topic0 = _topic0(w3, "ProcessingStarted(uint256,bytes32)")

    latest_block = int(w3.eth.block_number)
    window = max(1, int(days) * int(blocks_per_day))

    collected: list[ReportSubmission] = []
    seen_ref_slots: set[int] = set()

    scan_end = latest_block
    # Never scan below the first vault report block - no reports exist before it
    earliest_block = FIRST_VAULT_REPORT_BLOCK

    while scan_end >= earliest_block and (want_reports is None or len(collected) < want_reports):
        scan_start = max(earliest_block, scan_end - window + 1)

        logs: list[dict[str, Any]] = []
        for a, b in _iter_block_ranges(scan_start, scan_end, log_chunk_size):
            # Use provider.make_request to completely bypass web3.py middleware
            # Some RPC providers (like drpc.live) require proper hex formatting
            filter_params = {
                "address": oracle_address,
                "fromBlock": hex(a),
                "toBlock": hex(b),
                "topics": [topic0],
            }
            response = w3.provider.make_request("eth_getLogs", [filter_params])
            if "error" in response:
                raise RuntimeError(f"RPC error: {response['error']}")
            logs.extend(response.get("result", []))

        # Raw JSON-RPC response has hex strings; convert for sorting
        def _hex_to_int(val: Any) -> int:
            if isinstance(val, int):
                return val
            if isinstance(val, str):
                return int(val, 16) if val.startswith("0x") else int(val)
            return int(val)

        logs.sort(key=lambda x: (_hex_to_int(x["blockNumber"]), _hex_to_int(x["transactionIndex"]), _hex_to_int(x["logIndex"])))

        # Work backwards to get the latest reports first.
        for log in reversed(logs):
            # Handle both raw hex string and HexBytes from web3.py
            tx_hash = log["transactionHash"]
            tx_hash_hex = tx_hash if isinstance(tx_hash, str) else tx_hash.hex()
            if not tx_hash_hex.startswith("0x"):
                tx_hash_hex = f"0x{tx_hash_hex}"
            tx = w3.eth.get_transaction(tx_hash_hex)
            try:
                ref_slot, root_hex, cid, simulated_share_rate = _decode_submit_report_data_tx(contract, tx["input"])
            except Exception:  # pylint: disable=broad-exception-caught
                continue

            if ref_slot in seen_ref_slots:
                continue
            seen_ref_slots.add(ref_slot)

            block = w3.eth.get_block(int(tx["blockNumber"]))
            collected.append(
                ReportSubmission(
                    ref_slot=ref_slot,
                    block_number=int(tx["blockNumber"]),
                    block_timestamp=int(block["timestamp"]),
                    tx_hash=tx_hash_hex,
                    vaults_tree_root=root_hex,
                    vaults_tree_cid=cid,
                    simulated_share_rate=simulated_share_rate,
                )
            )

            if want_reports is not None and len(collected) >= want_reports:
                break

        scan_end = scan_start - 1

    return collected


def _print_current_and_delta(
    current: ReportSubmission,
    cur_snap: dict[str, VaultSnapshot],
    prev_snap: dict[str, VaultSnapshot] | None,
):
    ts = datetime.fromtimestamp(current.block_timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print("=" * 70)
    print(f"📊 VAULT ECONOMICS REPORT")
    print(f"   🕐 {ts}  •  refSlot={current.ref_slot}")
    print("=" * 70)

    for _, s in sorted(cur_snap.items(), key=lambda kv: kv[1].vault.lower()):
        status_emoji, status_text, action_hint = _vault_status(s)
        mode_emoji, mode_text = _economic_mode(s)

        print(f"\n{status_emoji} Vault: {s.vault}")
        print(f"   Status: {status_text}  •  Mode: {mode_emoji} {mode_text}")
        print("   " + "─" * 50)

        # Financials
        print(f"   💰 TVL:        {_format_eth(s.tvl_wei, decimals=2, approx=True)}")
        print(f"   📥 Net Inflow: {_format_eth(s.net_inflow_wei, decimals=6)}")

        # Fees breakdown
        print(f"   💸 Fees:")
        fee_delta_wei = s.infra_fee_wei + s.liquidity_fee_wei + s.reservation_fee_wei
        print(f"      • Total (cumulative): {_format_wei_sci(s.total_fees_wei)} wei")
        print(f"      • This report:        {_format_wei_sci(fee_delta_wei)} wei")
        print(f"         - Infra:       {_format_wei_sci(s.infra_fee_wei)} wei")
        liq_indicator = "🔴" if s.liquidity_fee_wei > 0 else "⚪"
        print(f"         - Liquidity:   {liq_indicator} {_format_wei_sci(s.liquidity_fee_wei)} wei")
        if s.reservation_fee_wei:
            print(f"         - Reservation: {_format_wei_sci(s.reservation_fee_wei)} wei")
        if s.prev_fee_wei:
            print(f"      • Prev total:       {_format_wei_sci(s.prev_fee_wei)} wei")

        # Leverage
        print(f"   📊 Leverage:")
        liab_wei = _shares_to_wei(s.liabilities_shares, current.simulated_share_rate)
        liab_hint = _format_eth(liab_wei, decimals=6, approx=True) if current.simulated_share_rate else "n/a"
        print(f"      • Liabilities: {_format_wei_sci(s.liabilities_shares)} shares  ({liab_hint})")
        if s.max_liabilities_shares and s.liabilities_shares >= s.max_liabilities_shares:
            print("      • Max:         🔒 Fully utilized")
        else:
            max_liab_wei = _shares_to_wei(s.max_liabilities_shares, current.simulated_share_rate)
            max_hint = _format_eth(max_liab_wei, decimals=6, approx=True) if current.simulated_share_rate else "n/a"
            print(f"      • Max:         {_format_wei_sci(s.max_liabilities_shares)} shares  ({max_hint})")
        print(f"      • Slashing reserve: {_format_wei_sci(s.slashing_reserve_wei)} wei")

        # Action hint
        print(f"\n   💡 {action_hint}")

    if prev_snap is None:
        return

    print("\n" + "=" * 70)
    print("📈 CHANGES SINCE LAST REPORT")
    print("=" * 70)

    for key, cur in sorted(cur_snap.items(), key=lambda kv: kv[1].vault.lower()):
        prev = prev_snap.get(key)
        if prev is None:
            continue

        mode_emoji, mode_text = _economic_mode(cur)
        fee_total_delta = _delta_indicator(prev.total_fees_wei, cur.total_fees_wei)
        prev_fee_delta_wei = prev.infra_fee_wei + prev.liquidity_fee_wei + prev.reservation_fee_wei
        cur_fee_delta_wei = cur.infra_fee_wei + cur.liquidity_fee_wei + cur.reservation_fee_wei
        fee_delta = _delta_indicator(prev_fee_delta_wei, cur_fee_delta_wei)
        liq_delta = _delta_indicator(prev.liquidity_fee_wei, cur.liquidity_fee_wei)

        print(f"\n🔹 {cur.vault}")
        print("   " + "─" * 50)

        # Fees delta
        print(f"   {fee_total_delta} Total Fees (cumulative): {_format_wei_sci(prev.total_fees_wei)} → {_format_wei_sci(cur.total_fees_wei)} wei")
        print(f"   {fee_delta} Fee (this report):          {_format_wei_sci(prev_fee_delta_wei)} → {_format_wei_sci(cur_fee_delta_wei)} wei")
        print(f"   {liq_delta} Liquidity Fee (this report): {_format_wei_sci(prev.liquidity_fee_wei)} → {_format_wei_sci(cur.liquidity_fee_wei)} wei")

        # Liabilities delta
        if prev.liabilities_shares == cur.liabilities_shares:
            if cur.max_liabilities_shares and cur.liabilities_shares >= cur.max_liabilities_shares:
                print("   ➡️  Liabilities:    Unchanged (at max capacity)")
            else:
                print("   ➡️  Liabilities:    Unchanged")
        else:
            liab_delta = _delta_indicator(prev.liabilities_shares, cur.liabilities_shares)
            print(f"   {liab_delta} Liabilities:    {_format_shares(prev.liabilities_shares)} → {_format_shares(cur.liabilities_shares)}")

        print(f"   {mode_emoji} Mode:           {mode_text}")

    print("\n" + "=" * 70)


def _write_csv(path: str, submissions: list[ReportSubmission], snapshots: list[dict[str, VaultSnapshot]]) -> None:
    rows: list[dict[str, Any]] = []
    for sub, snap in zip(submissions, snapshots):
        date = datetime.fromtimestamp(sub.block_timestamp, tz=timezone.utc).date().isoformat()
        for s in snap.values():
            fee_delta_wei = s.infra_fee_wei + s.liquidity_fee_wei + s.reservation_fee_wei
            rows.append(
                {
                    "date_utc": date,
                    "ref_slot": sub.ref_slot,
                    "block_number": sub.block_number,
                    "tx_hash": sub.tx_hash,
                    "simulated_share_rate": sub.simulated_share_rate,
                    "vault": s.vault,
                    "tvl_wei": s.tvl_wei,
                    "net_inflow_wei": s.net_inflow_wei,
                    "total_fees_wei": s.total_fees_wei,
                    "prev_fee_wei": s.prev_fee_wei,
                    "fees_delta_wei": fee_delta_wei,
                    "infra_fee_wei": s.infra_fee_wei,
                    "liquidity_fee_wei": s.liquidity_fee_wei,
                    "reservation_fee_wei": s.reservation_fee_wei,
                    "liabilities_shares": s.liabilities_shares,
                    "max_liabilities_shares": s.max_liabilities_shares,
                    "slashing_reserve_wei": s.slashing_reserve_wei,
                    "vaults_tree_cid": sub.vaults_tree_cid,
                }
            )

    if not rows:
        return

    fieldnames = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Standalone vault economics analysis from Lido AccountingOracle reports.")
    p.add_argument(
        "--rpc-url",
        default=None,
        help="Execution-layer RPC URL. Defaults to ETH_RPC_URL if set, otherwise tries a small list of public RPCs.",
    )
    p.add_argument("--accounting-oracle", default=ACCOUNTING_ORACLE_MAINNET, help="AccountingOracle address.")
    p.add_argument("--reports", type=int, default=None, help="How many latest reports to analyze. If not specified, retrieves all reports in the scanned range.")
    p.add_argument("--days", type=int, default=14, help="How many days back to scan for reports (default: 14).")
    p.add_argument("--blocks-per-day", type=int, default=DEFAULT_BLOCKS_PER_DAY, help="Approx blocks/day (default: 7200).")
    p.add_argument("--log-chunk-size", type=int, default=20_000, help="Block chunk size for eth_getLogs (default: 20000).")
    p.add_argument("--timeout", type=int, default=30, help="HTTP timeout seconds (RPC/IPFS).")
    p.add_argument("--tx-hash", default=None, help="Analyze a specific submitReportData tx hash (skips log scanning).")
    p.add_argument(
        "--ipfs-gateway",
        action="append",
        default=[],
        help="IPFS gateway base/prefix (repeatable). Defaults to a small public list.",
    )
    p.add_argument("--out-csv", default=None, help="Optional: write a per-vault per-report CSV to this path.")
    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    args = _parse_args(argv)

    try:
        from web3 import Web3  # type: ignore[import-not-found]
    except ImportError as ex:  # pragma: no cover
        print("Missing dependency. Run: uv sync", file=sys.stderr)
        raise SystemExit(2) from ex

    rpc_candidates = [args.rpc_url] if args.rpc_url else _default_rpc_urls(os.getenv("ETH_RPC_URL"))
    w3: Web3 | None = None
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

    oracle_addr = Web3.to_checksum_address(args.accounting_oracle)
    contract = w3.eth.contract(address=oracle_addr, abi=ACCOUNTING_ORACLE_MIN_ABI)

    gateways = tuple(args.ipfs_gateway) if args.ipfs_gateway else DEFAULT_IPFS_GATEWAYS

    submissions: list[ReportSubmission]
    if args.tx_hash:
        tx = w3.eth.get_transaction(args.tx_hash)
        ref_slot, root_hex, cid, simulated_share_rate = _decode_submit_report_data_tx(contract, tx["input"])
        block = w3.eth.get_block(int(tx["blockNumber"]))
        submissions = [
            ReportSubmission(
                ref_slot=ref_slot,
                block_number=int(tx["blockNumber"]),
                block_timestamp=int(block["timestamp"]),
                tx_hash=args.tx_hash,
                vaults_tree_root=root_hex,
                vaults_tree_cid=cid,
                simulated_share_rate=simulated_share_rate,
            )
        ]
    else:
        submissions = _collect_recent_report_submissions(
            w3,
            contract,
            oracle_addr,
            want_reports=max(1, int(args.reports)) if args.reports is not None else None,
            days=max(1, int(args.days)),
            blocks_per_day=max(1, int(args.blocks_per_day)),
            log_chunk_size=max(100, int(args.log_chunk_size)),
        )

        if not submissions:
            print("No submitReportData transactions found in the scanned range.", file=sys.stderr)
            return 1

    # Download + parse reports.
    snapshots: list[dict[str, VaultSnapshot]] = []
    for sub in submissions:
        raw = _fetch_ipfs_bytes(sub.vaults_tree_cid, gateways, timeout_s=args.timeout)
        report_json = _parse_ipfs_report(raw)
        snapshots.append(_parse_report_to_snapshots(report_json))

    # Print a header with extracted CIDs.
    print("\n🔗 IPFS Report Sources (latest first):")
    print("─" * 70)
    for i, sub in enumerate(submissions):
        ts = datetime.fromtimestamp(sub.block_timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        marker = "📍" if i == 0 else "  "
        print(f"{marker} {ts}  •  refSlot={sub.ref_slot}")
        print(f"   CID: {sub.vaults_tree_cid}")
    print("")

    # Show screenshot-style summary for latest report + delta vs previous.
    cur_sub = submissions[0]
    cur_snap = snapshots[0]
    prev_snap = snapshots[1] if len(snapshots) > 1 else None
    _print_current_and_delta(cur_sub, cur_snap, prev_snap)

    if args.out_csv:
        _write_csv(args.out_csv, submissions, snapshots)
        print(f"\n💾 CSV exported: {args.out_csv}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

