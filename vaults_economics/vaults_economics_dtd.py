#!/usr/bin/env python3
"""
Standalone: Vault economics day-to-date analysis from Lido AccountingOracle daily reports (Ethereum mainnet).

What it does
- Finds recent AccountingOracle daily reports by scanning `ProcessingStarted(uint256,bytes32)` logs.
- For each log's transaction, decodes `submitReportData(data, contractVersion)` input.
- Extracts `data.vaultsDataTreeCid` (an IPFS CID pointing to a JSON Merkle-tree dump).
- Downloads the JSON from IPFS gateways and validates report invariants (format/root checks, fee consistency,
  maxLiabilityShares >= liabilityShares, non-negative fee components).
- Prints per-vault economics + delta vs previous/first report + aggregates summary.

Validation
By default, the script validates:
- Fee consistency: cumulative_lido_fees_wei == prevFee + infraFee + liquidityFee + reservationFee
- maxLiabilityShares >= liabilityShares (contract invariant)
- Cumulative fees are non-decreasing across reports (for same vault, when prevFee matches the prior report)
- Non-negative values for total value, fee components, fees, shares, and slashing reserve
- Report metadata sanity (tree root + format when present)

Use --no-validate to skip validation (useful for debugging corrupted reports).

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
from typing import TYPE_CHECKING, Any, Iterable

if TYPE_CHECKING:
    from web3 import Web3  # pragma: no cover

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

STANDARD_MERKLE_TREE_FORMAT = "standard-v1"

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
    # `total_value_wei` is the value *reported in the IPFS Merkle tree leaf* for the given refSlot.
    # Note: on-chain, LazyOracle may quarantine part of a sudden increase and apply a smaller value.
    total_value_wei: int
    # `in_out_delta_wei` is a cumulative counter (all deposits - all withdrawals) tracked on-chain by VaultHub.
    in_out_delta_wei: int
    # Cumulative Lido protocol fees accrued on the vault (as of refSlot), in wei.
    cumulative_lido_fees_wei: int
    # Previous cumulative Lido fees (from extraValues.prevFee), in wei.
    prev_cumulative_lido_fees_wei: int
    infra_fee_wei: int
    liquidity_fee_wei: int
    reservation_fee_wei: int
    # Current stETH liability nominated in shares (as of refSlot).
    liability_shares: int
    # High-water mark of liability shares within the oracle period (as of refSlot).
    # This is NOT a minting capacity / share limit; it is used to compute `locked` on-chain.
    max_liability_shares: int
    slashing_reserve_wei: int


def _fee_delta_wei(s: VaultSnapshot) -> int:
    """Calculate fee delta (fees accrued this report period)."""
    return s.infra_fee_wei + s.liquidity_fee_wei + s.reservation_fee_wei


def _validate_vault_snapshot(s: VaultSnapshot, *, ref_slot: int, vault_key: str, warn_only: bool = False) -> list[str]:
    """
    Validate vault snapshot invariants.

    Returns list of validation warnings/errors. If warn_only=False, raises ValueError on critical errors.
    """
    issues: list[str] = []

    # 1. Fee consistency: cumulative == prev + infra + liquidity + reservation
    expected_cumulative = s.prev_cumulative_lido_fees_wei + _fee_delta_wei(s)
    if s.cumulative_lido_fees_wei != expected_cumulative:
        msg = (
            f"Vault {s.vault} (refSlot={ref_slot}): fee inconsistency: "
            f"cumulative={s.cumulative_lido_fees_wei} != "
            f"prev({s.prev_cumulative_lido_fees_wei}) + delta({_fee_delta_wei(s)}) = {expected_cumulative}"
        )
        issues.append(msg)
        if not warn_only:
            raise ValueError(msg)

    # 2. maxLiabilityShares >= liabilityShares (contract enforces this)
    if s.max_liability_shares < s.liability_shares:
        msg = (
            f"Vault {s.vault} (refSlot={ref_slot}): invalid maxLiabilityShares: "
            f"{s.max_liability_shares} < {s.liability_shares} (contract invariant violation)"
        )
        issues.append(msg)
        if not warn_only:
            raise ValueError(msg)

    # 3. Non-negative values (all uint256 on-chain fields)
    non_negative_fields = {
        "totalValueWei": s.total_value_wei,
        "cumulativeLidoFees": s.cumulative_lido_fees_wei,
        "prevFee": s.prev_cumulative_lido_fees_wei,
        "infraFee": s.infra_fee_wei,
        "liquidityFee": s.liquidity_fee_wei,
        "reservationFee": s.reservation_fee_wei,
        "liabilityShares": s.liability_shares,
        "maxLiabilityShares": s.max_liability_shares,
        "slashingReserve": s.slashing_reserve_wei,
    }
    for name, value in non_negative_fields.items():
        if value < 0:
            msg = f"Vault {s.vault} (refSlot={ref_slot}): negative {name}: {value}"
            issues.append(msg)
            if not warn_only:
                raise ValueError(msg)

    return issues


def _validate_cross_report_consistency(
    prev_snap: dict[str, VaultSnapshot],
    cur_snap: dict[str, VaultSnapshot],
    *,
    prev_ref_slot: int,
    cur_ref_slot: int,
    warn_only: bool = True,
) -> list[str]:
    """
    Validate consistency across reports (e.g., cumulative fees are non-decreasing).

    Returns list of warnings. By default, only warns (doesn't raise) since vaults can disconnect/reconnect.
    """
    issues: list[str] = []

    for key in set(prev_snap.keys()) & set(cur_snap.keys()):
        prev = prev_snap[key]
        cur = cur_snap[key]

        # Cumulative fees should be non-decreasing when prevFee matches the prior report.
        if cur.prev_cumulative_lido_fees_wei != prev.cumulative_lido_fees_wei:
            if cur.prev_cumulative_lido_fees_wei == 0 and prev.cumulative_lido_fees_wei > 0:
                msg = (
                    f"Vault {cur.vault}: prevFee reset detected (likely reconnect): "
                    f"prevFee=0, previous cumulative={prev.cumulative_lido_fees_wei} (refSlot={prev_ref_slot})"
                )
            else:
                msg = (
                    f"Vault {cur.vault}: prevFee mismatch: "
                    f"{cur.prev_cumulative_lido_fees_wei} (refSlot={cur_ref_slot}) != "
                    f"{prev.cumulative_lido_fees_wei} (refSlot={prev_ref_slot})"
                )
            issues.append(msg)
            if not warn_only:
                raise ValueError(msg)
            continue

        if cur.cumulative_lido_fees_wei < prev.cumulative_lido_fees_wei:
            msg = (
                f"Vault {cur.vault}: cumulative fees decreased: "
                f"{prev.cumulative_lido_fees_wei} (refSlot={prev_ref_slot}) → "
                f"{cur.cumulative_lido_fees_wei} (refSlot={cur_ref_slot})"
            )
            issues.append(msg)
            if not warn_only:
                raise ValueError(msg)

    return issues


def _zero_snapshot(vault: str) -> VaultSnapshot:
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


@dataclass(frozen=True)
class VaultAggregates:
    vaults_total: int
    vaults_active: int
    vaults_passive: int
    vaults_slashing_reserve: int

    mode_unlevered: int
    mode_below_peak: int
    mode_at_peak: int

    total_value_wei: int
    in_out_delta_wei: int
    cumulative_lido_fees_wei: int
    lido_fees_this_report_wei: int
    infra_fee_wei: int
    liquidity_fee_wei: int
    reservation_fee_wei: int
    liability_shares: int
    max_liability_shares: int
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


def _normalize_hex_str(value: Any) -> str:
    if isinstance(value, (bytes, bytearray)):
        return f"0x{value.hex()}"
    if hasattr(value, "hex") and not isinstance(value, str):
        hex_str = value.hex()
        return hex_str if hex_str.startswith("0x") else f"0x{hex_str}"
    s = str(value).strip()
    if s.lower().startswith("0x"):
        return f"0x{s[2:]}"
    return f"0x{s}"


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
    """Returns (emoji, mode_description).

    Important: `max_liability_shares` is a *high-water mark* within the oracle period, not a capacity.
    """
    if s.liability_shares == 0:
        return "🌱", "Unlevered"
    if s.max_liability_shares > s.liability_shares:
        return "⚡", "Below Peak (cooldown)"
    return "🔥", "At Peak (locked)"


def _vault_status(s: VaultSnapshot) -> tuple[str, str, str]:
    """Returns (emoji, status, action_hint)."""
    if s.slashing_reserve_wei > 0:
        return "🟠", "Slashing Reserve", "⚠️  Slashing reserve locked — monitor validator penalties"
    if s.liability_shares == 0:
        return "💤", "Passive", "No action needed — no stETH is minted against this vault"
    if s.max_liability_shares > s.liability_shares:
        return (
            "🟡",
            "Active (Below Peak)",
            "Liability decreased since the period peak — `locked` may still be based on the peak until next report",
        )
    return "🟢", "Active (At Peak)", "Liability is at the period peak — `locked` is based on this value"


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


def _validate_ipfs_report_metadata(
    report_json: dict[str, Any],
    *,
    expected_ref_slot: int | None = None,
    expected_tree_root: str | None = None,
    warn_only: bool = True,
) -> list[str]:
    issues: list[str] = []

    report_format = report_json.get("format")
    if report_format and report_format != STANDARD_MERKLE_TREE_FORMAT:
        msg = f"Unexpected report format: {report_format} (expected {STANDARD_MERKLE_TREE_FORMAT})"
        issues.append(msg)
        if not warn_only:
            raise ValueError(msg)

    if expected_ref_slot is not None and "refSlot" in report_json:
        report_ref_slot = _as_int(report_json.get("refSlot"))
        if report_ref_slot != expected_ref_slot:
            msg = f"Report refSlot mismatch: report={report_ref_slot}, expected={expected_ref_slot}"
            issues.append(msg)
            if not warn_only:
                raise ValueError(msg)

    tree = report_json.get("tree") or []
    if expected_tree_root and tree:
        report_root = _normalize_hex_str(tree[0]).lower()
        expected_root = _normalize_hex_str(expected_tree_root).lower()
        if report_root != expected_root:
            msg = f"Report tree root mismatch: report={report_root}, expected={expected_root}"
            issues.append(msg)
            if not warn_only:
                raise ValueError(msg)

    return issues


def _parse_report_to_snapshots(
    report_json: dict[str, Any], *, ref_slot: int | None = None, validate: bool = True
) -> dict[str, VaultSnapshot]:
    """
    Parse IPFS report JSON into VaultSnapshot dict.

    Args:
        report_json: IPFS report JSON (Merkle tree dump)
        ref_slot: Reference slot for validation messages (optional)
        validate: If True, validate invariants (fee consistency, maxLiabilityShares >= liabilityShares)

    Returns:
        Dict mapping vault address (lowercase) to VaultSnapshot
    """
    extra_values_raw = report_json.get("extraValues", {}) or {}
    extra_by_vault = {str(k).lower(): v for k, v in extra_values_raw.items()}

    # Newer reports include a schema map for the Merkle leaf tuple.
    leaf_index_to_data = report_json.get("leafIndexToData") or {}
    try:
        idx_vault = int(leaf_index_to_data.get("vaultAddress", 0))
        idx_total_value = int(leaf_index_to_data.get("totalValueWei", 1))
        idx_fee = int(leaf_index_to_data.get("fee", 2))
        idx_liability = int(leaf_index_to_data.get("liabilityShares", 3))
        idx_max_liability = int(leaf_index_to_data.get("maxLiabilityShares", 4))
        idx_slashing_reserve = int(leaf_index_to_data.get("slashingReserve", 5))
    except Exception:  # pylint: disable=broad-exception-caught
        # Fallback to the current canonical order.
        idx_vault, idx_total_value, idx_fee, idx_liability, idx_max_liability, idx_slashing_reserve = 0, 1, 2, 3, 4, 5

    out: dict[str, VaultSnapshot] = {}
    validation_issues: list[str] = []

    for entry in report_json.get("values", []) or []:
        # Each entry leaf encodes:
        # (vault, totalValueWei, cumulativeLidoFees, liabilityShares, maxLiabilityShares, slashingReserve)
        value = entry.get("value")
        if not isinstance(value, (list, tuple)):
            continue
        need_len = max(idx_vault, idx_total_value, idx_fee, idx_liability, idx_max_liability, idx_slashing_reserve) + 1
        if len(value) < need_len:
            continue

        vault = str(value[idx_vault])
        key = vault.lower()
        extra = extra_by_vault.get(key) or {}

        snapshot = VaultSnapshot(
            vault=vault,
            total_value_wei=_as_int(value[idx_total_value]),
            cumulative_lido_fees_wei=_as_int(value[idx_fee]),
            liability_shares=_as_int(value[idx_liability]),
            max_liability_shares=_as_int(value[idx_max_liability]),
            slashing_reserve_wei=_as_int(value[idx_slashing_reserve]),
            in_out_delta_wei=_as_int(extra.get("inOutDelta")),
            prev_cumulative_lido_fees_wei=_as_int(extra.get("prevFee")),
            infra_fee_wei=_as_int(extra.get("infraFee")),
            liquidity_fee_wei=_as_int(extra.get("liquidityFee")),
            reservation_fee_wei=_as_int(extra.get("reservationFee")),
        )

        if validate:
            issues = _validate_vault_snapshot(snapshot, ref_slot=ref_slot or 0, vault_key=key, warn_only=True)
            validation_issues.extend(issues)

        out[key] = snapshot

    if validation_issues:
        print("⚠️  Validation warnings:", file=sys.stderr)
        for issue in validation_issues:
            print(f"   {issue}", file=sys.stderr)

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

        logs.sort(
            key=lambda x: (
                _hex_to_int(x["blockNumber"]),
                _hex_to_int(x["transactionIndex"]),
                _hex_to_int(x["logIndex"]),
            )
        )

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


def _print_current_report(
    current: ReportSubmission,
    cur_snap: dict[str, VaultSnapshot],
) -> None:
    ts = datetime.fromtimestamp(current.block_timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print("=" * 70)
    print("📊 VAULT ECONOMICS REPORT")
    print(f"   🕐 {ts}  •  refSlot={current.ref_slot}")
    print("=" * 70)

    for _, s in sorted(cur_snap.items(), key=lambda kv: kv[1].vault.lower()):
        status_emoji, status_text, action_hint = _vault_status(s)
        mode_emoji, mode_text = _economic_mode(s)

        print(f"\n{status_emoji} Vault: {s.vault}")
        print(f"   Status: {status_text}  •  Mode: {mode_emoji} {mode_text}")
        print("   " + "─" * 50)

        # Financials
        print(f"   💰 Total Value (reported): {_format_eth(s.total_value_wei, decimals=2, approx=True)}")
        print(f"   🔁 In/Out Delta (cumulative): {_format_eth(s.in_out_delta_wei, decimals=6)}")

        # Fees breakdown
        print("   💸 Lido Fees:")
        fee_delta_wei = _fee_delta_wei(s)
        print(f"      • Total (cumulative): {_format_wei_sci(s.cumulative_lido_fees_wei)} wei")
        print(f"      • This report:        {_format_wei_sci(fee_delta_wei)} wei")
        print(f"         - Infra:       {_format_wei_sci(s.infra_fee_wei)} wei")
        liq_indicator = "🔴" if s.liquidity_fee_wei > 0 else "⚪"
        print(f"         - Liquidity:   {liq_indicator} {_format_wei_sci(s.liquidity_fee_wei)} wei")
        if s.reservation_fee_wei:
            print(f"         - Reservation: {_format_wei_sci(s.reservation_fee_wei)} wei")
        if s.prev_cumulative_lido_fees_wei:
            print(f"      • Prev total:       {_format_wei_sci(s.prev_cumulative_lido_fees_wei)} wei")

        # Liability (shares)
        print("   📊 Liability (shares):")
        liab_wei = _shares_to_wei(s.liability_shares, current.simulated_share_rate)
        liab_hint = _format_eth(liab_wei, decimals=6, approx=True) if current.simulated_share_rate else "n/a"
        print(f"      • Current (refSlot): {_format_wei_sci(s.liability_shares)} shares  ({liab_hint})")
        peak_wei = _shares_to_wei(s.max_liability_shares, current.simulated_share_rate)
        peak_hint = _format_eth(peak_wei, decimals=6, approx=True) if current.simulated_share_rate else "n/a"
        print(f"      • Peak (period):     {_format_wei_sci(s.max_liability_shares)} shares  ({peak_hint})")
        if s.max_liability_shares > s.liability_shares:
            below_peak_shares = s.max_liability_shares - s.liability_shares
            below_peak_wei = _shares_to_wei(below_peak_shares, current.simulated_share_rate)
            below_peak_hint = (
                _format_eth(below_peak_wei, decimals=6, approx=True) if current.simulated_share_rate else "n/a"
            )
            print(f"      • Below peak by:     {_format_wei_sci(below_peak_shares)} shares  ({below_peak_hint})")
        print(f"      • Slashing reserve: {_format_wei_sci(s.slashing_reserve_wei)} wei")

        # Action hint
        print(f"\n   💡 {action_hint}")

    _print_peak_help()


def _print_peak_help() -> None:
    print(
        "\nℹ️ Peak (period) = `maxLiabilityShares`: the max liability shares the vault reached in the current oracle period."
    )
    print(
        "   VaultHub computes on-chain `locked` using this high-water mark, so a vault can be 'Below Peak (cooldown)' after burning shares."
    )


def _compute_aggregates(snap: dict[str, VaultSnapshot]) -> VaultAggregates:
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
        lido_fees_this_report_wei += _fee_delta_wei(s)
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


def _print_changes_section(
    *,
    title: str,
    current: ReportSubmission,
    cur_snap: dict[str, VaultSnapshot],
    baseline: ReportSubmission,
    base_snap: dict[str, VaultSnapshot],
) -> None:
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
            base = _zero_snapshot(cur.vault)
        elif is_missing:
            cur = _zero_snapshot(base.vault)

        # NOTE: now both exist for printing/diffs
        assert cur is not None  # noqa: S101
        assert base is not None  # noqa: S101

        base_fee_delta_wei = _fee_delta_wei(base)
        cur_fee_delta_wei = _fee_delta_wei(cur)

        changed = (
            is_new
            or is_missing
            or base.cumulative_lido_fees_wei != cur.cumulative_lido_fees_wei
            or base_fee_delta_wei != cur_fee_delta_wei
            or base.liquidity_fee_wei != cur.liquidity_fee_wei
            or base.liability_shares != cur.liability_shares
            or base.max_liability_shares != cur.max_liability_shares
        )
        if not changed:
            unchanged += 1
            continue

        printed += 1
        mode_emoji, mode_text = _economic_mode(cur)
        fee_total_delta = _delta_indicator(base.cumulative_lido_fees_wei, cur.cumulative_lido_fees_wei)
        fee_delta = _delta_indicator(base_fee_delta_wei, cur_fee_delta_wei)
        liq_delta = _delta_indicator(base.liquidity_fee_wei, cur.liquidity_fee_wei)

        print(f"\n🔹 {cur.vault}")
        print("   " + "─" * 50)
        if is_new:
            print("   🆕 New vault (not present in baseline report)")
        elif is_missing:
            print("   🕳️ Missing in current report (present in baseline report)")

        print(
            f"   {fee_total_delta} Total Lido Fees (cumulative): {_format_wei_sci(base.cumulative_lido_fees_wei)} → {_format_wei_sci(cur.cumulative_lido_fees_wei)} wei"
        )
        print(
            f"   {fee_delta} Fee (this report):          {_format_wei_sci(base_fee_delta_wei)} → {_format_wei_sci(cur_fee_delta_wei)} wei"
        )
        print(
            f"   {liq_delta} Liquidity Fee (this report): {_format_wei_sci(base.liquidity_fee_wei)} → {_format_wei_sci(cur.liquidity_fee_wei)} wei"
        )

        if base.liability_shares == cur.liability_shares:
            print("   ➡️  Liability (shares): Unchanged")
        else:
            liab_delta = _delta_indicator(base.liability_shares, cur.liability_shares)
            print(
                f"   {liab_delta} Liability (shares): {_format_shares(base.liability_shares)} → {_format_shares(cur.liability_shares)}"
            )

        if base.max_liability_shares == cur.max_liability_shares:
            print("   ➡️  Peak liability (shares): Unchanged")
        else:
            peak_delta = _delta_indicator(base.max_liability_shares, cur.max_liability_shares)
            print(
                f"   {peak_delta} Peak liability (shares): {_format_shares(base.max_liability_shares)} → {_format_shares(cur.max_liability_shares)}"
            )

        print(f"   {mode_emoji} Mode:           {mode_text}")

    if printed == 0:
        print("\nℹ️ No changes detected in the tracked metrics.")
    elif unchanged > 0:
        print(f"\nℹ️ {unchanged} vault(s) unchanged in the tracked metrics (omitted).")


def _print_aggregates_section(
    *,
    current: ReportSubmission,
    cur_snap: dict[str, VaultSnapshot],
    prev: tuple[ReportSubmission, dict[str, VaultSnapshot]] | None,
    first: tuple[ReportSubmission, dict[str, VaultSnapshot]] | None,
) -> None:
    cur_agg = _compute_aggregates(cur_snap)
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
    print(f"💰 Total Value (reported): {_format_eth(cur_agg.total_value_wei, decimals=2, approx=True)}")
    print(f"🔁 In/Out Delta (cumulative): {_format_eth(cur_agg.in_out_delta_wei, decimals=6)}")

    print("💸 Lido Fees:")
    print(f"   • Total (cumulative): {_format_wei_sci(cur_agg.cumulative_lido_fees_wei)} wei")
    print(f"   • This report:        {_format_wei_sci(cur_agg.lido_fees_this_report_wei)} wei")
    print(f"      - Infra:       {_format_wei_sci(cur_agg.infra_fee_wei)} wei")
    print(f"      - Liquidity:   {_format_wei_sci(cur_agg.liquidity_fee_wei)} wei")
    if cur_agg.reservation_fee_wei:
        print(f"      - Reservation: {_format_wei_sci(cur_agg.reservation_fee_wei)} wei")

    print("📊 Liability (shares):")
    liab_wei = _shares_to_wei(cur_agg.liability_shares, current.simulated_share_rate)
    liab_hint = _format_eth(liab_wei, decimals=6, approx=True) if current.simulated_share_rate else "n/a"
    print(f"   • Current (refSlot): {_format_wei_sci(cur_agg.liability_shares)} shares  ({liab_hint})")
    peak_wei = _shares_to_wei(cur_agg.max_liability_shares, current.simulated_share_rate)
    peak_hint = _format_eth(peak_wei, decimals=6, approx=True) if current.simulated_share_rate else "n/a"
    print(f"   • Peak (period):     {_format_wei_sci(cur_agg.max_liability_shares)} shares  ({peak_hint})")
    print(f"🛡️ Slashing reserve (total): {_format_wei_sci(cur_agg.slashing_reserve_wei)} wei")

    def _print_agg_delta(label: str, base_sub: ReportSubmission, base_snap: dict[str, VaultSnapshot]) -> None:
        base_agg = _compute_aggregates(base_snap)
        print(f"\n📈 Aggregates change {label}:")
        print(
            f"   💰 Total Value (reported): {_format_eth(base_agg.total_value_wei, decimals=2, approx=True)} → {_format_eth(cur_agg.total_value_wei, decimals=2, approx=True)}"
        )
        print(
            f"   🔁 In/Out Delta (cumulative): {_format_eth(base_agg.in_out_delta_wei, decimals=6)} → {_format_eth(cur_agg.in_out_delta_wei, decimals=6)}"
        )
        print(
            f"   💸 Total Lido Fees (cumulative): {_format_wei_sci(base_agg.cumulative_lido_fees_wei)} → {_format_wei_sci(cur_agg.cumulative_lido_fees_wei)} wei"
        )
        print(
            f"   📊 Liability (shares): {_format_shares(base_agg.liability_shares)} → {_format_shares(cur_agg.liability_shares)}"
        )

    if prev is not None:
        _print_agg_delta("since last report", prev[0], prev[1])
    if first is not None:
        _print_agg_delta("since first report", first[0], first[1])


def _print_report_with_deltas(submissions: list[ReportSubmission], snapshots: list[dict[str, VaultSnapshot]]) -> None:
    current = submissions[0]
    cur_snap = snapshots[0]
    prev = (submissions[1], snapshots[1]) if len(submissions) > 1 else None
    first = (submissions[-1], snapshots[-1]) if len(submissions) > 1 else None

    _print_current_report(current, cur_snap)

    if prev is not None:
        _print_changes_section(
            title="📈 CHANGES SINCE LAST REPORT",
            current=current,
            cur_snap=cur_snap,
            baseline=prev[0],
            base_snap=prev[1],
        )

    if first is not None:
        # Avoid duplicating the previous-report comparison when only 2 reports are available.
        if len(submissions) > 2:
            _print_changes_section(
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

    _print_aggregates_section(
        current=current, cur_snap=cur_snap, prev=prev, first=first if len(submissions) > 2 else None
    )


def _write_csv(path: str, submissions: list[ReportSubmission], snapshots: list[dict[str, VaultSnapshot]]) -> None:
    rows: list[dict[str, Any]] = []
    for sub, snap in zip(submissions, snapshots):
        date = datetime.fromtimestamp(sub.block_timestamp, tz=timezone.utc).date().isoformat()
        for s in snap.values():
            fee_delta_wei = _fee_delta_wei(s)
            rows.append(
                {
                    "date_utc": date,
                    "ref_slot": sub.ref_slot,
                    "block_number": sub.block_number,
                    "tx_hash": sub.tx_hash,
                    "simulated_share_rate": sub.simulated_share_rate,
                    "vault": s.vault,
                    "total_value_wei": s.total_value_wei,
                    "in_out_delta_wei": s.in_out_delta_wei,
                    "cumulative_lido_fees_wei": s.cumulative_lido_fees_wei,
                    "prev_cumulative_lido_fees_wei": s.prev_cumulative_lido_fees_wei,
                    "lido_fees_delta_wei": fee_delta_wei,
                    "infra_fee_wei": s.infra_fee_wei,
                    "liquidity_fee_wei": s.liquidity_fee_wei,
                    "reservation_fee_wei": s.reservation_fee_wei,
                    "liability_shares": s.liability_shares,
                    "max_liability_shares": s.max_liability_shares,
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
        "--log-chunk-size", type=int, default=20_000, help="Block chunk size for eth_getLogs (default: 20000)."
    )
    p.add_argument("--timeout", type=int, default=30, help="HTTP timeout seconds (RPC/IPFS).")
    p.add_argument("--tx-hash", default=None, help="Analyze a specific submitReportData tx hash (skips log scanning).")
    p.add_argument(
        "--ipfs-gateway",
        action="append",
        default=[],
        help="IPFS gateway base/prefix (repeatable). Defaults to a small public list.",
    )
    p.add_argument("--out-csv", default=None, help="Optional: write a per-vault per-report CSV to this path.")
    p.add_argument(
        "--no-validate",
        action="store_true",
        help="Skip validation of report invariants (fee consistency, maxLiabilityShares >= liabilityShares, etc.)",
    )
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
        if not args.no_validate:
            meta_issues = _validate_ipfs_report_metadata(
                report_json,
                expected_ref_slot=sub.ref_slot,
                expected_tree_root=sub.vaults_tree_root,
                warn_only=True,
            )
            if meta_issues:
                print("⚠️  IPFS report metadata warnings:", file=sys.stderr)
                for issue in meta_issues:
                    print(f"   {issue}", file=sys.stderr)
        snapshots.append(_parse_report_to_snapshots(report_json, ref_slot=sub.ref_slot, validate=not args.no_validate))

        # Validate simulated_share_rate (should be > 0 for meaningful conversions)
        if sub.simulated_share_rate <= 0:
            print(
                f"⚠️  Warning: refSlot={sub.ref_slot} has invalid simulatedShareRate: {sub.simulated_share_rate}",
                file=sys.stderr,
            )

    # Cross-report validation: cumulative fees should be non-decreasing (older → newer)
    if len(snapshots) > 1 and not args.no_validate:
        for i in range(len(snapshots) - 1):
            # Compare older (i+1) to newer (i) report
            issues = _validate_cross_report_consistency(
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
    _print_report_with_deltas(submissions, snapshots)

    if args.out_csv:
        _write_csv(args.out_csv, submissions, snapshots)
        print(f"\n💾 CSV exported: {args.out_csv}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
