"""Report parsing and decoding."""

import json
import sys
from typing import Any

from vaults_economics.formatters import as_int, normalize_hex_str
from vaults_economics.models import VaultSnapshot
from vaults_economics.validation import validate_vault_snapshot


def parse_ipfs_report(raw_bytes: bytes) -> dict[str, Any]:
    """Parse IPFS report JSON from raw bytes."""
    data = json.loads(raw_bytes.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Unexpected IPFS report format (expected JSON object)")
    return data


def parse_report_to_snapshots(
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
            total_value_wei=as_int(value[idx_total_value]),
            cumulative_lido_fees_wei=as_int(value[idx_fee]),
            liability_shares=as_int(value[idx_liability]),
            max_liability_shares=as_int(value[idx_max_liability]),
            slashing_reserve_wei=as_int(value[idx_slashing_reserve]),
            in_out_delta_wei=as_int(extra.get("inOutDelta")),
            prev_cumulative_lido_fees_wei=as_int(extra.get("prevFee")),
            infra_fee_wei=as_int(extra.get("infraFee")),
            liquidity_fee_wei=as_int(extra.get("liquidityFee")),
            reservation_fee_wei=as_int(extra.get("reservationFee")),
        )

        if validate:
            issues = validate_vault_snapshot(snapshot, ref_slot=ref_slot or 0, vault_key=key, warn_only=True)
            validation_issues.extend(issues)

        out[key] = snapshot

    if validation_issues:
        print("⚠️  Validation warnings:", file=sys.stderr)
        for issue in validation_issues:
            print(f"   {issue}", file=sys.stderr)

    return out


def parse_lazy_oracle_vault_info(entry: Any) -> dict[str, Any]:
    """Parse LazyOracle batchVaultsInfo entry.

    VaultInfo struct fields (14 total) from actual contract:
        0: vault (address)
        1: aggregatedBalance (uint256)
        2: inOutDelta (int256) - signed!
        3: withdrawalCredentials (bytes32)
        4: liabilityShares (uint256)
        5: maxLiabilityShares (uint256)
        6: mintableStETH (uint256)
        7: shareLimit (uint96)
        8: reserveRatioBP (uint16)
        9: forcedRebalanceThresholdBP (uint16)
        10: infraFeeBP (uint16)
        11: liquidityFeeBP (uint16)
        12: reservationFeeBP (uint16)
        13: pendingDisconnect (bool)
    """
    if isinstance(entry, dict):
        return {
            "vault": entry.get("vault"),
            "aggregatedBalance": entry.get("aggregatedBalance"),
            "inOutDelta": entry.get("inOutDelta"),
            "withdrawalCredentials": entry.get("withdrawalCredentials"),
            "liabilityShares": entry.get("liabilityShares"),
            "maxLiabilityShares": entry.get("maxLiabilityShares"),
            "mintableStETH": entry.get("mintableStETH"),
            "shareLimit": entry.get("shareLimit"),
            "reserveRatioBP": entry.get("reserveRatioBP"),
            "forcedRebalanceThresholdBP": entry.get("forcedRebalanceThresholdBP"),
            "infraFeeBP": entry.get("infraFeeBP"),
            "liquidityFeeBP": entry.get("liquidityFeeBP"),
            "reservationFeeBP": entry.get("reservationFeeBP"),
            "pendingDisconnect": entry.get("pendingDisconnect"),
        }
    # Tuple format (web3.py may decode as tuple)
    return {
        "vault": entry[0] if len(entry) > 0 else None,
        "aggregatedBalance": entry[1] if len(entry) > 1 else None,
        "inOutDelta": entry[2] if len(entry) > 2 else None,
        "withdrawalCredentials": entry[3] if len(entry) > 3 else None,
        "liabilityShares": entry[4] if len(entry) > 4 else None,
        "maxLiabilityShares": entry[5] if len(entry) > 5 else None,
        "mintableStETH": entry[6] if len(entry) > 6 else None,
        "shareLimit": entry[7] if len(entry) > 7 else None,
        "reserveRatioBP": entry[8] if len(entry) > 8 else None,
        "forcedRebalanceThresholdBP": entry[9] if len(entry) > 9 else None,
        "infraFeeBP": entry[10] if len(entry) > 10 else None,
        "liquidityFeeBP": entry[11] if len(entry) > 11 else None,
        "reservationFeeBP": entry[12] if len(entry) > 12 else None,
        "pendingDisconnect": entry[13] if len(entry) > 13 else None,
    }


def decode_submit_report_data_tx(contract, tx_input: str) -> tuple[int, str, str, int]:
    """
    Decode submitReportData transaction input.

    Returns: (ref_slot, vaults_tree_root_hex, vaults_tree_cid, simulated_share_rate)
    """
    fn, args = contract.decode_function_input(tx_input)
    if fn.fn_name != "submitReportData":
        raise ValueError(f"Unexpected function: {fn.fn_name}")

    data = args["data"]

    # web3.py may decode tuples into dict-like or plain tuples depending on version/config.
    if isinstance(data, dict):
        ref_slot = as_int(data.get("refSlot"))
        root = data.get("vaultsDataTreeRoot")
        cid = str(data.get("vaultsDataTreeCid") or "")
        simulated_share_rate = as_int(data.get("simulatedShareRate"))
    else:
        # ABI component order is fixed (see ACCOUNTING_ORACLE_MIN_ABI).
        ref_slot = as_int(data[1])
        simulated_share_rate = as_int(data[10])
        root = data[12]
        cid = str(data[13])

    if not cid:
        raise ValueError("Empty vaultsDataTreeCid decoded from tx input")

    root_hex = root.hex() if hasattr(root, "hex") else str(root)
    if not root_hex.startswith("0x"):
        root_hex = f"0x{root_hex}"
    return ref_slot, root_hex, cid, simulated_share_rate
