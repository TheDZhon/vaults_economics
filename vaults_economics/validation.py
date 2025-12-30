"""Validation logic for reports and vaults."""

from typing import Any

from vaults_economics.constants import STANDARD_MERKLE_TREE_FORMAT
from vaults_economics.models import VaultSnapshot
from vaults_economics.reports import fee_delta_wei


def validate_vault_snapshot(s: VaultSnapshot, *, ref_slot: int, _vault_key: str, warn_only: bool = False) -> list[str]:
    """
    Validate vault snapshot invariants.

    Returns list of validation warnings/errors. If warn_only=False, raises ValueError on critical errors.
    """
    issues: list[str] = []

    # 1. Fee consistency: cumulative == prev + infra + liquidity + reservation
    expected_cumulative = s.prev_cumulative_lido_fees_wei + fee_delta_wei(s)
    if s.cumulative_lido_fees_wei != expected_cumulative:
        msg = (
            f"Vault {s.vault} (refSlot={ref_slot}): fee inconsistency: "
            f"cumulative={s.cumulative_lido_fees_wei} != "
            f"prev({s.prev_cumulative_lido_fees_wei}) + delta({fee_delta_wei(s)}) = {expected_cumulative}"
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


def validate_cross_report_consistency(
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


def validate_ipfs_report_metadata(
    report_json: dict[str, Any],
    *,
    expected_ref_slot: int | None = None,
    expected_tree_root: str | None = None,
    warn_only: bool = True,
) -> list[str]:
    """
    Validate IPFS report metadata (format, refSlot, tree root).

    Returns list of warnings. By default, only warns (doesn't raise).
    """
    issues: list[str] = []

    fmt = report_json.get("format")
    if fmt and fmt != STANDARD_MERKLE_TREE_FORMAT:
        msg = f"Unexpected report format: {fmt} (expected {STANDARD_MERKLE_TREE_FORMAT})"
        issues.append(msg)
        if not warn_only:
            raise ValueError(msg)

    if expected_ref_slot is not None:
        report_ref_slot = report_json.get("refSlot")
        if report_ref_slot is not None and int(report_ref_slot) != expected_ref_slot:
            msg = f"refSlot mismatch: report={report_ref_slot}, expected={expected_ref_slot}"
            issues.append(msg)
            if not warn_only:
                raise ValueError(msg)

    if expected_tree_root is not None:
        report_root = report_json.get("tree")
        if report_root:
            # tree can be a list or a single root
            root_str = str(report_root[0] if isinstance(report_root, list) else report_root)
            expected_normalized = expected_tree_root.lower().strip()
            if root_str.lower().strip() != expected_normalized:
                msg = f"Tree root mismatch: report={root_str}, expected={expected_tree_root}"
                issues.append(msg)
                if not warn_only:
                    raise ValueError(msg)

    return issues
