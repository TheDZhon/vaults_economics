"""Onchain data fetching from LazyOracle/VaultHub."""

import sys
from typing import TYPE_CHECKING, Any, Iterable

from vaults_economics.constants import LAZY_ORACLE_MIN_ABI, VAULT_HUB_MIN_ABI
from vaults_economics.formatters import as_int
from vaults_economics.models import OnchainVaultMetrics
from vaults_economics.parsing import parse_lazy_oracle_vault_info

if TYPE_CHECKING:
    from web3 import Web3  # pragma: no cover


def fetch_lazy_oracle_vaults(contract, *, block_identifier: int | str, page_size: int) -> dict[str, dict[str, Any]]:
    """Fetch all vault info from LazyOracle in batches."""
    vaults_count = contract.functions.vaultsCount().call(block_identifier=block_identifier)
    out: dict[str, dict[str, Any]] = {}
    for offset in range(0, vaults_count, page_size):
        batch = contract.functions.batchVaultsInfo(offset, page_size).call(block_identifier=block_identifier)
        for entry in batch:
            info = parse_lazy_oracle_vault_info(entry)
            vault = str(info["vault"])
            out[vault.lower()] = info
    return out


def collect_onchain_metrics(
    w3: "Web3",
    lazy_oracle_contract,
    vault_hub_contract,
    vault_keys: Iterable[str],
    *,
    block_identifier: int | str,
    page_size: int,
    use_cache: bool = True,
) -> dict[str, OnchainVaultMetrics]:
    """Collect onchain metrics for vaults from LazyOracle and VaultHub."""
    from vaults_economics.cache import cache_key, get_cached, set_cached

    # Check cache for onchain metrics
    if use_cache:
        vault_keys_sorted = sorted(vault_keys)
        key = cache_key("onchain_metrics", str(block_identifier), str(page_size), ":".join(vault_keys_sorted))
        cached = get_cached(key)
        if cached is not None:
            # Convert cached dict back to OnchainVaultMetrics objects
            return {k: OnchainVaultMetrics(**v) for k, v in cached.items()}

    lazy_info = fetch_lazy_oracle_vaults(lazy_oracle_contract, block_identifier=block_identifier, page_size=page_size)
    out: dict[str, OnchainVaultMetrics] = {}

    for key in vault_keys:
        info = lazy_info.get(key)
        if not info:
            continue
        vault_addr = w3.to_checksum_address(info["vault"])

        # Most fields now come directly from batchVaultsInfo
        # Only isVaultHealthy still needs a separate call
        try:
            is_healthy = vault_hub_contract.functions.isVaultHealthy(vault_addr).call(
                block_identifier=block_identifier
            )
        except Exception as ex:  # pylint: disable=broad-exception-caught
            print(f"⚠️  isVaultHealthy failed for {vault_addr}: {ex}", file=sys.stderr)
            is_healthy = True  # Default to healthy if call fails

        out[key] = OnchainVaultMetrics(
            vault=info["vault"],
            aggregated_balance_wei=as_int(info["aggregatedBalance"]),
            reserve_ratio_bp=as_int(info["reserveRatioBP"]),
            forced_rebalance_threshold_bp=as_int(info["forcedRebalanceThresholdBP"]),
            share_limit=as_int(info["shareLimit"]),
            mintable_steth_wei=as_int(info["mintableStETH"]),
            pending_disconnect=bool(info["pendingDisconnect"]),
            onchain_total_value_wei=as_int(info["totalValue"]),
            locked_wei=as_int(info["locked"]),
            withdrawable_wei=as_int(info["withdrawable"]),
            obligations_shares=as_int(info["obligationsShares"]),
            unsettled_lido_fees_wei=as_int(info["unsettledLidoFees"]),
            is_healthy=bool(is_healthy),
        )

    # Cache the result
    if use_cache:
        vault_keys_sorted = sorted(vault_keys)
        key = cache_key("onchain_metrics", str(block_identifier), str(page_size), ":".join(vault_keys_sorted))
        # Convert dataclass to dict for caching
        cache_data = {k: v.__dict__ for k, v in out.items()}
        set_cached(key, cache_data)

    return out
