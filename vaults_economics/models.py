"""Data models for vault economics analysis."""

from dataclasses import dataclass


@dataclass(frozen=True)
class LidoContracts:
    """Container for Lido protocol contract addresses resolved from LidoLocator."""

    locator: str
    accounting_oracle: str
    lazy_oracle: str
    vault_hub: str
    lido: str


@dataclass(frozen=True)
class ReportSubmission:
    """Represents a single AccountingOracle report submission."""

    ref_slot: int
    block_number: int
    block_timestamp: int
    tx_hash: str
    vaults_tree_root: str
    vaults_tree_cid: str
    simulated_share_rate: int


@dataclass(frozen=True)
class VaultSnapshot:
    """Snapshot of a vault's state from an oracle report."""

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


@dataclass(frozen=True)
class OnchainVaultMetrics:
    """On-chain metrics for a vault fetched from LazyOracle/VaultHub."""

    vault: str
    aggregated_balance_wei: int
    reserve_ratio_bp: int
    forced_rebalance_threshold_bp: int
    share_limit: int
    mintable_steth_wei: int
    pending_disconnect: bool
    onchain_total_value_wei: int
    locked_wei: int
    withdrawable_wei: int
    obligations_shares: int
    unsettled_lido_fees_wei: int
    is_healthy: bool


@dataclass(frozen=True)
class VaultAggregates:
    """Aggregated metrics across all vaults."""

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
