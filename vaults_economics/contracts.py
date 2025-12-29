"""Contract interaction functions."""

from typing import TYPE_CHECKING

from vaults_economics.constants import (
    LIDO_LOCATOR_ABI,
    LIDO_STETH_MIN_ABI,
    SHARE_RATE_SCALE,
)
from vaults_economics.models import LidoContracts

if TYPE_CHECKING:
    from web3 import Web3  # pragma: no cover


def resolve_lido_contracts(w3: "Web3", locator_address: str) -> LidoContracts:
    """
    Resolve all Lido contract addresses from LidoLocator.

    This follows the pattern from lido-staking-vault-cli where LidoLocator is the single
    entry point for resolving all protocol contract addresses.
    """
    locator = w3.eth.contract(
        address=w3.to_checksum_address(locator_address),
        abi=LIDO_LOCATOR_ABI,
    )

    accounting_oracle = locator.functions.accountingOracle().call()
    lazy_oracle = locator.functions.lazyOracle().call()
    vault_hub = locator.functions.vaultHub().call()
    lido = locator.functions.lido().call()

    return LidoContracts(
        locator=locator_address,
        accounting_oracle=accounting_oracle,
        lazy_oracle=lazy_oracle,
        vault_hub=vault_hub,
        lido=lido,
    )


def calculate_share_rate(w3: "Web3", lido_address: str, *, block_identifier: int | str = "latest") -> int:
    """
    Calculate the share rate from Lido stETH contract: (totalSupply * 1e27) / getTotalShares.

    This follows the pattern from lido-staking-vault-cli/utils/share-rate.ts.
    Returns the share rate as a ray (1e27 scale).
    """
    lido_contract = w3.eth.contract(
        address=w3.to_checksum_address(lido_address),
        abi=LIDO_STETH_MIN_ABI,
    )
    total_supply = lido_contract.functions.totalSupply().call(block_identifier=block_identifier)
    total_shares = lido_contract.functions.getTotalShares().call(block_identifier=block_identifier)
    if total_shares == 0:
        return 0
    return int((total_supply * SHARE_RATE_SCALE) // total_shares)
