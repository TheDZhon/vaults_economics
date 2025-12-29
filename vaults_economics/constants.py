"""Constants and configuration for vault economics analysis."""

from decimal import Decimal

# LidoLocator is the single entry point for resolving all Lido protocol contract addresses.
# Use --locator to override for testnets.
LIDO_LOCATOR_MAINNET = "0xC1d0b3DE6792Bf6b4b37EccdcC24e45978Cfd2Eb"

# Minimal ABI for LidoLocator - only the functions we need to resolve contract addresses.
# Source: https://github.com/lidofinance/lido-staking-vault-cli/blob/main/abi/LidoLocator.ts
LIDO_LOCATOR_ABI: list[dict] = [
    {
        "inputs": [],
        "name": "accountingOracle",
        "outputs": [{"internalType": "address", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "lazyOracle",
        "outputs": [{"internalType": "address", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "vaultHub",
        "outputs": [{"internalType": "address", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "lido",
        "outputs": [{"internalType": "address", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    },
]

# Minimal ABI needed to decode `submitReportData` tx input.
# Source: AccountingOracle ABI on Etherscan (same structure as in Lido oracle codebase).
ACCOUNTING_ORACLE_MIN_ABI: list[dict] = [
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

# Minimal ABI for LazyOracle - functions we need for vault metrics and report data.
# Source: https://github.com/lidofinance/lido-staking-vault-cli/blob/main/abi/LazyOracle.ts
LAZY_ORACLE_MIN_ABI: list[dict] = [
    {
        "type": "function",
        "name": "latestReportData",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [
            {"name": "timestamp", "type": "uint256"},
            {"name": "refSlot", "type": "uint256"},
            {"name": "vaultsDataTreeRoot", "type": "bytes32"},
            {"name": "vaultsDataTreeCid", "type": "string"},
        ],
    },
    {
        "type": "function",
        "name": "vaultsCount",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{"name": "", "type": "uint256"}],
    },
    {
        "type": "function",
        "name": "batchVaultsInfo",
        "stateMutability": "view",
        "inputs": [
            {"name": "offset", "type": "uint256"},
            {"name": "limit", "type": "uint256"},
        ],
        "outputs": [
            {
                "name": "",
                "type": "tuple[]",
                "components": [
                    {"name": "vault", "type": "address"},  # 0
                    {"name": "aggregatedBalance", "type": "uint256"},  # 1
                    {"name": "inOutDelta", "type": "int256"},  # 2
                    {"name": "withdrawalCredentials", "type": "bytes32"},  # 3
                    {"name": "liabilityShares", "type": "uint256"},  # 4
                    {"name": "maxLiabilityShares", "type": "uint256"},  # 5
                    {"name": "mintableStETH", "type": "uint256"},  # 6
                    {"name": "shareLimit", "type": "uint96"},  # 7
                    {"name": "reserveRatioBP", "type": "uint16"},  # 8
                    {"name": "forcedRebalanceThresholdBP", "type": "uint16"},  # 9
                    {"name": "infraFeeBP", "type": "uint16"},  # 10
                    {"name": "liquidityFeeBP", "type": "uint16"},  # 11
                    {"name": "reservationFeeBP", "type": "uint16"},  # 12
                    {"name": "pendingDisconnect", "type": "bool"},  # 13
                ],
            }
        ],
    },
]

# Minimal ABI for VaultHub - functions we need for on-chain vault metrics.
# Source: https://github.com/lidofinance/lido-staking-vault-cli/blob/main/abi/VaultHub.ts
VAULT_HUB_MIN_ABI: list[dict] = [
    {
        "type": "function",
        "name": "totalValue",
        "stateMutability": "view",
        "inputs": [{"name": "_vault", "type": "address"}],
        "outputs": [{"name": "", "type": "uint256"}],
    },
    {
        "type": "function",
        "name": "locked",
        "stateMutability": "view",
        "inputs": [{"name": "_vault", "type": "address"}],
        "outputs": [{"name": "", "type": "uint256"}],
    },
    {
        "type": "function",
        "name": "withdrawableValue",
        "stateMutability": "view",
        "inputs": [{"name": "_vault", "type": "address"}],
        "outputs": [{"name": "", "type": "uint256"}],
    },
    {
        "type": "function",
        "name": "obligations",
        "stateMutability": "view",
        "inputs": [{"name": "_vault", "type": "address"}],
        "outputs": [
            {"name": "sharesToBurn", "type": "uint256"},
            {"name": "feesToSettle", "type": "uint256"},
        ],
    },
    {
        "type": "function",
        "name": "isVaultHealthy",
        "stateMutability": "view",
        "inputs": [{"name": "_vault", "type": "address"}],
        "outputs": [{"name": "", "type": "bool"}],
    },
    {
        "type": "function",
        "name": "liabilityShares",
        "stateMutability": "view",
        "inputs": [{"name": "_vault", "type": "address"}],
        "outputs": [{"name": "", "type": "uint256"}],
    },
    {
        "type": "function",
        "name": "isVaultConnected",
        "stateMutability": "view",
        "inputs": [{"name": "_vault", "type": "address"}],
        "outputs": [{"name": "", "type": "bool"}],
    },
    {
        "type": "function",
        "name": "vaultsCount",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{"name": "", "type": "uint256"}],
    },
]

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

# Minimal ABI for Lido (stETH) - functions we need for share rate calculation.
# Source: https://github.com/lidofinance/lido-staking-vault-cli/blob/main/abi/StEth.ts
LIDO_STETH_MIN_ABI: list[dict] = [
    {
        "type": "function",
        "name": "totalSupply",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{"name": "", "type": "uint256"}],
    },
    {
        "type": "function",
        "name": "getTotalShares",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{"name": "", "type": "uint256"}],
    },
]

STANDARD_MERKLE_TREE_FORMAT = "standard-v1"

WEI_PER_ETH = Decimal(10**18)
CONNECT_DEPOSIT_WEI = 10**18
TOTAL_BASIS_POINTS = 100_00
SHARE_SCALE = Decimal(10**18)
SHARE_RATE_SCALE = 10**27  # Lido simulatedShareRate is a ray (1e27)
DAYS_PER_YEAR = 365  # For annual projections (reports are daily)

# Explorer URLs
ETHERSCAN_BASE = "https://etherscan.io"
BEACONCHA_BASE = "https://beaconcha.in"

# Cache configuration
CACHE_DIR_NAME = ".vaults_economics_cache"
CACHE_VERSION = "1"  # Increment to invalidate all caches
