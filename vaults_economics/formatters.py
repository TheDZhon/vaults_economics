"""Formatting and conversion utilities."""

from decimal import Decimal

from vaults_economics.constants import (
    CONNECT_DEPOSIT_WEI,
    DAYS_PER_YEAR,
    SHARE_RATE_SCALE,
    SHARE_SCALE,
    TOTAL_BASIS_POINTS,
    WEI_PER_ETH,
)
from vaults_economics.models import VaultSnapshot


def as_int(value, *, default: int = 0) -> int:
    """Convert value to int, handling various types."""
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


def normalize_hex_str(value) -> str:
    """Normalize hex string to 0x-prefixed format."""
    if isinstance(value, (bytes, bytearray)):
        return f"0x{value.hex()}"
    if hasattr(value, "hex") and not isinstance(value, str):
        hex_str = value.hex()
        return hex_str if hex_str.startswith("0x") else f"0x{hex_str}"
    s = str(value).strip()
    if s.lower().startswith("0x"):
        return f"0x{s[2:]}"
    return f"0x{s}"


def ceil_div(numer: int, denom: int) -> int:
    """Ceiling division."""
    if denom == 0:
        raise ZeroDivisionError("denom must be > 0")
    return (numer + denom - 1) // denom


def format_bp(bp: int) -> str:
    """Format basis points as percentage."""
    return f"{(Decimal(bp) / Decimal(100)):.2f}%"


def format_wei_sci(value: int, *, sig: int = 3) -> str:
    """Format wei value in scientific notation."""
    if value == 0:
        return "0"
    s = format(Decimal(abs(value)), f".{max(0, sig - 1)}e")  # 1.69e+13
    mant, exp = s.split("e")
    mant = mant.rstrip("0").rstrip(".")
    exp_i = int(exp)
    sign = "-" if value < 0 else ""
    return f"{sign}{mant}e{exp_i}"


def format_eth(value_wei: int, *, decimals: int = 9, approx: bool = False) -> str:
    """Format wei value as ETH."""
    eth = Decimal(value_wei) / WEI_PER_ETH
    s = f"{eth:.{decimals}f}".rstrip("0").rstrip(".")
    prefix = "~" if approx else ""
    return f"{prefix}{s} ETH"


def format_shares(value: int, *, decimals: int = 3) -> str:
    """Format shares value."""
    shares = Decimal(value) / SHARE_SCALE
    s = f"{shares:.{decimals}f}".rstrip("0").rstrip(".")
    return f"{s} shares"


def annual_projection_wei(daily_fee_wei: int) -> int:
    """Project daily fees to annual (assuming same fee every day)."""
    return daily_fee_wei * DAYS_PER_YEAR


def format_annual_projection(daily_fee_wei: int, *, decimals: int = 4) -> str:
    """Format projected annual revenue from daily fee."""
    annual_wei = annual_projection_wei(daily_fee_wei)
    eth = Decimal(annual_wei) / WEI_PER_ETH
    s = f"{eth:.{decimals}f}".rstrip("0").rstrip(".")
    return f"~{s} ETH/yr"


def shares_to_wei(shares: int, simulated_share_rate: int) -> int:
    """Convert Lido shares to wei using simulatedShareRate (ray, 1e27)."""
    if shares <= 0 or simulated_share_rate <= 0:
        return 0
    return int((shares * simulated_share_rate) // SHARE_RATE_SCALE)


def locked_value_wei(
    liability_shares: int, minimal_reserve_wei: int, reserve_ratio_bp: int, simulated_share_rate: int
) -> int:
    """Calculate locked value in wei."""
    if liability_shares <= 0:
        return minimal_reserve_wei
    liability_wei = shares_to_wei(liability_shares, simulated_share_rate)
    if reserve_ratio_bp >= TOTAL_BASIS_POINTS:
        return liability_wei + minimal_reserve_wei
    reserve_wei = ceil_div(liability_wei * reserve_ratio_bp, TOTAL_BASIS_POINTS - reserve_ratio_bp)
    return liability_wei + max(reserve_wei, minimal_reserve_wei)


def economic_mode(s: VaultSnapshot) -> tuple[str, str]:
    """Returns (emoji, mode_description).

    Important: `max_liability_shares` is a *high-water mark* within the oracle period, not a capacity.
    """
    if s.liability_shares == 0:
        return "🌱", "Unlevered"
    if s.max_liability_shares > s.liability_shares:
        return "⚡", "Below Peak (cooldown)"
    return "🔥", "At Peak (locked)"


def vault_status(s: VaultSnapshot) -> tuple[str, str, str]:
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


def delta_indicator(prev_val: int, cur_val: int) -> str:
    """Returns emoji indicator for value change."""
    if cur_val > prev_val:
        return "📈"
    if cur_val < prev_val:
        return "📉"
    return "➡️"
