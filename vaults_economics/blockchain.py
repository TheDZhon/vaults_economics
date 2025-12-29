"""Blockchain data fetching with caching."""

import sys
from typing import TYPE_CHECKING, Any, Iterable

from tqdm import tqdm

from vaults_economics.cache import cache_key, get_cached, set_cached
from vaults_economics.constants import FIRST_VAULT_REPORT_BLOCK
from vaults_economics.formatters import as_int, normalize_hex_str
from vaults_economics.models import ReportSubmission
from vaults_economics.parsing import decode_submit_report_data_tx

if TYPE_CHECKING:
    from web3 import Web3  # pragma: no cover


def topic0(w3: "Web3", signature: str) -> str:
    """Compute topic0 (event signature hash) for a function/event signature."""
    from web3 import Web3  # pylint: disable=import-outside-toplevel

    return normalize_hex_str(Web3.keccak(text=signature))


def iter_block_ranges(start: int, end: int, chunk_size: int) -> Iterable[tuple[int, int]]:
    """Iterate over block ranges in chunks."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be > 0")
    cur = start
    while cur <= end:
        yield cur, min(end, cur + chunk_size - 1)
        cur += chunk_size


def get_cached_logs(w3: "Web3", filter_params: dict[str, Any], use_cache: bool = True) -> list[dict[str, Any]]:
    """Get logs with caching."""
    if not use_cache:
        response = w3.provider.make_request("eth_getLogs", [filter_params])
        if "error" in response:
            raise RuntimeError(f"RPC error: {response['error']}")
        return response.get("result", [])

    # Create cache key from filter params
    key = cache_key(
        "logs",
        filter_params.get("address", ""),
        filter_params.get("fromBlock", ""),
        filter_params.get("toBlock", ""),
        str(filter_params.get("topics", [])),
    )
    cached = get_cached(key)
    if cached is not None:
        return cached

    # Fetch from RPC
    response = w3.provider.make_request("eth_getLogs", [filter_params])
    if "error" in response:
        raise RuntimeError(f"RPC error: {response['error']}")
    result = response.get("result", [])
    set_cached(key, result)
    return result


def get_cached_transaction(w3: "Web3", tx_hash: str, use_cache: bool = True) -> dict[str, Any]:
    """Get transaction with caching. Returns a dict for consistent access."""
    key = cache_key("tx", tx_hash)
    if use_cache:
        cached = get_cached(key)
        if cached is not None:
            return cached

    tx = w3.eth.get_transaction(tx_hash)
    # Convert HexBytes to hex strings for JSON serialization
    tx_dict = dict(tx)
    for key_name, value in tx_dict.items():
        if hasattr(value, "hex"):
            tx_dict[key_name] = normalize_hex_str(value)
    if use_cache:
        set_cached(key, tx_dict)
    return tx_dict


def get_cached_block(w3: "Web3", block_identifier: int | str, use_cache: bool = True) -> dict[str, Any]:
    """Get block with caching. Returns a dict for consistent access."""
    key = cache_key("block", str(block_identifier))
    if use_cache:
        cached = get_cached(key)
        if cached is not None:
            return cached

    block = w3.eth.get_block(block_identifier)
    # Convert HexBytes to hex strings for JSON serialization
    block_dict = dict(block)
    for key_name, value in block_dict.items():
        if hasattr(value, "hex"):
            block_dict[key_name] = normalize_hex_str(value)
        elif isinstance(value, list):
            # Handle list of transactions
            block_dict[key_name] = [
                (normalize_hex_str(tx) if hasattr(tx, "hex") else str(tx)) if not isinstance(tx, dict) else tx
                for tx in value
            ]
    if use_cache:
        set_cached(key, block_dict)
    return block_dict


def get_latest_report_from_lazy_oracle(
    w3: "Web3",
    lazy_oracle_contract,
) -> tuple[int, int, str, str]:
    """
    Get the latest report data directly from LazyOracle.latestReportData().

    Returns: (timestamp, ref_slot, tree_root_hex, report_cid)
    """
    timestamp, ref_slot, tree_root, report_cid = lazy_oracle_contract.functions.latestReportData().call()
    return int(timestamp), int(ref_slot), normalize_hex_str(tree_root), str(report_cid)


def collect_recent_report_submissions(
    w3: "Web3",
    contract,
    oracle_address: str,
    *,
    want_reports: int | None,
    days: int,
    blocks_per_day: int,
    log_chunk_size: int,
    use_cache: bool = True,
) -> list[ReportSubmission]:
    """Collect recent report submissions. If want_reports is None, collect all in the scanned range."""
    topic0_sig = topic0(w3, "ProcessingStarted(uint256,bytes32)")

    latest_block = int(w3.eth.block_number)
    window = max(1, int(days) * int(blocks_per_day))

    collected: list[ReportSubmission] = []
    seen_ref_slots: set[int] = set()

    # Never scan below the first vault report block - no reports exist before it
    earliest_block = FIRST_VAULT_REPORT_BLOCK

    scan_end = latest_block
    scan_start = max(earliest_block, scan_end - window + 1)
    ranges = list(iter_block_ranges(scan_start, scan_end, log_chunk_size))
    oracle_addr = normalize_hex_str(oracle_address)

    with tqdm(total=len(ranges), desc="🔍 Scanning blockchain logs", unit="chunk", file=sys.stderr) as pbar:
        logs: list[dict[str, Any]] = []
        for a, b in ranges:
            # Use provider.make_request to completely bypass web3.py middleware
            # Some RPC providers (like drpc.live) require proper hex formatting.
            filter_params = {
                "address": oracle_addr,
                "fromBlock": hex(a),
                "toBlock": hex(b),
                "topics": [topic0_sig],
            }
            logs.extend(get_cached_logs(w3, filter_params, use_cache=use_cache))
            pbar.update(1)

        # Raw JSON-RPC response has hex strings; normalize for sorting
        logs.sort(
            key=lambda x: (
                as_int(x["blockNumber"]),
                as_int(x["transactionIndex"]),
                as_int(x["logIndex"]),
            )
        )

        # Work backwards to get the latest reports first.
        pbar.set_description(f"🔍 Processing {len(logs)} logs")
        for log in reversed(logs):
            tx_hash_hex = normalize_hex_str(log["transactionHash"])
            tx = get_cached_transaction(w3, tx_hash_hex, use_cache=use_cache)
            try:
                ref_slot, root_hex, cid, simulated_share_rate = decode_submit_report_data_tx(contract, tx["input"])
            except Exception:  # pylint: disable=broad-exception-caught
                continue

            if ref_slot in seen_ref_slots:
                continue
            seen_ref_slots.add(ref_slot)

            block = get_cached_block(w3, int(tx["blockNumber"]), use_cache=use_cache)
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
            pbar.set_postfix(found=len(collected))

            if want_reports is not None and len(collected) >= want_reports:
                break

    return collected
