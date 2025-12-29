import json
from pathlib import Path

import pytest

from vaults_economics.vaults_economics_dtd import (
    ACCOUNTING_ORACLE_MIN_ABI,
    DEFAULT_PUBLIC_ETH_RPC_URLS,
    VaultSnapshot,
    _as_int,
    _build_gateway_url,
    _decode_submit_report_data_tx,
    _default_rpc_urls,
    _economic_mode,
    _format_eth,
    _format_shares,
    _format_wei_sci,
    _parse_report_to_snapshots,
    _vault_status,
)


def test_build_gateway_url_variants():
    cid = "bafybeigdyrztw"
    assert _build_gateway_url("https://ipfs.io/ipfs/", cid) == f"https://ipfs.io/ipfs/{cid}"
    assert _build_gateway_url("https://ipfs.io/ipfs", cid) == f"https://ipfs.io/ipfs/{cid}"
    assert _build_gateway_url("https://ipfs.io", cid) == f"https://ipfs.io/ipfs/{cid}"
    assert _build_gateway_url("https://gateway.pinata.cloud/ipfs/", cid) == f"https://gateway.pinata.cloud/ipfs/{cid}"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, 0),
        (True, 1),
        (False, 0),
        (5, 5),
        ("5", 5),
        ("  5  ", 5),
        ("0x10", 16),
    ],
)
def test_as_int(value, expected):
    assert _as_int(value) == expected


def test_format_wei_sci():
    assert _format_wei_sci(0) == "0"
    assert _format_wei_sci(1000) == "1e3"
    assert _format_wei_sci(16900000000000) == "1.69e13"
    assert _format_wei_sci(-1000) == "-1e3"


def test_format_eth_and_shares():
    assert _format_eth(10**18) == "1 ETH"
    assert _format_eth(10**18, approx=True).startswith("~")
    assert _format_shares(10**18) == "1 shares"


def test_parse_report_to_snapshots_parses_values_and_extra_values_case_insensitive():
    report_json = {
        "values": [
            {"value": ["0xAbC", "0x10", 5, 0, 0, 1]},
            {"value": ["0xDeF", 0, 0, 1, 2, 3]},
        ],
        "extraValues": {
            "0xabc": {
                "inOutDelta": "0x2",
                "prevFee": 0,
                "infraFee": 11,
                "liquidityFee": 22,
                "reservationFee": 33,
            }
        },
    }

    snaps = _parse_report_to_snapshots(report_json)
    assert set(snaps.keys()) == {"0xabc", "0xdef"}
    s_abc = snaps["0xabc"]
    assert s_abc.vault == "0xAbC"
    assert s_abc.tvl_wei == 16
    assert s_abc.total_fees_wei == 5
    assert s_abc.liabilities_shares == 0
    assert s_abc.max_liabilities_shares == 0
    assert s_abc.slashing_reserve_wei == 1
    assert s_abc.net_inflow_wei == 2
    assert s_abc.prev_fee_wei == 0
    assert s_abc.infra_fee_wei == 11
    assert s_abc.liquidity_fee_wei == 22
    assert s_abc.reservation_fee_wei == 33


@pytest.mark.parametrize(
    "fixture_name",
    [
        "vault_report_sample_0xb1168ee90b001b3e04e76618a085c9dbb7eddb1415f462c839c6728110a4b86f.json",
        "vault_report_sample_0xc79165e96f1d3267ef86f0c3d0156a2d060167f76c2549072b670eea9d16cc72.json",
    ],
)
def test_parse_report_to_snapshots_from_known_ipfs_samples(fixture_name):
    fixtures_dir = Path(__file__).resolve().parent / "fixtures"
    path = fixtures_dir / fixture_name
    assert path.exists(), f"Missing fixture file: {path}"

    data = json.loads(path.read_text(encoding="utf-8"))
    sample = data["report_sample"]
    expected = data["expected_snapshots"]

    snaps = _parse_report_to_snapshots(sample)
    assert set(expected.keys()).issubset(set(snaps.keys()))

    for vault_key, exp in expected.items():
        s = snaps[vault_key]
        assert s.vault == exp["vault"]
        assert s.tvl_wei == exp["tvl_wei"]
        assert s.net_inflow_wei == exp["net_inflow_wei"]
        assert s.total_fees_wei == exp["total_fees_wei"]
        assert s.prev_fee_wei == exp["prev_fee_wei"]
        assert s.infra_fee_wei == exp["infra_fee_wei"]
        assert s.liquidity_fee_wei == exp["liquidity_fee_wei"]
        assert s.reservation_fee_wei == exp["reservation_fee_wei"]
        assert s.liabilities_shares == exp["liabilities_shares"]
        assert s.max_liabilities_shares == exp["max_liabilities_shares"]
        assert s.slashing_reserve_wei == exp["slashing_reserve_wei"]


def test_economic_mode_and_status_emojis():
    base = VaultSnapshot(
        vault="0xVault",
        tvl_wei=0,
        net_inflow_wei=0,
        total_fees_wei=0,
        prev_fee_wei=0,
        infra_fee_wei=0,
        liquidity_fee_wei=0,
        reservation_fee_wei=0,
        liabilities_shares=0,
        max_liabilities_shares=0,
        slashing_reserve_wei=0,
    )

    assert _economic_mode(base) == ("🌱", "Unlevered")
    assert _vault_status(base)[0] == "💤"

    building = VaultSnapshot(**{**base.__dict__, "liabilities_shares": 1, "max_liabilities_shares": 2})
    assert _economic_mode(building) == ("⚡", "Partially Leveraged")
    assert _vault_status(building)[0] == "🟢"

    maxed_no_liq = VaultSnapshot(**{**base.__dict__, "liabilities_shares": 2, "max_liabilities_shares": 2})
    assert _economic_mode(maxed_no_liq) == ("🔥", "Steady-State Leveraged")
    assert _vault_status(maxed_no_liq)[0] == "🟡"

    maxed_liq = VaultSnapshot(**{**base.__dict__, "liabilities_shares": 2, "max_liabilities_shares": 2, "liquidity_fee_wei": 1})
    assert _vault_status(maxed_liq)[0] == "🔴"

    slashing = VaultSnapshot(**{**base.__dict__, "slashing_reserve_wei": 1})
    assert _vault_status(slashing)[0] == "🟠"


def test_default_rpc_urls_order_and_dedup():
    env = "https://example.invalid"
    urls = _default_rpc_urls(env)
    assert urls[0] == env
    assert list(DEFAULT_PUBLIC_ETH_RPC_URLS) == urls[1:]
    assert _default_rpc_urls(None) == list(DEFAULT_PUBLIC_ETH_RPC_URLS)


@pytest.mark.parametrize(
    "fixture_name",
    [
        "submitReportData_tx_0xb1168ee90b001b3e04e76618a085c9dbb7eddb1415f462c839c6728110a4b86f.json",
        "submitReportData_tx_0xc79165e96f1d3267ef86f0c3d0156a2d060167f76c2549072b670eea9d16cc72.json",
    ],
)
def test_decode_submit_report_data_known_mainnet_txs(fixture_name):
    fixtures_dir = Path(__file__).resolve().parent / "fixtures"
    path = fixtures_dir / fixture_name
    assert path.exists(), f"Missing fixture file: {path}"

    data = json.loads(path.read_text(encoding="utf-8"))
    tx_input = data["tx_input"]
    expected = data["expected"]

    from web3 import Web3

    w3 = Web3()
    contract = w3.eth.contract(
        address=Web3.to_checksum_address("0x0000000000000000000000000000000000000000"),
        abi=ACCOUNTING_ORACLE_MIN_ABI,
    )

    ref_slot, root_hex, cid, simulated_share_rate = _decode_submit_report_data_tx(contract, tx_input)
    assert ref_slot == expected["ref_slot"]
    assert root_hex == expected["vaults_tree_root"]
    assert cid == expected["vaults_tree_cid"]
    assert simulated_share_rate > 0

