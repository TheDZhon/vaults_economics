import json
from pathlib import Path

import pytest

from vaults_economics.vaults_economics_dtd import (
    ACCOUNTING_ORACLE_MIN_ABI,
    DEFAULT_PUBLIC_ETH_RPC_URLS,
    ReportSubmission,
    VaultSnapshot,
    _as_int,
    _build_gateway_url,
    _compute_aggregates,
    _decode_submit_report_data_tx,
    _default_rpc_urls,
    _economic_mode,
    _fee_delta_wei,
    _format_eth,
    _format_shares,
    _format_wei_sci,
    _parse_report_to_snapshots,
    _print_changes_section,
    _print_report_with_deltas,
    _validate_cross_report_consistency,
    _validate_ipfs_report_metadata,
    _validate_vault_snapshot,
    _vault_status,
    _zero_snapshot,
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
    assert s_abc.total_value_wei == 16
    assert s_abc.cumulative_lido_fees_wei == 5
    assert s_abc.liability_shares == 0
    assert s_abc.max_liability_shares == 0
    assert s_abc.slashing_reserve_wei == 1
    assert s_abc.in_out_delta_wei == 2
    assert s_abc.prev_cumulative_lido_fees_wei == 0
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
        assert s.total_value_wei == exp["total_value_wei"]
        assert s.in_out_delta_wei == exp["in_out_delta_wei"]
        assert s.cumulative_lido_fees_wei == exp["cumulative_lido_fees_wei"]
        assert s.prev_cumulative_lido_fees_wei == exp["prev_cumulative_lido_fees_wei"]
        assert s.infra_fee_wei == exp["infra_fee_wei"]
        assert s.liquidity_fee_wei == exp["liquidity_fee_wei"]
        assert s.reservation_fee_wei == exp["reservation_fee_wei"]
        assert s.liability_shares == exp["liability_shares"]
        assert s.max_liability_shares == exp["max_liability_shares"]
        assert s.slashing_reserve_wei == exp["slashing_reserve_wei"]


def test_validate_ipfs_report_metadata_flags_mismatches():
    report_json = {
        "format": "standard-v1",
        "tree": ["0xabc"],
        "refSlot": 10,
    }

    assert (
        _validate_ipfs_report_metadata(report_json, expected_ref_slot=10, expected_tree_root="0xAbC", warn_only=True)
        == []
    )

    issues = _validate_ipfs_report_metadata(
        report_json,
        expected_ref_slot=11,
        expected_tree_root="0xdef",
        warn_only=True,
    )
    assert any("refslot mismatch" in issue.lower() for issue in issues)
    assert any("tree root mismatch" in issue.lower() for issue in issues)

    issues = _validate_ipfs_report_metadata(
        {"format": "unknown-v0"},
        expected_ref_slot=None,
        expected_tree_root=None,
        warn_only=True,
    )
    assert any("unexpected report format" in issue.lower() for issue in issues)


def test_economic_mode_and_status_emojis():
    base = VaultSnapshot(
        vault="0xVault",
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

    assert _economic_mode(base) == ("🌱", "Unlevered")
    assert _vault_status(base)[0] == "💤"

    below_peak = VaultSnapshot(**{**base.__dict__, "liability_shares": 1, "max_liability_shares": 2})
    assert _economic_mode(below_peak) == ("⚡", "Below Peak (cooldown)")
    assert _vault_status(below_peak)[0] == "🟡"

    at_peak = VaultSnapshot(**{**base.__dict__, "liability_shares": 2, "max_liability_shares": 2})
    assert _economic_mode(at_peak) == ("🔥", "At Peak (locked)")
    assert _vault_status(at_peak)[0] == "🟢"

    at_peak_with_liq_fee = VaultSnapshot(
        **{**base.__dict__, "liability_shares": 2, "max_liability_shares": 2, "liquidity_fee_wei": 1}
    )
    assert _vault_status(at_peak_with_liq_fee)[0] == "🟢"

    slashing = VaultSnapshot(**{**base.__dict__, "slashing_reserve_wei": 1})
    assert _vault_status(slashing)[0] == "🟠"


def test_default_rpc_urls_order_and_dedup():
    env = "https://example.invalid"
    urls = _default_rpc_urls(env)
    assert urls[0] == env
    assert list(DEFAULT_PUBLIC_ETH_RPC_URLS) == urls[1:]
    assert _default_rpc_urls(None) == list(DEFAULT_PUBLIC_ETH_RPC_URLS)


def test_fee_delta_wei_and_zero_snapshot():
    s = _zero_snapshot("0xVault")
    assert s.vault == "0xVault"
    assert _fee_delta_wei(s) == 0


def test_compute_aggregates_counts_and_sums():
    base = _zero_snapshot("0xA")
    passive = VaultSnapshot(**{**base.__dict__, "vault": "0xPassive"})
    at_peak = VaultSnapshot(
        **{
            **base.__dict__,
            "vault": "0xAtPeak",
            "liability_shares": 5,
            "max_liability_shares": 5,
            "infra_fee_wei": 10,
            "liquidity_fee_wei": 20,
            "reservation_fee_wei": 30,
            "cumulative_lido_fees_wei": 123,
            "total_value_wei": 7,
            "in_out_delta_wei": 11,
        }
    )
    slashing = VaultSnapshot(**{**base.__dict__, "vault": "0xSlash", "slashing_reserve_wei": 1})

    agg = _compute_aggregates({"a": passive, "b": at_peak, "c": slashing})
    assert agg.vaults_total == 3
    assert agg.vaults_active == 1
    assert agg.vaults_passive == 1
    assert agg.vaults_slashing_reserve == 1
    assert agg.mode_unlevered == 2
    assert agg.mode_at_peak == 1
    assert agg.mode_below_peak == 0

    assert agg.total_value_wei == 7
    assert agg.in_out_delta_wei == 11
    assert agg.cumulative_lido_fees_wei == 123
    assert agg.lido_fees_this_report_wei == 60
    assert agg.infra_fee_wei == 10
    assert agg.liquidity_fee_wei == 20
    assert agg.reservation_fee_wei == 30
    assert agg.slashing_reserve_wei == 1


def test_print_changes_section_marks_new_vault_and_omits_unchanged(capsys):
    # Baseline has one vault; current adds a new vault (and baseline one stays unchanged).
    base_v = VaultSnapshot(**{**_zero_snapshot("0xOld").__dict__, "vault": "0xOld", "cumulative_lido_fees_wei": 1})
    cur_old = VaultSnapshot(**{**base_v.__dict__})
    cur_new = VaultSnapshot(**{**_zero_snapshot("0xNew").__dict__, "vault": "0xNew", "cumulative_lido_fees_wei": 2})

    baseline = ReportSubmission(
        ref_slot=1,
        block_number=1,
        block_timestamp=1,
        tx_hash="0x0",
        vaults_tree_root="0x0",
        vaults_tree_cid="cid0",
        simulated_share_rate=10**27,
    )
    current = ReportSubmission(
        ref_slot=2,
        block_number=2,
        block_timestamp=2,
        tx_hash="0x1",
        vaults_tree_root="0x1",
        vaults_tree_cid="cid1",
        simulated_share_rate=10**27,
    )

    _print_changes_section(
        title="📈 CHANGES SINCE LAST REPORT",
        current=current,
        cur_snap={"0xold": cur_old, "0xnew": cur_new},
        baseline=baseline,
        base_snap={"0xold": base_v},
    )

    out = capsys.readouterr().out
    assert "📈 CHANGES SINCE LAST REPORT" in out
    assert "🆕 New vault" in out
    assert "0xNew" in out
    assert "unchanged" in out.lower()


def test_print_report_with_deltas_includes_first_report_section_when_three_reports(capsys):
    sub0 = ReportSubmission(
        ref_slot=3,
        block_number=3,
        block_timestamp=3,
        tx_hash="0x3",
        vaults_tree_root="0x3",
        vaults_tree_cid="cid3",
        simulated_share_rate=10**27,
    )
    sub1 = ReportSubmission(
        ref_slot=2,
        block_number=2,
        block_timestamp=2,
        tx_hash="0x2",
        vaults_tree_root="0x2",
        vaults_tree_cid="cid2",
        simulated_share_rate=10**27,
    )
    sub2 = ReportSubmission(
        ref_slot=1,
        block_number=1,
        block_timestamp=1,
        tx_hash="0x1",
        vaults_tree_root="0x1",
        vaults_tree_cid="cid1",
        simulated_share_rate=10**27,
    )

    s0 = {"0xv": VaultSnapshot(**{**_zero_snapshot("0xV").__dict__, "vault": "0xV", "cumulative_lido_fees_wei": 3})}
    s1 = {"0xv": VaultSnapshot(**{**_zero_snapshot("0xV").__dict__, "vault": "0xV", "cumulative_lido_fees_wei": 2})}
    s2 = {"0xv": VaultSnapshot(**{**_zero_snapshot("0xV").__dict__, "vault": "0xV", "cumulative_lido_fees_wei": 1})}

    _print_report_with_deltas([sub0, sub1, sub2], [s0, s1, s2])
    out = capsys.readouterr().out
    assert "📈 CHANGES SINCE FIRST REPORT" in out
    assert "🧾 stVaults AGGREGATES" in out
    assert "Aggregates change since first report" in out


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


def test_validate_vault_snapshot_fee_consistency():
    """Test that fee consistency validation catches mismatches."""
    # Valid: cumulative == prev + infra + liquidity + reservation
    valid = VaultSnapshot(
        vault="0xValid",
        total_value_wei=100,
        in_out_delta_wei=0,
        cumulative_lido_fees_wei=100,  # prev(50) + infra(30) + liq(20) + res(0)
        prev_cumulative_lido_fees_wei=50,
        infra_fee_wei=30,
        liquidity_fee_wei=20,
        reservation_fee_wei=0,
        liability_shares=10,
        max_liability_shares=10,
        slashing_reserve_wei=0,
    )
    issues = _validate_vault_snapshot(valid, ref_slot=1, vault_key="0xvalid", warn_only=True)
    assert len(issues) == 0

    # Invalid: cumulative != prev + delta
    invalid = VaultSnapshot(**{**valid.__dict__, "cumulative_lido_fees_wei": 99})
    issues = _validate_vault_snapshot(invalid, ref_slot=1, vault_key="0xinvalid", warn_only=True)
    assert len(issues) == 1
    assert "fee inconsistency" in issues[0].lower()


def test_validate_vault_snapshot_max_liability_shares():
    """Test that maxLiabilityShares >= liabilityShares validation works."""
    # Valid: max >= liability
    valid = VaultSnapshot(
        vault="0xValid",
        total_value_wei=100,
        in_out_delta_wei=0,
        cumulative_lido_fees_wei=10,
        prev_cumulative_lido_fees_wei=0,
        infra_fee_wei=10,
        liquidity_fee_wei=0,
        reservation_fee_wei=0,
        liability_shares=10,
        max_liability_shares=10,  # equal is OK
        slashing_reserve_wei=0,
    )
    issues = _validate_vault_snapshot(valid, ref_slot=1, vault_key="0xvalid", warn_only=True)
    assert len(issues) == 0

    # Invalid: max < liability
    invalid = VaultSnapshot(**{**valid.__dict__, "max_liability_shares": 9})
    issues = _validate_vault_snapshot(invalid, ref_slot=1, vault_key="0xinvalid", warn_only=True)
    assert len(issues) == 1
    assert "invalid maxliabilityshares" in issues[0].lower()


def test_validate_vault_snapshot_negative_values():
    """Test that negative values are caught."""
    base = _zero_snapshot("0xVault")
    # Negative cumulative fees triggers both fee inconsistency and negative value checks
    invalid = VaultSnapshot(**{**base.__dict__, "cumulative_lido_fees_wei": -1})
    issues = _validate_vault_snapshot(invalid, ref_slot=1, vault_key="0xvault", warn_only=True)
    assert len(issues) >= 1  # At least one issue (may have multiple)
    assert any("negative" in issue.lower() for issue in issues)


def test_validate_cross_report_consistency():
    """Test that cross-report validation catches fee decreases."""
    prev = VaultSnapshot(
        vault="0xVault",
        total_value_wei=100,
        in_out_delta_wei=0,
        cumulative_lido_fees_wei=100,
        prev_cumulative_lido_fees_wei=0,
        infra_fee_wei=100,
        liquidity_fee_wei=0,
        reservation_fee_wei=0,
        liability_shares=0,
        max_liability_shares=0,
        slashing_reserve_wei=0,
    )
    cur_valid = VaultSnapshot(
        **{
            **prev.__dict__,
            "cumulative_lido_fees_wei": 150,
            "prev_cumulative_lido_fees_wei": prev.cumulative_lido_fees_wei,
        }
    )
    cur_invalid = VaultSnapshot(
        **{
            **prev.__dict__,
            "cumulative_lido_fees_wei": 50,
            "prev_cumulative_lido_fees_wei": prev.cumulative_lido_fees_wei,
        }
    )

    # Valid: fees increased
    issues = _validate_cross_report_consistency(
        {"0xvault": prev}, {"0xvault": cur_valid}, prev_ref_slot=1, cur_ref_slot=2, warn_only=True
    )
    assert len(issues) == 0

    # Invalid: fees decreased (contract enforces non-decreasing)
    issues = _validate_cross_report_consistency(
        {"0xvault": prev}, {"0xvault": cur_invalid}, prev_ref_slot=1, cur_ref_slot=2, warn_only=True
    )
    assert len(issues) == 1
    assert "cumulative fees decreased" in issues[0].lower()


def test_validate_cross_report_prev_fee_reset():
    """Test that prevFee resets are flagged and skip non-decreasing checks."""
    prev = VaultSnapshot(
        vault="0xVault",
        total_value_wei=100,
        in_out_delta_wei=0,
        cumulative_lido_fees_wei=100,
        prev_cumulative_lido_fees_wei=0,
        infra_fee_wei=100,
        liquidity_fee_wei=0,
        reservation_fee_wei=0,
        liability_shares=0,
        max_liability_shares=0,
        slashing_reserve_wei=0,
    )
    cur = VaultSnapshot(
        **{
            **prev.__dict__,
            "cumulative_lido_fees_wei": 50,
            "prev_cumulative_lido_fees_wei": 0,
        }
    )

    issues = _validate_cross_report_consistency(
        {"0xvault": prev}, {"0xvault": cur}, prev_ref_slot=1, cur_ref_slot=2, warn_only=True
    )
    assert any("prevfee reset" in issue.lower() for issue in issues)
    assert not any("cumulative fees decreased" in issue.lower() for issue in issues)


def test_parse_report_to_snapshots_validates_by_default():
    """Test that parsing validates by default and warns on issues."""
    import sys
    from io import StringIO

    # Report with fee inconsistency: cumulative=100 but prev(50) + infra(30) + liq(20) + res(0) = 100
    # Actually correct! Let's make it wrong: cumulative=99
    report_json = {
        "values": [
            {
                "value": [
                    "0xVault",
                    "100",
                    "99",  # cumulative (should be 50 + 30 + 20 = 100, but we set it to 99)
                    "10",
                    "10",
                    "0",
                ]
            }
        ],
        "extraValues": {
            "0xvault": {
                "inOutDelta": "0",
                "prevFee": "50",
                "infraFee": "30",
                "liquidityFee": "20",
                "reservationFee": "0",
            }
        },
    }

    # With validation (default): should warn but not raise
    stderr_capture = StringIO()
    old_stderr = sys.stderr
    sys.stderr = stderr_capture
    try:
        snaps = _parse_report_to_snapshots(report_json, ref_slot=1, validate=True)
        assert len(snaps) == 1
        assert "0xvault" in snaps
        # Should have warnings
        stderr_output = stderr_capture.getvalue()
        assert "validation warnings" in stderr_output.lower() or "fee inconsistency" in stderr_output.lower()
    finally:
        sys.stderr = old_stderr

    # Without validation: should parse silently
    sys.stderr = StringIO()
    snaps = _parse_report_to_snapshots(report_json, ref_slot=1, validate=False)
    assert len(snaps) == 1
