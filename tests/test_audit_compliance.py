from vaults_economics.formatters import as_int
from vaults_economics.parsing import parse_report_to_snapshots


def test_parse_report_strict_compliance() -> None:
    """Validates parsing against a realistic IPFS report JSON structure."""

    # Simulate a JSON payload matching the IPFS report format

    report_json = {
        "format": "standard-v1",
        "tree": ["0x..."],
        "values": [
            {
                "value": [
                    "0xVaultAddress1",  # 0: vaultAddress
                    "1000000000000000000",  # 1: totalValueWei (1 ETH) - often string in JSON if large
                    200,  # 2: fee (int)
                    "500000000000000000",  # 3: liabilityShares (0.5 stETH shares)
                    "600000000000000000",  # 4: maxLiabilityShares (0.6 stETH shares)
                    0,  # 5: slashingReserve
                ],
                "treeIndex": 0,
            }
        ],
        "leafIndexToData": {
            "vaultAddress": 0,
            "totalValueWei": 1,
            "fee": 2,
            "liabilityShares": 3,
            "maxLiabilityShares": 4,
            "slashingReserve": 5,
        },
        "extraValues": {
            "0xvaultaddress1": {  # keys can be lowercased or checksummed
                "inOutDelta": "-500",  # str
                "prevFee": "100",  # str
                "infraFee": "50",  # str
                "liquidityFee": "50",  # str
                "reservationFee": "0",  # str
            }
        },
    }

    # 2. Parse
    snapshots = parse_report_to_snapshots(report_json)

    # 3. Verify
    assert "0xvaultaddress1" in snapshots
    s = snapshots["0xvaultaddress1"]

    # Verify values
    assert s.vault == "0xVaultAddress1"
    assert s.total_value_wei == 10**18
    assert s.cumulative_lido_fees_wei == 200
    assert s.liability_shares == 5 * 10**17
    assert s.max_liability_shares == 6 * 10**17
    assert s.slashing_reserve_wei == 0

    # Verify extra values (parsed from strings to ints)
    assert s.in_out_delta_wei == -500
    assert s.prev_cumulative_lido_fees_wei == 100
    assert s.infra_fee_wei == 50
    assert s.liquidity_fee_wei == 50
    assert s.reservation_fee_wei == 0


def test_as_int_robustness() -> None:
    """Challenge as_int with various types found in wild JSONs."""
    assert as_int("123") == 123
    assert as_int("0x10") == 16
    assert as_int(123) == 123
    assert as_int(None) == 0
    assert as_int("-500") == -500  # Important for inOutDelta
    assert as_int("  10  ") == 10
