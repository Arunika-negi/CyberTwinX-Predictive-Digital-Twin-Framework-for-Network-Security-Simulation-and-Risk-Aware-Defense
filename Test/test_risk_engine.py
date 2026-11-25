
from backend.models.asset import Asset
from backend.models.risk import RiskAssessmentRequest
from backend.services.risk_engine import calculate_contextual_risk


def create_request():
    asset = Asset(
        asset_id="SRV-001",
        name="Test Server",
        ip_address="192.168.1.10",
        asset_type="server",
        zone="DMZ",
        criticality=9,
    )

    return RiskAssessmentRequest(
        asset=asset,
        cve_id="CVE-2021-44228",
        cvss_score=10,
        exposure_score=0.8,
        reachable_from_attacker=True,
        attack_path_position=0.7,
        kev_listed=True,
    )


def test_risk_score_is_within_range():
    result = calculate_contextual_risk(create_request())
    assert 0 <= result["contextual_risk_score"] <= 10


def test_critical_vulnerability_returns_critical_risk():
    result = calculate_contextual_risk(create_request())
    assert result["risk_level"] == "Critical"


def test_risk_result_contains_explanations():
    result = calculate_contextual_risk(create_request())
    assert len(result["reasons"]) > 0
    assert "features" in result


def test_kev_signal_is_recorded():
    result = calculate_contextual_risk(create_request())
    assert result["features"]["exploit_signal"] == 1
