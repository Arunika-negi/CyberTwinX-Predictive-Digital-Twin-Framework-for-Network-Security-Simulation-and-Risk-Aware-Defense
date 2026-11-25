

from backend.models.asset import Asset
from backend.models.risk import RiskAssessmentRequest
from backend.services.risk_engine import calculate_contextual_risk


def create_request(**overrides):
    asset = Asset(
        asset_id="SRV-001",
        name="Test Server",
        ip_address="192.168.1.10",
        asset_type="server",
        zone="DMZ",
        criticality=9,
    )

    request_data = {
        "asset": asset,
        "cve_id": "CVE-2021-44228",
        "cvss_score": 10,
        "exposure_score": 0.8,
        "reachable_from_attacker": True,
        "attack_path_position": 0.7,
        "kev_listed": True,
    }

    request_data.update(overrides)

    return RiskAssessmentRequest(**request_data)


# Original tests

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


# New pending-context tests

def test_missing_exposure_returns_pending_assessment():
    result = calculate_contextual_risk(
        create_request(exposure_score=None)
    )

    assert result["assessment_status"] == "pending_context"
    assert result["contextual_risk_score"] is None
    assert "exposure_score" in result["missing_context"]


def test_unknown_reachability_is_not_treated_as_unreachable():
    result = calculate_contextual_risk(
        create_request(reachable_from_attacker=None)
    )

    assert result["assessment_status"] == "pending_context"
    assert result["features"]["reachability"] is None
    assert "reachable_from_attacker" in result["missing_context"]


def test_unknown_attack_path_is_not_treated_as_zero():
    result = calculate_contextual_risk(
        create_request(attack_path_position=None)
    )

    assert result["assessment_status"] == "pending_context"
    assert result["features"]["attack_path_position"] is None
    assert "attack_path_position" in result["missing_context"]


def test_false_reachability_is_valid_when_assessed():
    result = calculate_contextual_risk(
        create_request(reachable_from_attacker=False)
    )

    assert result["assessment_status"] == "completed"
    assert result["features"]["reachability"] == 0.0
    assert result["contextual_risk_score"] is not None


def test_complete_context_returns_completed_assessment():
    result = calculate_contextual_risk(create_request())

    assert result["assessment_status"] == "completed"
    assert result["missing_context"] == []
    assert result["contextual_risk_score"] is not None
