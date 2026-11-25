
def calculate_contextual_risk(request):
    """
    Calculate contextual cybersecurity risk.

    This is an experimental weighted scoring model,
    not an industry-standard CVSS replacement.
    """

    # 1. Normalize CVSS severity
    severity = request.cvss_score / 10.0

    # 2. Normalize asset criticality (1-10)
    criticality = (
        request.asset.criticality - 1
    ) / 9.0

    # 3. Exposure
    exposure = request.exposure_score

    # 4. Attacker reachability
    reachability = (
        1.0 if request.reachable_from_attacker else 0.0
    )

    # 5. Attack path importance
    path_position = request.attack_path_position

    # 6. Exploit evidence from CISA KEV
    exploit_signal = (
        1.0 if request.kev_listed else 0.0
    )

    # Experimental weights from project blueprint
    weights = {
        "severity": 0.25,
        "criticality": 0.20,
        "exposure": 0.15,
        "reachability": 0.15,
        "attack_path": 0.15,
        "exploit_signal": 0.10
    }

    # Calculate contextual risk
    risk_score = 10 * (
        weights["severity"] * severity
        + weights["criticality"] * criticality
        + weights["exposure"] * exposure
        + weights["reachability"] * reachability
        + weights["attack_path"] * path_position
        + weights["exploit_signal"] * exploit_signal
    )

    # Severity-only baseline
    severity_baseline = request.cvss_score

    # Risk classification
    if risk_score >= 8:
        risk_level = "Critical"

    elif risk_score >= 6:
        risk_level = "High"

    elif risk_score >= 4:
        risk_level = "Medium"

    else:
        risk_level = "Low"

    # Explain the result
    reasons = []

    if request.cvss_score >= 7:
        reasons.append("High technical vulnerability severity")

    if criticality >= 0.7:
        reasons.append("High business-criticality asset")

    if exposure >= 0.7:
        reasons.append("High network exposure")

    if request.reachable_from_attacker:
        reasons.append("Reachable from attacker source")

    if path_position >= 0.7:
        reasons.append("Important position in a critical attack path")

    if request.kev_listed:
        reasons.append("Listed in CISA Known Exploited Vulnerabilities")

    if not reasons:
        reasons.append("No high-risk contextual factors identified")

    return {
        "asset_id": request.asset.asset_id,
        "asset_name": request.asset.name,
        "cve_id": request.cve_id,

        "severity_only_baseline": round(
            severity_baseline, 2
        ),

        "contextual_risk_score": round(
            risk_score, 2
        ),

        "risk_level": risk_level,

        "risk_difference": round(
            risk_score - severity_baseline, 2
        ),

        "features": {
            "severity": round(severity, 3),
            "criticality": round(criticality, 3),
            "exposure": round(exposure, 3),
            "reachability": reachability,
            "attack_path_position": path_position,
            "exploit_signal": exploit_signal
        },

        "reasons": reasons
    }
