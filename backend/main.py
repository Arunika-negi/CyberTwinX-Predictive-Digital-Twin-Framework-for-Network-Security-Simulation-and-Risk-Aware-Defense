from backend.models.risk import AssetRiskAssessmentRequest
from backend.services.vulnerability_matcher import match_asset_services
from backend.models.risk import RiskAssessmentRequest

from backend.services.risk_engine import (
    calculate_contextual_risk
)
import requests

from fastapi import FastAPI, HTTPException

from backend.services.kev_loader import (
    load_kev_catalog,
    search_kev
)

from backend.services.nvd_loader import fetch_cve


app = FastAPI(
    title="CyberTwin-X",
    description="Predictive Digital Twin Framework for Network Security",
    version="1.0.0"
)


@app.get("/")
def home():

    return {
        "project": "CyberTwin-X",
        "status": "running"
    }


@app.get("/health")
def health():

    return {
        "status": "healthy"
    }


@app.get("/intel/kev")
def get_kev():

    try:
        catalog = load_kev_catalog()

        return {
            "status": "success",
            "catalog_version": catalog["catalog_version"],
            "date_released": catalog["date_released"],
            "total_vulnerabilities":
                catalog["total_vulnerabilities"]
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(error)
        )


@app.get("/intel/kev/{cve_id}")
def get_kev_cve(cve_id: str):

    try:
        result = search_kev(cve_id)

        return {
            "found": result is not None,
            "cve_id": cve_id.upper(),
            "vulnerability": result
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(error)
        )


@app.get("/intel/nvd/{cve_id}")
def get_nvd_cve(cve_id: str):

    try:
        result = fetch_cve(cve_id)

        if result is None:
            raise HTTPException(
                status_code=404,
                detail="CVE not found in NVD"
            )

        return {
            "status": "success",
            "vulnerability": result
        }

    except HTTPException:
        raise

    except requests.exceptions.RequestException as error:
        raise HTTPException(
            status_code=502,
            detail=f"NVD API request failed: {error}"
        )

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(error)
        )


@app.post("/risk/assess")
def assess_risk(request: RiskAssessmentRequest):

    try:
        result = calculate_contextual_risk(request)

        return {
            "status": "success",
            "risk_assessment": result
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(error)
        )



@app.post("/risk/assess-asset")
def assess_asset_risk(request: AssetRiskAssessmentRequest):
    try:
        # Find vulnerabilities for discovered services
        matching_results = match_asset_services(request.asset)

        assessments = []

        for service in matching_results["service_results"]:
            for vulnerability in service["matches"]:

                # Only assess confirmed affected versions
                if vulnerability["match_status"] != "confirmed_affected_range":
                    continue

                if vulnerability["cvss_score"] is None:
                    continue

                risk_request = RiskAssessmentRequest(
                    asset=request.asset,
                    cve_id=vulnerability["cve_id"],
                    cvss_score=vulnerability["cvss_score"],
                    exposure_score=request.exposure_score,
                    reachable_from_attacker=request.reachable_from_attacker,
                    attack_path_position=request.attack_path_position,
                    kev_listed=vulnerability["kev_listed"]
                )

                risk_result = calculate_contextual_risk(
                    risk_request
                )

                assessments.append({
                    "service_product": service["product"],
                    "service_version": service["version"],
                    "vulnerability": vulnerability,
                    "risk_assessment": risk_result
                })

        assessments.sort(
            key=lambda item: item["risk_assessment"][
                "contextual_risk_score"
            ],
            reverse=True
        )

        return {
            "status": "success",
            "asset_id": request.asset.asset_id,
            "asset_name": request.asset.name,
            "total_confirmed_vulnerabilities": len(assessments),
            "risk_assessments": assessments
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(error)
        )
