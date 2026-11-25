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