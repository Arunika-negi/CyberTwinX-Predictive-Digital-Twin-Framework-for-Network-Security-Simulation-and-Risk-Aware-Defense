
import os
import requests

from pathlib import Path
from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[2]

load_dotenv(PROJECT_ROOT / ".env")

NVD_API_URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
)


def fetch_cve(cve_id: str):

    api_key = os.getenv("NVD_API_KEY")

    if not api_key:
        raise RuntimeError(
            "NVD_API_KEY is missing from the .env file"
        )

    cve_id = cve_id.strip().upper()

    if not cve_id.startswith("CVE-"):
        raise ValueError("Invalid CVE ID format")

    response = requests.get(
        NVD_API_URL,
        headers={"apiKey": api_key},
        params={"cveId": cve_id},
        timeout=30
    )

    response.raise_for_status()

    data = response.json()
    vulnerabilities = data.get("vulnerabilities", [])

    if not vulnerabilities:
        return None

    cve = vulnerabilities[0]["cve"]

    description = next(
        (
            item["value"]
            for item in cve.get("descriptions", [])
            if item.get("lang") == "en"
        ),
        None
    )

    metrics = cve.get("metrics", {})

    cvss_score = None
    severity = None
    cvss_version = None

    for metric_name in [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2"
    ]:

        metric_list = metrics.get(metric_name, [])

        if not metric_list:
            continue

        metric = metric_list[0]
        cvss = metric.get("cvssData", {})

        cvss_score = cvss.get("baseScore")
        severity = (
            cvss.get("baseSeverity")
            or metric.get("baseSeverity")
        )
        cvss_version = cvss.get("version")

        if cvss_score is not None:
            break

    return {
        "cve_id": cve.get("id"),
        "description": description,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "cvss_score": cvss_score,
        "severity": severity,
        "cvss_version": cvss_version,
        "source": "NVD"
    }


def search_nvd_product(product: str, results_per_page: int = 20):
    """
    Search NVD for CVE candidates associated with a product.
    Returns raw CVE records so the matcher can inspect CPE ranges.
    """
    api_key = os.getenv("NVD_API_KEY")

    if not api_key:
        raise RuntimeError("NVD_API_KEY is missing from .env")

    if not product or not product.strip():
        raise ValueError("Product name cannot be empty")

    response = requests.get(
        NVD_API_URL,
        headers={"apiKey": api_key},
        params={
            "keywordSearch": product.strip(),
            "resultsPerPage": results_per_page
        },
        timeout=30
    )

    response.raise_for_status()

    data = response.json()

    return [
        item["cve"]
        for item in data.get("vulnerabilities", [])
    ]
