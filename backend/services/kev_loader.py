
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

KEV_FILE = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "kev"
    / "known_exploited_vulnerabilities.json"
)


def load_kev_catalog():

    if not KEV_FILE.exists():
        raise FileNotFoundError(
            f"CISA KEV file not found: {KEV_FILE}"
        )

    with KEV_FILE.open("r", encoding="utf-8") as file:
        data = json.load(file)

    records = data.get("vulnerabilities", [])

    vulnerabilities = []

    for item in records:
        vulnerabilities.append({
            "cve_id": item.get("cveID"),
            "vendor": item.get("vendorProject"),
            "product": item.get("product"),
            "name": item.get("vulnerabilityName"),
            "date_added": item.get("dateAdded"),
            "description": item.get("shortDescription"),
            "required_action": item.get("requiredAction"),
            "due_date": item.get("dueDate"),
            "known_ransomware_use": item.get(
                "knownRansomwareCampaignUse"
            )
        })

    return {
        "catalog_version": data.get("catalogVersion"),
        "date_released": data.get("dateReleased"),
        "total_vulnerabilities": len(vulnerabilities),
        "vulnerabilities": vulnerabilities
    }


def search_kev(cve_id: str):

    catalog = load_kev_catalog()
    cve_id = cve_id.strip().upper()

    for item in catalog["vulnerabilities"]:
        if item["cve_id"] == cve_id:
            return item

    return None

