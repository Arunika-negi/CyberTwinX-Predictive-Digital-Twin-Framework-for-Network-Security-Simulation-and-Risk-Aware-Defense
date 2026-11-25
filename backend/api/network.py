import json
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, UploadFile, File, HTTPException

from backend.services.nmap_parser import parse_nmap_xml
from backend.models.network_asset import NetworkInventory


router = APIRouter(prefix="/network", tags=["Network Discovery"])

# Project-root paths (independent of the CMD working directory)
PROJECT_ROOT = Path(__file__).resolve().parents[2]

SCAN_DIR = PROJECT_ROOT / "data" / "scans"
INVENTORY_DIR = PROJECT_ROOT / "data" / "processed"
INVENTORY_FILE = INVENTORY_DIR / "asset_inventory.json"

MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10 MB


def save_inventory(inventory: NetworkInventory):
    """Save validated inventory JSON atomically."""

    INVENTORY_DIR.mkdir(parents=True, exist_ok=True)

    temporary_file = INVENTORY_DIR / "asset_inventory.tmp"

    temporary_file.write_text(
        inventory.model_dump_json(indent=4),
        encoding="utf-8"
    )

    temporary_file.replace(INVENTORY_FILE)


@router.post("/import-xml", response_model=NetworkInventory)
async def import_nmap_xml(file: UploadFile = File(...)):
    """Upload and parse an authorized Nmap XML scan."""

    if not file.filename or not file.filename.lower().endswith(".xml"):
        raise HTTPException(
            status_code=400,
            detail="Please upload an Nmap XML file."
        )

    content = await file.read(MAX_UPLOAD_SIZE + 1)
    await file.close()

    if not content:
        raise HTTPException(
            status_code=400,
            detail="Uploaded file is empty."
        )

    if len(content) > MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=413,
            detail="File exceeds the 10 MB upload limit."
        )

    SCAN_DIR.mkdir(parents=True, exist_ok=True)

    # Use a generated filename; never trust the uploaded filename as a path.
    scan_path = SCAN_DIR / f"upload_{uuid4().hex}.xml"

    try:
        scan_path.write_bytes(content)

        parsed_data = parse_nmap_xml(scan_path)

        inventory = NetworkInventory.model_validate(parsed_data)

        save_inventory(inventory)

        return inventory

    except (ValueError, OSError) as error:
        scan_path.unlink(missing_ok=True)

        raise HTTPException(
            status_code=400,
            detail=f"Could not process Nmap XML: {error}"
        )

    except Exception as error:
        scan_path.unlink(missing_ok=True)

        raise HTTPException(
            status_code=500,
            detail=f"Network inventory processing failed: {error}"
        )


@router.get("/assets", response_model=NetworkInventory)
def get_network_assets():
    """Retrieve the most recently imported network inventory."""

    if not INVENTORY_FILE.exists():
        raise HTTPException(
            status_code=404,
            detail="No network inventory found. Import an Nmap XML scan first."
        )

    try:
        data = json.loads(INVENTORY_FILE.read_text(encoding="utf-8"))
        return NetworkInventory.model_validate(data)

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Could not read network inventory: {error}"
        )