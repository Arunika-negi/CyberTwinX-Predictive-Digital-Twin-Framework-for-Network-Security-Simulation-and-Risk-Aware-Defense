
from pydantic import BaseModel, Field

from backend.models.asset import Asset


class RiskAssessmentRequest(BaseModel):
    asset: Asset

    cve_id: str

    cvss_score: float = Field(ge=0, le=10)

    # 0 = isolated, 1 = internet-facing
    exposure_score: float = Field(ge=0, le=1)

    # Derived from network graph analysis
    reachable_from_attacker: bool = False

    # 0 = not on a critical path, 1 = highest path importance
    attack_path_position: float = Field(default=0, ge=0, le=1)

    # True when the CVE is listed in CISA KEV
    kev_listed: bool = False
