
from typing import Optional

from pydantic import BaseModel, Field

from backend.models.asset import Asset


class RiskAssessmentRequest(BaseModel):
    asset: Asset
    cve_id: str
    cvss_score: float = Field(ge=0, le=10)

    # 0 = isolated, 1 = internet-facing
    exposure_score: Optional[float] = Field(
        default=None, ge=0, le=1
    )

    reachable_from_attacker: Optional[bool] = None

    attack_path_position: Optional[float] = Field(
        default=None, ge=0, le=1
    )

    # True when the CVE is listed in CISA KEV
    kev_listed: bool = False


class AssetRiskAssessmentRequest(BaseModel):
    asset: Asset

    # Context supplied by the network analysis module
    exposure_score: Optional[float] = Field(
        default=None, ge=0, le=1
    )

    reachable_from_attacker: Optional[bool] = None

    attack_path_position: Optional[float] = Field(
        default=None, ge=0, le=1
    )
