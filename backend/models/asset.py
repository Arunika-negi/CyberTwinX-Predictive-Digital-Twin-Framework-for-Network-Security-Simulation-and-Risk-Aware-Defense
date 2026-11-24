from pydantic import BaseModel, Field, IPvAnyAddress
from typing import Optional


class Asset(BaseModel):
    asset_id: str
    name: str
    ip_address: IPvAnyAddress
    asset_type: str
    zone: str
    criticality: int = Field(ge=1, le=10)
    operating_system: Optional[str] = None
