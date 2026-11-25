
from typing import Optional

from pydantic import BaseModel, Field, IPvAnyAddress


class Service(BaseModel):
    service_name: Optional[str] = None
    product: Optional[str] = None
    vendor: Optional[str] = None
    version: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    state: Optional[str] = None
    cpe: list[str] = Field(default_factory=list)


class Asset(BaseModel):
    asset_id: str
    name: str
    ip_address: IPvAnyAddress
    asset_type: str
    zone: str
    criticality: int = Field(ge=1, le=10)
    operating_system: Optional[str] = None
    services: list[Service] = Field(default_factory=list)

