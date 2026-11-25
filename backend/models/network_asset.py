
from typing import Optional

from pydantic import BaseModel, Field


class NetworkAddress(BaseModel):
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None
    mac: Optional[str] = None
    mac_vendor: Optional[str] = None


class NetworkService(BaseModel):
    name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extrainfo: Optional[str] = None
    ostype: Optional[str] = None
    method: Optional[str] = None
    confidence: Optional[str] = None
    cpe: list[str] = Field(default_factory=list)


class NetworkPort(BaseModel):
    protocol: Optional[str] = None
    port: int
    state: Optional[str] = None
    reason: Optional[str] = None
    service: NetworkService


class ExtraPortCount(BaseModel):
    state: Optional[str] = None
    count: int


class NetworkAsset(BaseModel):
    status: Optional[str] = None
    addresses: NetworkAddress
    hostnames: list[str] = Field(default_factory=list)
    os_matches: list[dict] = Field(default_factory=list)
    ports: list[NetworkPort] = Field(default_factory=list)
    extraports: list[ExtraPortCount] = Field(default_factory=list)


class NetworkScanSummary(BaseModel):
    total_hosts: int = 0
    hosts_up: int = 0
    hosts_down: int = 0
    observed_ports: int = 0
    aggregate_port_count: int = 0
    total_ports_accounted_for: int = 0
    open_ports: int = 0
    closed_ports: int = 0
    filtered_ports: int = 0


class NetworkInventory(BaseModel):
    scanner: Optional[str] = None
    nmap_version: Optional[str] = None
    scan_arguments: Optional[str] = None
    start_time: Optional[str] = None
    hosts: list[NetworkAsset] = Field(default_factory=list)
    summary: NetworkScanSummary
