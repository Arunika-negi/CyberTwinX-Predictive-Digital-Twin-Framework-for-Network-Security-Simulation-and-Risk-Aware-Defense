
from typing import Optional, Literal

from pydantic import BaseModel, Field


class GraphNode(BaseModel):
    """
    Represents one discovered network asset in the graph.
    """

    node_id: str
    ip_address: str
    hostname: Optional[str] = None

    asset_type: Optional[str] = None
    zone: Optional[str] = None
    criticality: Optional[int] = Field(
        default=None, ge=1, le=10
    )

    operating_system: Optional[str] = None

    services: list[str] = Field(default_factory=list)


class GraphEdge(BaseModel):
    """
    Represents an observed or configured relationship
    between two network assets.
    """

    source: str
    target: str

    relationship: str

    evidence_source: str

    direction: Literal["directed", "undirected"] = "directed"

    verified: bool = False

    attributes: dict = Field(default_factory=dict)


class NetworkGraphData(BaseModel):
    """
    Complete graph representation of the network.
    """

    nodes: list[GraphNode] = Field(default_factory=list)

    edges: list[GraphEdge] = Field(default_factory=list)

    total_nodes: int = 0
    total_edges: int = 0
