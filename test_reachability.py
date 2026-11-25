
from backend.models.graph_models import (
    GraphNode,
    GraphEdge,
    NetworkGraphData
)

from backend.services.network_graph import (
    build_network_graph
)

from backend.services.reachability import (
    analyze_reachability
)


# Create sample network nodes
nodes = [
    GraphNode(
        node_id="A",
        ip_address="192.168.1.10"
    ),
    GraphNode(
        node_id="B",
        ip_address="192.168.1.20"
    ),
    GraphNode(
        node_id="C",
        ip_address="192.168.1.30"
    ),
    GraphNode(
        node_id="D",
        ip_address="192.168.1.40"
    )
]


# Create network relationships
edges = [
    GraphEdge(
        source="A",
        target="B",
        relationship="verified_connection",
        evidence_source="test_data",
        verified=True
    ),
    GraphEdge(
        source="B",
        target="C",
        relationship="verified_connection",
        evidence_source="test_data",
        verified=True
    ),
    GraphEdge(
        source="A",
        target="D",
        relationship="unverified_connection",
        evidence_source="test_data",
        verified=False
    )
]


# Build graph
graph_data = NetworkGraphData(
    nodes=nodes,
    edges=edges
)

G = build_network_graph(graph_data)


# Analyze reachability
result = analyze_reachability(G, "A")


# Display results
print("Reachability Analysis")
print("---------------------")

for key, value in result.items():
    print(f"{key}: {value}")
