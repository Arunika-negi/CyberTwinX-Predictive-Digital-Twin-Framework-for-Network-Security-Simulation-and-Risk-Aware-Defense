
from backend.models.graph_models import (
    GraphNode,
    GraphEdge,
    NetworkGraphData
)

from backend.services.network_graph import (
    build_network_graph
)

from backend.services.attack_path import (
    find_attack_paths
)


# 1. Create sample network nodes
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
    ),
    GraphNode(
        node_id="E",
        ip_address="192.168.1.50"
    ),
    GraphNode(
        node_id="F",
        ip_address="192.168.1.60"
    )
]


# 2. Create network relationships
edges = [
    GraphEdge(
        source="A",
        target="B",
        relationship="verified_connection",
        evidence_source="test_data",
        verified=True
    ),
    GraphEdge(
        source="A",
        target="C",
        relationship="verified_connection",
        evidence_source="test_data",
        verified=True
    ),
    GraphEdge(
        source="B",
        target="D",
        relationship="verified_connection",
        evidence_source="test_data",
        verified=True
    ),
    GraphEdge(
        source="C",
        target="D",
        relationship="verified_connection",
        evidence_source="test_data",
        verified=True
    ),
    GraphEdge(
        source="D",
        target="E",
        relationship="verified_connection",
        evidence_source="test_data",
        verified=True
    ),
    GraphEdge(
        source="A",
        target="F",
        relationship="unverified_connection",
        evidence_source="test_data",
        verified=False
    )
]


# 3. Build network graph
graph_data = NetworkGraphData(
    nodes=nodes,
    edges=edges
)

G = build_network_graph(graph_data)


# 4. Find possible paths from A to E
result = find_attack_paths(
    graph=G,
    source_node="A",
    target_node="E",
    max_paths=10
)


# 5. Display results
print("Attack Path Analysis")
print("--------------------")

for key, value in result.items():
    print(f"{key}: {value}")
