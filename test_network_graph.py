
from backend.models.graph_models import (
    GraphNode,
    GraphEdge,
    NetworkGraphData
)

from backend.services.network_graph import (
    build_network_graph,
    get_graph_summary
)

nodes = [
    GraphNode(
        node_id="A",
        ip_address="192.168.1.10",
        hostname="Device-A"
    ),
    GraphNode(
        node_id="B",
        ip_address="192.168.1.20",
        hostname="Device-B"
    ),
    GraphNode(
        node_id="C",
        ip_address="192.168.1.30",
        hostname="Device-C"
    )
]

edges = [
    GraphEdge(
        source="A",
        target="B",
        relationship="observed_connection",
        evidence_source="test_flow_record",
        direction="directed",
        verified=True
    ),
    GraphEdge(
        source="B",
        target="C",
        relationship="possible_connection",
        evidence_source="unverified_test_data",
        direction="directed",
        verified=False
    )
]

graph_data = NetworkGraphData(
    nodes=nodes,
    edges=edges
)

G = build_network_graph(graph_data)

print("Nodes:", list(G.nodes()))
print("Edges:", list(G.edges()))

print("\nGraph Summary:")
print(get_graph_summary(G))

import networkx as nx

print("\nA can reach B:", nx.has_path(G, "A", "B"))
print("A can reach C:", nx.has_path(G, "A", "C"))
