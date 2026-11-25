
import networkx as nx

from backend.models.graph_models import NetworkGraphData


def build_network_graph(graph_data: NetworkGraphData) -> nx.DiGraph:
    """
    Build a directed NetworkX graph from network graph data.

    Only verified relationships are added as graph edges.
    Unverified relationships are excluded from reachability
    and attack-path calculations.
    """

    graph = nx.DiGraph()

    # Store graph-level information
    graph.graph["total_input_nodes"] = len(graph_data.nodes)
    graph.graph["total_input_edges"] = len(graph_data.edges)
    graph.graph["skipped_unverified_edges"] = 0

    # 1. Add network assets as graph nodes
    for node in graph_data.nodes:

        if node.node_id in graph:
            raise ValueError(
                f"Duplicate node ID found: {node.node_id}"
            )

        node_attributes = node.model_dump(
            exclude={"node_id"},
            exclude_none=True
        )

        graph.add_node(
            node.node_id,
            **node_attributes
        )

    # 2. Add verified relationships as graph edges
    for edge in graph_data.edges:

        # Check whether both endpoints exist
        if edge.source not in graph:
            raise ValueError(
                f"Source node does not exist: {edge.source}"
            )

        if edge.target not in graph:
            raise ValueError(
                f"Target node does not exist: {edge.target}"
            )

        if edge.source == edge.target:
            raise ValueError(
                f"Self-loop is not allowed: {edge.source}"
            )

        # Ignore relationships without verification
        if not edge.verified:
            graph.graph["skipped_unverified_edges"] += 1
            continue

        edge_attributes = {
            "relationship": edge.relationship,
            "evidence_source": edge.evidence_source,
            "verified": edge.verified,
            "attributes": edge.attributes,
            "direction": edge.direction
        }

        # Add the original direction
        graph.add_edge(
            edge.source,
            edge.target,
            **edge_attributes
        )

        # An undirected relationship permits traversal both ways
        if edge.direction == "undirected":

            reverse_attributes = edge_attributes.copy()

            graph.add_edge(
                edge.target,
                edge.source,
                **reverse_attributes
            )

    # 3. Store final graph statistics
    graph.graph["total_nodes"] = graph.number_of_nodes()
    graph.graph["total_edges"] = graph.number_of_edges()

    return graph


def get_graph_summary(graph: nx.DiGraph) -> dict:
    """
    Return basic statistics about the constructed graph.
    """

    return {
        "total_nodes": graph.number_of_nodes(),
        "total_edges": graph.number_of_edges(),
        "isolated_nodes": list(nx.isolates(graph)),
        "skipped_unverified_edges": graph.graph.get(
            "skipped_unverified_edges", 0
        ),
        "is_directed": graph.is_directed()
    }
