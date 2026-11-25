
import networkx as nx


def analyze_reachability(
    graph: nx.DiGraph,
    source_node: str
) -> dict:
    """
    Analyze which network nodes are reachable
    from a specified source node.

    Only paths present in the supplied graph
    are considered.
    """

    # 1. Validate graph
    if not isinstance(graph, nx.DiGraph):
        raise TypeError(
            "Expected a NetworkX directed graph."
        )

    # 2. Validate source node
    if source_node not in graph:
        raise ValueError(
            f"Source node does not exist: {source_node}"
        )

    # 3. Find all nodes reachable from source
    reachable_nodes = list(
        nx.descendants(graph, source_node)
    )

    # 4. Calculate shortest path distances
    shortest_paths = nx.single_source_shortest_path_length(
        graph,
        source_node
    )

    # Remove the source itself from destination results
    shortest_paths.pop(source_node, None)

    # 5. Sort nodes for consistent output
    reachable_nodes.sort()

    shortest_paths = dict(
        sorted(shortest_paths.items())
    )

    # 6. Identify unreachable nodes
    unreachable_nodes = sorted(
        node
        for node in graph.nodes()
        if node != source_node
        and node not in reachable_nodes
    )

    # 7. Return structured result
    return {
        "source_node": source_node,

        "total_nodes": graph.number_of_nodes(),

        "reachable_count": len(reachable_nodes),

        "unreachable_count": len(unreachable_nodes),

        "reachable_nodes": reachable_nodes,

        "unreachable_nodes": unreachable_nodes,

        "shortest_path_distances": shortest_paths
    }
