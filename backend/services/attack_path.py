
import networkx as nx
from itertools import islice


def find_attack_paths(
    graph: nx.DiGraph,
    source_node: str,
    target_node: str,
    max_paths: int = 10,
    cutoff: int | None = None
) -> dict:
    """
    Identify possible paths between an attacker
    entry point and a target network asset.

    Only edges already present in the supplied
    graph are considered.

    max_paths: Maximum number of simple paths returned.
    cutoff: Maximum number of edges allowed in a path.
    """

    # 1. Validate graph
    if not isinstance(graph, nx.DiGraph):
        raise TypeError(
            "Expected a NetworkX directed graph."
        )

    # 2. Validate maximum number of paths
    if max_paths < 1:
        raise ValueError(
            "max_paths must be at least 1."
        )

    if cutoff is not None and cutoff < 0:
        raise ValueError(
            "cutoff cannot be negative."
        )

    # 3. Validate source and target
    if source_node not in graph:
        raise ValueError(
            f"Source node does not exist: {source_node}"
        )

    if target_node not in graph:
        raise ValueError(
            f"Target node does not exist: {target_node}"
        )

    # 4. Check whether a path exists
    if not nx.has_path(graph, source_node, target_node):
        return {
            "source_node": source_node,
            "target_node": target_node,
            "path_found": False,
            "shortest_path": None,
            "shortest_path_length": None,
            "alternative_paths": [],
            "total_paths_returned": 0,
            "max_paths_limit": max_paths,
            "message": "No path exists between source and target."
        }

    # 5. Find shortest path
    shortest_path = nx.shortest_path(
        graph,
        source=source_node,
        target=target_node
    )

    shortest_path_length = len(shortest_path) - 1

    # 6. Find simple paths
    path_generator = nx.all_simple_paths(
        graph,
        source=source_node,
        target=target_node,
        cutoff=cutoff
    )

    alternative_paths = list(
        islice(path_generator, max_paths)
    )

    # 7. Return structured results
    return {
        "source_node": source_node,
        "target_node": target_node,
        "path_found": True,
        "shortest_path": shortest_path,
        "shortest_path_length": shortest_path_length,
        "alternative_paths": alternative_paths,
        "total_paths_returned": len(alternative_paths),
        "max_paths_limit": max_paths,
        "message": "Possible graph paths identified successfully."
    }
