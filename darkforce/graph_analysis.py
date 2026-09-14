"""Network-graph analytics built on the attribution graph.

Attribution network: actors (nodes) are connected when they share a handle,
an identifier value, or a site. Handle/site/identifier nodes are included as
intermediate nodes so communities and bridge scores mean something even when
the raw `links` table is sparse.

Returns communities, centrality, bridge actors, and a summary."""
import networkx as nx

from .db import DB

_HANDLE_TYPES = {"actor", "handle", "site"}
_IDENTIFIER_KINDS = {"btc", "xmr", "email", "jabber", "onion", "pgp",
                     "pgp_email", "telegram"}


def _build_graph(db: DB) -> "nx.Graph":
    G = nx.Graph()
    actor_by_id = {r["id"]: r["canon"] for r in db.q("SELECT id, canon FROM actors")}

    for a in db.q("SELECT * FROM actors ORDER BY confidence DESC"):
        conf = a["confidence"]
        G.add_node(f"actor:{a['canon']}", label=a["canon"], kind="actor",
                   confidence=float(conf) if conf is not None else None)
        G.nodes[f"actor:{a['canon']}"]["_actor_id"] = a["id"]

    for h in db.q("SELECT h.*, s.url site_url, a.canon FROM handles h "
                  "LEFT JOIN sites s ON s.id=h.site_id "
                  "LEFT JOIN actors a ON a.id=h.actor_id"):
        h = dict(h)
        node = f"handle:{h['handle']}"
        G.add_node(node, label=h["handle"], kind="handle", confidence=h.get("confidence"))
        actor_node = f"actor:{h['canon']}"
        if G.has_node(actor_node):
            G.add_edge(actor_node, node, weight=0.9, edge_type="has_handle")
        if h.get("site_url"):
            site_node = f"site:{h['site_url']}"
            G.add_node(site_node, label=h["site_url"], kind="site", confidence=None)
            G.add_edge(node, site_node, weight=0.8, edge_type="registered")

    for i in db.q("SELECT * FROM identifiers"):
        kind = i["kind"] if i["kind"] in _IDENTIFIER_KINDS else "id"
        node = f"{kind}:{i['value'][:18]}"
        if not G.has_node(node):
            G.add_node(node, label=i["value"][:40], kind=i["kind"], confidence=None)
        canon = actor_by_id.get(i["actor_id"])
        if canon and G.has_node(f"actor:{canon}"):
            G.add_edge(f"actor:{canon}", node, weight=0.95, edge_type=f"uses_{i['kind']}")

    # Cross-actor: sharing an identifier value is the strongest attribution bridge.
    for i in db.q("SELECT value FROM identifiers "
                  "GROUP BY value HAVING COUNT(DISTINCT actor_id) > 1"):
        rows = db.q("SELECT actor_id FROM identifiers WHERE value=?", (i["value"],))
        ids = [r["actor_id"] for r in rows]
        for x in range(len(ids)):
            for y in range(x + 1, len(ids)):
                ax, ay = actor_by_id.get(ids[x]), actor_by_id.get(ids[y])
                if ax and ay:
                    nx_node_a = f"actor:{ax}"
                    nx_node_b = f"actor:{ay}"
                    if G.has_node(nx_node_a) and G.has_node(nx_node_b):
                        G.add_edge(nx_node_a, nx_node_b, weight=1.0, edge_type="shared_identifier")
    return G


def analyze_network(db: DB) -> dict:
    """Build the attribution graph, compute analytics, return JSON-safe dict."""
    G = _build_graph(db)
    if G.number_of_nodes() == 0:
        return {"n_nodes": 0, "n_edges": 0, "n_communities": 0,
                "communities": [], "centrality": [], "bridges": [],
                "summary": {"density": 0.0, "avg_degree": 0.0, "most_central": None}}

    n_nodes, n_edges = G.number_of_nodes(), G.number_of_edges()

    # actor-only induced subgraph: fast centrality + the bridge signal analysts
    # actually read (an actor is central when it connects other ACTORS, not
    # sites/handles). Full-graph betweenness cost O(V*E) (~20s here).
    actor_nodes = [n for n in G.nodes if G.nodes[n].get("kind") == "actor"]
    S = G.subgraph(actor_nodes) if len(actor_nodes) > 1 else G

    # ── communities ─────────────────────────────────────────────────────────
    try:
        import networkx.algorithms.community as _comm
        raw_comms = list(_comm.louvain_communities(G, weight="weight", seed=7))
    except Exception:
        try:
            raw_comms = list(nx.community.greedy_modularity_communities(G, weight="weight"))
        except Exception:
            raw_comms = [frozenset(G.nodes)]

    communities, node_comm = [], {}
    for idx, comm in enumerate(raw_comms):
        for n in comm:
            node_comm[n] = idx
        members = [n for n in comm if G.nodes[n].get("kind") == "actor"]
        communities.append({
            "id": idx,
            "size": len(comm),
            "actors": sorted(members),
            "labels": [G.nodes[n].get("label", n) for n in sorted(members)],
        })

    # ── centrality ──────────────────────────────────────────────────────────
    try:
        degree = nx.degree_centrality(S)
    except Exception:
        degree = {n: 0.0 for n in G}
    try:
        betweenness = nx.betweenness_centrality(S, weight="weight")
    except Exception:
        betweenness = {n: 0.0 for n in G}
    try:
        eigen = nx.eigenvector_centrality(S, max_iter=1000, weight="weight")
    except Exception:
        eigen = {n: 0.0 for n in G}

    centrality = sorted(
        [{"node": n,
          "label": G.nodes[n].get("label", n),
          "kind": G.nodes[n].get("kind", "entity"),
          "actor_id": G.nodes[n].get("_actor_id"),
          "degree": round(degree.get(n, 0.0), 4),
          "betweenness": round(betweenness.get(n, 0.0), 4),
          "eigenvector": round(eigen.get(n, 0.0), 4),
          "community": node_comm.get(n, 0),
          "confidence": G.nodes[n].get("confidence")}
         for n in G.nodes],
        key=lambda c: -c["degree"],
    )

    # Actor-only centrality ranking (what the analyst actually reads).
    actor_centrality = [c for c in centrality if c["kind"] == "actor"]

    # ── bridges ─────────────────────────────────────────────────────────────
    bridges = []
    for n in actor_nodes:
        neighbor_communities = {node_comm.get(m, 0) for m in S.neighbors(n)}
        if len(neighbor_communities) > 1:
            bridges.append({
                "node": n,
                "label": G.nodes[n].get("label", n),
                "kind": "actor",
                "actor_id": G.nodes[n].get("_actor_id"),
                "connects_communities": len(neighbor_communities),
                "communities": sorted(neighbor_communities),
            })
    if S is not G:
        for n in G.nodes:
            if n not in actor_nodes and G.nodes[n].get("kind") != "actor":
                neighbor_communities = {node_comm.get(m, 0) for m in G.neighbors(n)}
                if len(neighbor_communities) > 1:
                    bridges.append({
                        "node": n,
                        "label": G.nodes[n].get("label", n),
                        "kind": G.nodes[n].get("kind", "entity"),
                        "actor_id": G.nodes[n].get("_actor_id"),
                        "connects_communities": len(neighbor_communities),
                        "communities": sorted(neighbor_communities),
                    })
    bridges.sort(key=lambda b: -b["connects_communities"])

    density = nx.density(G)
    full_deg = dict(G.degree())
    avg_degree = (sum(full_deg.values()) / n_nodes) if n_nodes else 0.0
    most_central = actor_centrality[0]["label"] if actor_centrality else None

    return {
        "n_nodes": n_nodes,
        "n_edges": n_edges,
        "n_communities": len(communities),
        "communities": communities,
        "centrality": centrality,
        "bridges": bridges,
        "summary": {
            "density": round(density, 4),
            "avg_degree": round(avg_degree, 4),
            "most_central": most_central,
            "top_actor": actor_centrality[0] if actor_centrality else None,
            "actor_count": len(actor_centrality),
        },
        "actor_centrality": actor_centrality,
    }