import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, BarChart3, CloudDownload, FileJson, FileText, GitFork, Link2, Network, ShieldAlert, Users } from "lucide-react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import GraphCanvas from "@/components/GraphCanvas";
import { apiDownload } from "@/lib/api";
import { getActors, getGraph, getNetworkAnalysis, getText, type GraphNode } from "@/lib/darkforce";

function metric(value?: number, label = "RECORDS") {
  return (
    <div className="stat-block" data-testid="net-metric">
      <div className="stat-icon" style={{ color: "var(--accent)" }}>
        <BarChart3 size={16} />
      </div>
      <div>
        <div className="stat-value">{(value ?? 0).toLocaleString()}</div>
        <div className="stat-label">{label}</div>
      </div>
    </div>
  );
}

export default function Analyst() {
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const downloadNightlyDigest = (fmt: "json" | "md" | "pdf") => {
    void apiDownload(`/digest?fmt=${fmt}`, `darkforce-digest.${fmt === "md" ? "md" : fmt}`)
      .catch(() => undefined);
  };

  const graphQuery = useQuery({ queryKey: ["analyst-graph"], queryFn: () => getGraph(""), retry: false });
  const actorsQuery = useQuery({ queryKey: ["analyst-actors"], queryFn: getActors, retry: false });
  const netQuery = useQuery({ queryKey: ["analyst-network"], queryFn: getNetworkAnalysis, retry: false });

  const net = netQuery.data;
  const byCentrality = useMemo(
    () =>
      [...(net?.actor_centrality ?? [])]
        .map((row) => ({
          label: getText(row.label ?? row.node, "?"),
          id: getText(row.node, ""),
          degree: Number(row.degree ?? 0),
          betweenness: Number(row.betweenness ?? 0),
          eigenvector: Number(row.eigenvector ?? 0),
          community: getText(row.community, "0"),
        }))
        .sort((a, b) => b.eigenvector - a.eigenvector || b.betweenness - a.betweenness)
        .slice(0, 12),
    [net],
  );
  const topBridges = useMemo(
    () =>
      [...(net?.bridges ?? [])]
        .map((row) => ({
          label: getText(row.label ?? row.node, "?"),
          id: getText(row.node, ""),
          connects: Number(row.connects_communities ?? row.connects ?? 0),
        }))
        .sort((a, b) => b.connects - a.connects)
        .slice(0, 8),
    [net],
  );
  const communities = net?.communities ?? [];
  const topCommunities = useMemo(
    () =>
      [...communities]
        .map((c) => ({ id: getText(c.id, "0"), size: Number(c.size ?? 0), label: getText(c.labels?.[0], "?",)}))
        .sort((a, b) => b.size - a.size)
        .slice(0, 10),
    [communities],
  );

  const sum = net?.summary ?? {};
  const graphNodes = graphQuery.data?.nodes ?? graphQuery.data?.elements?.nodes ?? [];

  return (
    <div className="console-main analyst-page" data-testid="analyst-page">
      <header className="panel-heading">
        <div>
          <div className="section-kicker">
            <Network size={14} /> ANALYST VIEW <span className="mono">/ NETWORK INTELLIGENCE</span>
          </div>
          <div className="panel-subtitle">Actor network graph, communities, bridges and centrality across the collected onion landscape</div>
        </div>
        <div style={{ display: "flex", gap: "0.5rem", alignItems: "center", flexWrap: "wrap" }}>
          <Link to="/evidence" data-testid="analyst-evidence-link">
            <Button variant="ghost" size="sm"><FileText size={13} /> Evidence</Button>
          </Link>
          <Link to="/wallets" data-testid="analyst-wallets-link">
            <Button variant="ghost" size="sm"><BarChart3 size={13} /> Wallets</Button>
          </Link>
          <Link to="/breaches" data-testid="analyst-breaches-link">
            <Button variant="ghost" size="sm"><ShieldAlert size={13} /> Breaches</Button>
          </Link>
          <Link to="/cases" data-testid="analyst-cases-link">
            <Button variant="ghost" size="sm"><AlertTriangle size={13} /> Cases / Ops</Button>
          </Link>
          <Link to="/registry" data-testid="analyst-back-link">
            <Button variant="outline" size="sm">
              <GitFork size={14} /> Back to Registry
            </Button>
          </Link>
        </div>
      </header>

      <section className="stat-grid" style={{ marginBottom: "1rem" }}>
        {metric(net?.n_nodes, "NODES")}
        {metric(net?.n_edges, "EDGES")}
        {metric(net?.n_communities, "COMMUNITIES")}
        {metric(getText(sum, 0), "DENSITY")}
      </section>

      <section className="console-panel graph-panel" data-testid="analyst-graph-panel">
        <div className="panel-heading">
          <div>
            <div className="section-kicker">
              <Link2 size={14} /> FULL CONTACT NETWORK <span className="mono">/ CYTOSCAPE</span>
            </div>
            <div className="panel-subtitle">Select a node to inspect it. Click an actor row below to open its contract.</div>
          </div>
          <div className="graph-legend">
            <span><i className="legend-dot actor" /> actor</span>
            <span><i className="legend-dot identity" /> identity</span>
            <span><i className="legend-dot site" /> site</span>
            <span><i className="legend-dot finding" /> evidence</span>
          </div>
        </div>
        <div className="graph-stage">
          <GraphCanvas graph={graphQuery.data} activeId={selectedNode ? `actor:${getText(selectedNode.label ?? selectedNode.id)}` : undefined} onNodeSelect={setSelectedNode} />
        </div>
      </section>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: "1rem" }}>
        <section className="console-panel" data-testid="analyst-actors-panel">
          <div className="panel-heading">
            <div>
              <div className="section-kicker"><Users size={14} /> MOST CENTRAL ACTORS</div>
              <div className="panel-subtitle">Top-linked identities (eigenvector centrality)</div>
            </div>
          </div>
          <div className="inventory-table-wrap">
            <table className="inventory-table">
              <thead><tr><th>CENTRALITY</th><th>DEGREE</th><th>BETWEEN</th><th>COMMUNITY</th></tr></thead>
              <tbody>
                {byCentrality.map((row) => (
                  <tr key={row.id}>
                    <td className="mono inventory-value">{row.label}</td>
                    <td className="mono">{(row.degree * 100).toFixed(1)}%</td>
                    <td className="mono">{(row.betweenness * 100).toFixed(1)}%</td>
                    <td className="mono">{row.community}</td>
                  </tr>
                ))}
                {!byCentrality.length && <tr><td colSpan={4} className="muted-text">No centrality data — run a network analysis first.</td></tr>}
              </tbody>
            </table>
          </div>
        </section>

        <section className="console-panel" data-testid="analyst-bridges-panel">
          <div className="panel-heading">
            <div>
              <div className="section-kicker"><ShieldAlert size={14} /> BRIDGE ACTORS</div>
              <div className="panel-subtitle">Identities that connect communities — key pivot points</div>
            </div>
          </div>
          <div className="inventory-table-wrap">
            <table className="inventory-table">
              <thead><tr><th>HANDLE</th><th>COMMUNITIES CONNECTED</th></tr></thead>
              <tbody>
                {topBridges.map((bridge) => (
                  <tr key={bridge.id}>
                    <td className="mono inventory-value">{bridge.label}</td>
                    <td className="mono">{bridge.connects}</td>
                  </tr>
                ))}
                {!topBridges.length && <tr><td colSpan={2} className="muted-text">No bridge actors identified.</td></tr>}
              </tbody>
            </table>
          </div>
        </section>

        <section className="console-panel" data-testid="analyst-communities-panel">
          <div className="panel-heading">
            <div>
              <div className="section-kicker"><AlertTriangle size={14} /> TOP COMMUNITIES</div>
              <div className="panel-subtitle">Largest clusters in the link network</div>
            </div>
          </div>
          <div className="inventory-table-wrap">
            <table className="inventory-table">
              <thead><tr><th>CLUSTER</th><th>SIZE</th></tr></thead>
              <tbody>
                {topCommunities.map((community) => (
                  <tr key={community.id}>
                    <td className="mono inventory-value">{community.label || `Cluster ${community.id}`}</td>
                    <td className="mono">{community.size.toLocaleString()}</td>
                  </tr>
                ))}
                {!topCommunities.length && <tr><td colSpan={2} className="muted-text">No communities found.</td></tr>}
              </tbody>
            </table>
          </div>
        </section>
      </div>
      <footer className="console-footer" style={{ marginTop: "1.5rem" }}>
        <div>
          <span className="mono">DARKFORCE / ANALYST</span>
          <span className="footer-divider" /> {graphNodes.length.toLocaleString()} graph nodes · {(net?.n_edges ?? 0).toLocaleString()} edges · {(net?.n_communities ?? 0).toLocaleString()} communities
        </div>
        <div className="export-actions">
          <span className="micro-label">NIGHTLY DIGEST</span>
          <Button variant="ghost" size="sm" onClick={() => downloadNightlyDigest("json")} data-testid="digest-json-button"><FileJson size={13} /> JSON</Button>
          <Button variant="ghost" size="sm" onClick={() => downloadNightlyDigest("pdf")} data-testid="digest-pdf-button"><CloudDownload size={13} /> PDF</Button>
          <Button variant="ghost" size="sm" onClick={() => downloadNightlyDigest("md")} data-testid="digest-md-button"><FileText size={13} /> MD</Button>
        </div>
      </footer>
    </div>
  );
}