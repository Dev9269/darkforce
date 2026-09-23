import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, ArrowLeft, LoaderCircle, Network, SlidersHorizontal, ZoomIn, ZoomOut, RotateCcw, Maximize2, Minimize2, Tags, Filter } from "lucide-react";
import { Link } from "react-router-dom";
import GraphCanvas, { type GraphApi } from "@/components/GraphCanvas";
import { getGraph, getText, type GraphNode } from "@/lib/darkforce";

export default function GraphPage() {
  const [minConf, setMinConf] = useState(0.6);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [showLabels, setShowLabels] = useState(true);
  const graphApiRef = useState<GraphApi | null>(null);

  const graphQuery = useQuery({
    queryKey: ["graph", minConf],
    queryFn: () => getGraph("", minConf),
    refetchInterval: 15000,
    retry: false,
  });

  const nodes = graphQuery.data?.nodes ?? graphQuery.data?.elements?.nodes ?? [];
  const edges = graphQuery.data?.edges ?? graphQuery.data?.elements?.edges ?? [];

  const toggleGraphLabels = () => setShowLabels(graphApiRef.current?.toggleLabels() ?? false);
  const toggleFullscreen = () => {
    setIsFullscreen((value) => !value);
    window.setTimeout(() => graphApiRef.current?.resize(), 90);
  };

  useEffect(() => {
    document.body.classList.toggle("graph-fullscreen-open", isFullscreen);
    if (!isFullscreen) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") toggleFullscreen();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [isFullscreen]);

  const graphToolbar = (
    <div className="graph-toolbar" data-testid="graph-toolbar">
      <button type="button" title="Zoom out" onClick={() => graphApiRef.current?.zoomOut()}><ZoomOut size={14} /></button>
      <button type="button" title="Zoom in" onClick={() => graphApiRef.current?.zoomIn()}><ZoomIn size={14} /></button>
      <button type="button" title="Fit the whole graph on screen" onClick={() => graphApiRef.current?.fit()}><RotateCcw size={14} /></button>
      <button type="button" title={showLabels ? "Hide names" : "Show names"} onClick={toggleGraphLabels}><Tags size={14} /></button>
      <button type="button" className="graph-fullscreen-btn" title={isFullscreen ? "Exit full screen (Esc)" : "Full screen"} onClick={toggleFullscreen} aria-label={isFullscreen ? "Exit full screen" : "Open graph full screen"}>
        {isFullscreen ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
        <span className="toolbar-label">{isFullscreen ? "Exit full" : "Full screen"}</span>
      </button>
    </div>
  );

  return (
    <div className="console-shell registry-shell" data-testid="graph-page">
      <nav className="registry-nav">
        <Link to="/" className="registry-back"><ArrowLeft size={14} /> DARKFORCE CONSOLE</Link>
        <Link to="/analyst" className="registry-back" data-testid="graph-analyst-link"><Network size={14} /> ANALYST</Link>
        <span className="registry-title"><Network size={14} /> RELATIONSHIP GRAPH</span>
        <span className="mono registry-total">{nodes.length} NODES · {edges.length} EDGES</span>
      </nav>
      <main className="console-main">
        <section className="console-panel" data-testid="graph-controls-panel">
          <div className="panel-heading">
            <div>
              <div className="section-kicker"><SlidersHorizontal size={14} /> GRAPH FILTERS</div>
              <div className="panel-subtitle">Adjust minimum confidence to focus on strongest relationships. Lower = more edges, higher = tighter clusters.</div>
            </div>
          </div>
          <div className="graph-filter-row">
            <label className="filter-control" htmlFor="min-conf">
              <span className="filter-label"><Filter size={12} /> MIN CONFIDENCE</span>
              <input
                type="range"
                id="min-conf"
                min="0"
                max="1"
                step="0.05"
                value={minConf}
                onChange={(event) => setMinConf(Number(event.target.value))}
                className="filter-slider"
                aria-label="Minimum confidence threshold"
              />
              <span className="filter-value mono">{(minConf * 100).toFixed(0)}%</span>
            </label>
          </div>
        </section>

        <section className="console-panel graph-panel" data-testid="graph-main-panel">
          <div className="panel-heading">
            <div>
              <div className="section-kicker">
                <Network size={14} /> RELATIONSHIP GRAPH <span className="mono">/ CYTOSCAPE</span>
              </div>
              <div className="panel-subtitle">Click a node to inspect its relationship context. Confidence filter: <strong>≥ {(minConf * 100).toFixed(0)}%</strong></div>
            </div>
            <div className="graph-legend">
              <span><i className="legend-dot actor" /> person</span>
              <span><i className="legend-dot identity" /> identity / credential</span>
              <span><i className="legend-dot site" /> website</span>
              <span><i className="legend-dot finding" /> clue / finding</span>
            </div>
          </div>
          <div className={`graph-stage${isFullscreen ? " graph-stage-fullscreen" : ""}`} data-testid="graph-main-stage">
            {graphToolbar}
            {isFullscreen && (
              <div className="graph-fs-title" data-testid="graph-fullscreen-title">RELATIONSHIP GRAPH <em>click a dot to inspect · drag to move · scroll to zoom · Esc to exit</em></div>
            )}
            <GraphCanvas
              graph={graphQuery.data}
              activeId={undefined}
              onNodeSelect={(node) => console.log("Node selected:", node)}
              apiRef={graphApiRef}
            />
          </div>
        </section>
      </main>
    </div>
  );
}