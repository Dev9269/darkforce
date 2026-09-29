import { useState, useEffect, useCallback, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, ArrowLeft, LoaderCircle, Layers, Network, SlidersHorizontal, ZoomIn, ZoomOut, RotateCcw, Maximize2, Minimize2, Tags, Filter, Search, Users, Globe, Shield, Database, Download, Minimize2 as Minimize2Icon, Maximize2 as Maximize2Icon, Copy, Check, X } from "lucide-react";
import { Link, useSearchParams } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import GraphCanvas, { type GraphApi, type GraphFilters } from "@/components/GraphCanvas";
import GraphFilterBar from "@/components/GraphFilterBar";
import {
  EMPTY_FILTER,
  graphFacets,
  toggleValue,
  visibleCounts,
  type GraphFilter,
} from "@/components/graphFilter";
import { getGraph, getCategories, getText, clampConfidence, type GraphNode } from "@/lib/darkforce";

const SAFETY_COLORS: Record<string, string> = {
  safe: "#22c55e",
  suspicious: "#f59e0b",
  malicious: "#ef4444",
  ransomware: "#dc2626",
  malware: "#dc2626",
  phishing: "#f97316",
  unknown: "#6b7280",
};

const ENTITY_TYPES = [
  { id: "actor", label: "Actors", icon: Users, color: "#52e1ec" },
  { id: "site", label: "Darknet Sites", icon: Globe, color: "#e4b350" },
  { id: "identity", label: "Credentials", icon: Shield, color: "#86aaff" },
  { id: "finding", label: "Evidence", icon: Database, color: "#f27960" },
  { id: "handle", label: "Handles", icon: Users, color: "#52e1ec" },
  { id: "identifier", label: "Identifiers", icon: Shield, color: "#86aaff" },
  { id: "btc", label: "BTC Wallets", icon: Database, color: "#f7931a" },
  { id: "xmr", label: "XMR Wallets", icon: Database, color: "#ff6b00" },
  { id: "pgp", label: "PGP Keys", icon: Shield, color: "#8b5cf6" },
  { id: "onion", label: "Onion Services", icon: Globe, color: "#a855f7" },
  { id: "finding2", label: "Findings", icon: AlertTriangle, color: "#f27960" },
  { id: "misconfig", label: "Misconfigs", icon: AlertTriangle, color: "#f27960" },
  { id: "post", label: "Posts", icon: Database, color: "#a855f7" },
];

export default function GraphPage() {
  const [searchParams] = useSearchParams();
  const initialConf = clampConfidence(Number.parseFloat(searchParams.get("min_conf") ?? ""));
  // Single source of truth for every filter on this page. The sidebar controls
  // and the relationship filter bar both read and write this object, so the two
  // UIs can never disagree about what is currently hidden.
  const [filter, setFilter] = useState<GraphFilter>(() => ({
    ...EMPTY_FILTER,
    minConfidence: Number.isNaN(initialConf) ? 0.6 : initialConf,
  }));
  const [excludedCategories, setExcludedCategories] = useState<string[]>([]);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [showLabels, setShowLabels] = useState(true);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const graphApiRef = useState<GraphApi | null>(null);

  const minConf = filter.minConfidence;
  const searchQuery = filter.query;
  const excludedTypes = filter.hiddenTypes;

  const setMinConf = useCallback((value: number) => {
    setFilter((prev) => ({ ...prev, minConfidence: value }));
  }, []);

  const setSearchQuery = useCallback((value: string) => {
    setFilter((prev) => ({ ...prev, query: value }));
  }, []);

  const filters: GraphFilters = {
    minConfidence: minConf,
    searchQuery,
    excludedTypes,
    excludedCategories,
  };

  const graphQuery = useQuery({
    queryKey: ["graph", minConf, searchQuery, excludedTypes, excludedCategories],
    queryFn: () => getGraph("", minConf),
    refetchInterval: 15000,
    retry: false,
  });

  const categoriesQuery = useQuery({
    queryKey: ["categories"],
    queryFn: getCategories,
    retry: false,
  });

  const categories = categoriesQuery.data?.categories ?? [];
  const categoryCounts = categoriesQuery.data?.counts ?? {};

  const nodes = graphQuery.data?.nodes ?? graphQuery.data?.elements?.nodes ?? [];
  const edges = graphQuery.data?.edges ?? graphQuery.data?.elements?.edges ?? [];

  const toggleType = useCallback((type: string) => {
    setFilter((prev) => ({ ...prev, hiddenTypes: toggleValue(prev.hiddenTypes, type) }));
  }, []);

  const toggleCategory = useCallback((cat: string) => {
    setExcludedCategories((prev) => prev.includes(cat) ? prev.filter((c) => c !== cat) : [...prev, cat]);
  }, []);

  const clearAllFilters = useCallback(() => {
    setFilter({ ...EMPTY_FILTER, minConfidence: 0 });
    setExcludedCategories([]);
  }, []);

  const graphFacetsData = useMemo(() => graphFacets(graphQuery.data), [graphQuery.data]);
  const graphCounts = useMemo(
    () => visibleCounts(graphQuery.data, filter, selectedNode ? String(selectedNode.id) : null),
    [graphQuery.data, filter, selectedNode],
  );

  const toggleGraphLabels = useCallback(() => setShowLabels(graphApiRef.current?.toggleLabels() ?? false), []);
  const toggleFullscreen = useCallback(() => {
    setIsFullscreen((value) => !value);
    window.setTimeout(() => graphApiRef.current?.resize(), 90);
  }, []);

  const exportImage = useCallback(() => {
    const data = graphApiRef.current?.exportPng();
    if (data) {
      const link = document.createElement("a");
      link.download = "network-capture.png";
      link.href = data;
      link.click();
    }
  }, []);

  useEffect(() => {
    document.body.classList.toggle("graph-fullscreen-open", isFullscreen);
    if (!isFullscreen) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") toggleFullscreen();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [isFullscreen, toggleFullscreen]);

  const graphToolbar = (
    <div className="graph-toolbar" data-testid="graph-toolbar">
      <div className="graph-toolbar-group" data-testid="graph-toolbar-zoom">
        <button type="button" title="Zoom out" aria-label="Zoom out" onClick={() => graphApiRef.current?.zoomOut()}><ZoomOut size={14} /></button>
        <button type="button" title="Zoom in" aria-label="Zoom in" onClick={() => graphApiRef.current?.zoomIn()}><ZoomIn size={14} /></button>
        <button type="button" title="Fit the whole graph on screen" aria-label="Fit graph to screen" onClick={() => graphApiRef.current?.fit()}><RotateCcw size={14} /></button>
      </div>
      <i className="graph-toolbar-sep" />
      <div className="graph-toolbar-group" data-testid="graph-toolbar-view">
        <button type="button" title={showLabels ? "Hide names" : "Show names"} aria-label={showLabels ? "Hide names" : "Show names"} onClick={toggleGraphLabels} className={showLabels ? "is-on" : ""}><Tags size={14} /></button>
      </div>
      <i className="graph-toolbar-sep" />
      <div className="graph-toolbar-group" data-testid="graph-toolbar-export">
        <button type="button" title="Export as PNG" aria-label="Export as PNG" onClick={exportImage}><Download size={14} /></button>
        <button type="button" className="graph-fullscreen-btn" title={isFullscreen ? "Exit full screen (Esc)" : "Full screen"} onClick={toggleFullscreen} aria-label={isFullscreen ? "Exit full screen" : "Open graph full screen"}>
          {isFullscreen ? <Minimize2Icon size={14} /> : <Maximize2Icon size={14} />}
          <span className="toolbar-label">{isFullscreen ? "Exit full" : "Full screen"}</span>
        </button>
      </div>
    </div>
  );

  const categoryChips = (
    <div className="graph-filter-bar" data-testid="graph-category-filter">
      <div className="graph-filter-label"><Filter size={12} /> CATEGORY</div>
      <div className="graph-filter-chips">
        <button
          type="button"
          className={`graph-cat-chip is-all ${excludedCategories.length === 0 ? "active" : ""}`}
          onClick={() => setExcludedCategories([])}
          data-testid="graph-cat-chip-all"
        >
          ALL <span className="chip-count">{categories.length}</span>
        </button>
        {categories.map((cat) => {
          const excluded = excludedCategories.includes(cat);
          return (
            <button
              type="button"
              key={cat}
              className={`graph-cat-chip ${excluded ? "is-excluded" : "active"}`}
              onClick={() => toggleCategory(cat)}
              data-testid={`graph-cat-chip-${cat}`}
              title={excluded ? `Show ${cat}` : `Hide ${cat}`}
            >
              <span className="capitalize">{cat}</span>
              <span className="chip-count">{categoryCounts[cat] ?? 0}</span>
            </button>
          );
        })}
      </div>
      {excludedCategories.length > 0 && (
        <button
          type="button"
          className="graph-filter-clear"
          onClick={() => setExcludedCategories([])}
          data-testid="graph-category-clear"
        >
          <X size={11} /> RESET
        </button>
      )}
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
        <aside className="w-80 border-r border-border bg-card/50 p-4 flex flex-col gap-6" data-testid="graph-sidebar">
          <div>
            <label className="section-kicker mb-3 flex items-center gap-2">
              <Search size={12} /> SEARCH NODES
            </label>
            <Input
              placeholder="Find handle, domain, or identity..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-background/50"
            />
          </div>

          <div>
            <label className="section-kicker mb-3 flex items-center gap-2">
              <Filter size={12} /> CONFIDENCE THRESHOLD
            </label>
            <input
              type="range"
              min="0"
              max="1"
              step="0.05"
              className="w-full accent-primary"
              value={minConf}
              onChange={(e) => setMinConf(parseFloat(e.target.value))}
              aria-label="Minimum confidence threshold"
            />
            <div className="flex justify-between text-[10px] mono mt-1 text-muted-foreground">
              <span>0%</span>
              <span className="text-primary font-bold">{(minConf * 100).toFixed(0)}%</span>
              <span>100%</span>
            </div>
          </div>

          <div>
            <label className="section-kicker mb-3 flex items-center gap-2">
              <Layers size={12} /> ENTITY VISIBILITY
            </label>
            <div className="grid gap-2">
              {ENTITY_TYPES.map((type) => (
                <button
                  key={type.id}
                  onClick={() => toggleType(type.id)}
                  className={`flex items-center justify-between rounded border px-3 py-2 transition-all ${
                    excludedTypes.includes(type.id)
                      ? "border-transparent opacity-40"
                      : "border-border bg-background"
                  }`}
                >
                  <div className="flex items-center gap-2 text-xs font-medium">
                    <type.icon size={14} style={{ color: type.color }} />
                    {type.label}
                  </div>
                  <div className={`h-2 w-2 rounded-full`} style={{ backgroundColor: type.color }} />
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="section-kicker mb-3 flex items-center gap-2">
              <Tags size={12} /> CATEGORY FILTER
            </label>
            <div className="grid gap-1 max-h-60 overflow-y-auto">
              {categories.map((cat) => {
                const count = categoryCounts[cat] ?? 0;
                return (
                  <button
                    key={cat}
                    onClick={() => toggleCategory(cat)}
                    className={`flex items-center justify-between rounded border px-3 py-1.5 text-xs transition-all ${
                      excludedCategories.includes(cat)
                        ? "border-transparent opacity-40"
                        : "border-border bg-background"
                    }`}
                  >
                    <span className="capitalize">{cat}</span>
                    <span className="mono text-[10px] text-muted-foreground">{count}</span>
                  </button>
                );
              })}
            </div>
            {(excludedTypes.length > 0 || excludedCategories.length > 0 || searchQuery || minConf > 0) && (
              <Button variant="ghost" size="sm" className="w-full mt-2 text-[10px]" onClick={clearAllFilters}>
                <X size={10} /> Clear All Filters
              </Button>
            )}
          </div>

          <div className="mt-auto">
            <Button variant="outline" className="w-full" onClick={exportImage}>
              <Download size={14} /> Export Image
            </Button>
          </div>
        </aside>

        <main className="relative flex-1">
          <section className="console-panel graph-panel" data-testid="graph-main-panel">
            <div className="panel-heading">
              <div>
                <div className="section-kicker">
                  <Network size={14} /> RELATIONSHIP GRAPH <span className="mono">/ CYTOSCAPE</span>
                </div>
                <div className="panel-subtitle">
                  Click a node to inspect. Filters: <strong>Confidence ≥ {(minConf * 100).toFixed(0)}%</strong>
                  {searchQuery && <span className="ml-2">| Search: <strong>"{searchQuery}"</strong></span>}
                  {excludedTypes.length > 0 && <span className="ml-2">| Hidden types: <strong>{excludedTypes.length}</strong></span>}
                  {excludedCategories.length > 0 && <span className="ml-2">| Hidden categories: <strong>{excludedCategories.length}</strong></span>}
                </div>
              </div>
              <div className="graph-legend">
                <span><i className="legend-dot actor" style={{ background: "#52e1ec" }} /> person</span>
                <span><i className="legend-dot site" style={{ background: "#e4b350" }} /> site</span>
                <span><i className="legend-dot identity" style={{ background: "#86aaff" }} /> identity</span>
                <span><i className="legend-dot finding" style={{ background: "#f27960" }} /> evidence</span>
              </div>
            </div>
            {categoryChips}
            <GraphFilterBar
              facets={graphFacetsData}
              filter={filter}
              onChange={setFilter}
              shownNodes={graphCounts.nodes}
              shownEdges={graphCounts.edges}
              selectedLabel={selectedNode ? getText(selectedNode.label ?? selectedNode.id) : null}
              testId="graph-relationship-filter"
            />
            <div className={`graph-stage${isFullscreen ? " graph-stage-fullscreen" : ""}`} data-testid="graph-main-stage">
              {graphToolbar}
              {isFullscreen && (
                <div className="graph-fs-title" data-testid="graph-fullscreen-title">RELATIONSHIP GRAPH <em>click a dot to inspect · drag to move · scroll to zoom · Esc to exit</em></div>
              )}
              <GraphCanvas
                graph={graphQuery.data}
                filters={filters}
                filter={filter}
                onNodeSelect={setSelectedNode}
                apiRef={graphApiRef}
              />
            </div>
          </section>
        </main>

        {selectedNode && (
          <div className="absolute right-6 top-6 w-72 rounded-lg border border-primary/50 bg-card/95 p-4 shadow-2xl backdrop-blur animate-in fade-in slide-in-from-right-4 z-20" data-testid="node-inspector">
            <div className="flex items-center justify-between mb-3">
              <div className="section-kicker text-primary">NODE INSPECTOR</div>
              <button onClick={() => setSelectedNode(null)} className="text-muted-foreground hover:text-foreground p-1"><X size={14} /></button>
            </div>
            <h3 className="font-mono text-lg font-bold text-foreground break-all leading-tight mb-2">
              {selectedNode.label}
            </h3>
            <div className="mb-3 grid gap-2">
              <div className="flex justify-between items-center border-b border-border pb-2">
                <span className="text-[10px] text-muted-foreground uppercase">Entity Type</span>
                <span className="text-xs font-bold uppercase text-primary">{selectedNode.entityType}</span>
              </div>
              <div className="flex justify-between items-center border-b border-border pb-2">
                <span className="text-[10px] text-muted-foreground uppercase">Category</span>
                <span className="text-xs font-bold capitalize">{selectedNode.category ?? "unknown"}</span>
              </div>
              <div className="flex justify-between items-center border-b border-border pb-2">
                <span className="text-[10px] text-muted-foreground uppercase">Confidence</span>
                <span className="text-xs font-bold mono">{Math.round(selectedNode.confidence * 100)}%</span>
              </div>
              {selectedNode.safety && (
                <div className="flex justify-between items-center border-b border-border pb-2">
                  <span className="text-[10px] text-muted-foreground uppercase">Safety Status</span>
                  <span className="text-xs font-bold" style={{ color: SAFETY_COLORS[selectedNode.safety] ?? "#6b7280" }}>
                    {selectedNode.safety.toUpperCase()}
                  </span>
                </div>
              )}
              {selectedNode.safety === "malicious" || selectedNode.safety === "ransomware" || selectedNode.safety === "malware" ? (
                <div className="flex justify-between items-center border-b border-border pb-2 text-destructive">
                  <span className="text-[10px] text-muted-foreground uppercase">⚠ THREAT DETECTED</span>
                  <AlertTriangle size={12} />
                </div>
              ) : null}
            </div>
            <div className="mt-3">
              <p className="text-[11px] leading-relaxed text-muted-foreground italic">
                Transitive relationships detected. Click connected nodes to expand investigation.
              </p>
            </div>
            <Button variant="secondary" size="sm" className="mt-4 w-full text-[10px]" onClick={() => setSelectedNode(null)}>
              Close Inspector
            </Button>
          </div>
        )}

        {selectedNode && (
          <div className="absolute inset-0" onClick={() => setSelectedNode(null)} />
        )}
      </main>
    </div>
  );
}