import { memo, useEffect, useMemo, useRef, useState, type MutableRefObject } from "react";
import cytoscape, { type Core, type ElementDefinition, type NodeSingular } from "cytoscape";
import type { GraphResponse, GraphNode } from "@/lib/darkforce";

import {
  EMPTY_FILTER,
  edgeId,
  isFilterActive,
  partitionGraph,
  type GraphFilter,
} from "./graphFilter";

export interface GraphApi {
  zoomIn(): void;
  zoomOut(): void;
  fit(): void;
  resize(): void;
  toggleLabels(): boolean;
  exportPng(): string | null;
}

export interface GraphFilters {
  minConfidence: number;
  searchQuery: string;
  excludedTypes: string[];
  excludedCategories: string[];
}

interface GraphCanvasProps {
  graph?: GraphResponse;
  activeId?: string;
  /** Removal-based filters. Optional: Home and Analyst render the graph with no
   *  sidebar controls, and graphElements treats every field as optional. */
  filters?: GraphFilters;
  onNodeSelect: (node: GraphNode | null) => void;
  apiRef?: MutableRefObject<GraphApi | null>;
  /**
   * Dimming filter from graphFilter.ts. Unlike `filters` (which drops nodes and
   * reflows the layout), a filtered element is only pushed back visually, so the
   * analyst keeps the shape of the graph and can still see what was excluded.
   */
  filter?: GraphFilter;
}

const ENTITY_TYPE_COLORS: Record<string, string> = {
  actor: "#52e1ec",
  site: "#e4b350",
  identity: "#86aaff",
  identifier: "#86aaff",
  btc: "#f7931a",
  xmr: "#ff6b00",
  pgp: "#8b5cf6",
  pgp_email: "#8b5cf6",
  jabber: "#06b6d4",
  onion: "#a855f7",
  handle: "#52e1ec",
  site: "#e4b350",
  finding: "#f27960",
  misconfig: "#f27960",
  post: "#a855f7",
};

const ENTITY_TYPE_SHAPES: Record<string, string> = {
  actor: "round-rectangle",
  site: "hexagon",
  identity: "ellipse",
  identifier: "ellipse",
  btc: "ellipse",
  xmr: "ellipse",
  pgp: "ellipse",
  pgp_email: "ellipse",
  jabber: "ellipse",
  onion: "ellipse",
  handle: "round-rectangle",
  finding: "cut-rectangle",
  misconfig: "cut-rectangle",
  post: "concave-hexagon",
};

const ENTITY_TYPE_SIZES: Record<string, { w: number; h: number }> = {
  actor: { w: 62, h: 35 },
  site: { w: 64, h: 64 },
  identity: { w: 58, h: 24 },
  identifier: { w: 58, h: 24 },
  btc: { w: 58, h: 24 },
  xmr: { w: 58, h: 24 },
  pgp: { w: 58, h: 24 },
  pgp_email: { w: 58, h: 24 },
  jabber: { w: 58, h: 24 },
  onion: { w: 58, h: 24 },
  handle: { w: 56, h: 28 },
  finding: { w: 60, h: 30 },
  misconfig: { w: 60, h: 30 },
  post: { w: 52, h: 30 },
};

const SAFETY_COLORS: Record<string, string> = {
  safe: "#22c55e",
  suspicious: "#f59e0b",
  malicious: "#ef4444",
  ransomware: "#dc2626",
  malware: "#dc2626",
  phishing: "#f97316",
  unknown: "#6b7280",
};

function graphElements(graph?: GraphResponse, filters?: GraphFilters): ElementDefinition[] {
  const nodes = graph?.nodes ?? graph?.elements?.nodes ?? [];
  const edges = graph?.edges ?? graph?.elements?.edges ?? [];

  // Only category exclusion drops nodes here. Type exclusion is a dimming filter
  // (see `filter` / graphFilter.ts): removing the nodes would reflow the cose
  // layout and hide that the excluded nodes existed at all.
  const filteredNodes = nodes.filter((node) => {
    const category = node.category ?? "unknown";
    if (filters?.excludedCategories?.includes(category)) return false;
    return true;
  });

  return [
    ...filteredNodes.map((node) => {
      const entityType = node.entity_type ?? node.type ?? node.kind ?? "entity";
      const category = node.category ?? "unknown";
      const confidence = node.confidence ?? (node as { meta?: { conf?: number } }).meta?.conf ?? node.meta?.conf ?? 0;
      const safety = node.safety ?? node.safety_status ?? "unknown";
      const label = node.label ?? node.handle ?? node.name ?? node.id;

      const searchMatch = filters?.searchQuery
        ? label.toLowerCase().includes(filters.searchQuery.toLowerCase())
        : false;

      const belowConfidence = confidence < (filters?.minConfidence ?? 0);

      return {
        group: "nodes" as const,
        data: {
          ...node,
          id: node.id,
          label,
          entityType,
          category,
          confidence,
          safety,
          searchMatch,
          belowConfidence,
        },
        classes: [
          searchMatch ? "search-match" : "",
          belowConfidence ? "below-confidence" : "",
        ].filter(Boolean).join(" "),
      };
    }),
    ...edges.map((edge, index) => ({
      group: "edges" as const,
      data: {
        ...edge,
        // Shared with graphFilter.partitionGraph: the dimming pass matches edge
        // ids against the visible set, so if the two derived ids by different
        // rules every edge would dim the moment a relationship filter is used.
        id: edgeId(edge, index),
        source: edge.source ?? edge.s,
        target: edge.target ?? edge.t,
        label: edge.label ?? edge.relation ?? edge.e ?? "linked",
        confidence: edge.confidence ?? edge.w ?? 0,
      },
    })),
  ];
}

const NODE_BASE_STYLE = {
  "label": "data(label)",
  "font-family": "JetBrains Mono, monospace",
  "font-size": "9px",
  "color": "#d9e6e9",
  "text-wrap": "wrap",
  "text-max-width": "58px",
  "text-valign": "bottom",
  "text-halign": "center",
  "text-margin-y": 6,
  "background-color": "#11191d",
  "border-width": 2,
  "border-color": "#29c4d3",
  "width": 30,
  "height": 30,
  "overlay-opacity": 0,
  "overlay-padding": 6,
};

export default memo(function GraphCanvas({ graph, activeId, filters, onNodeSelect, apiRef, filter }: GraphCanvasProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const selectedIdRef = useRef(activeId);
  const onSelectRef = useRef(onNodeSelect);
  onSelectRef.current = onNodeSelect;
  const labelsRef = useRef(true);
  // Tracked here as well as in the parent so the neighbourhood filter can react
  // to a tap without the parent having to hand the id back down.
  const [tappedId, setTappedId] = useState<string | null>(null);

  const elements = useMemo(() => graphElements(graph, filters), [graph, filters]);
  const activeFilter = filter ?? EMPTY_FILTER;

  const focusNode = (cy: Core, node: NodeSingular) => {
    cy.nodes().removeClass("selected");
    cy.elements().removeClass("selected");
    cy.elements().addClass("dimmed");
    node.removeClass("dimmed");
    node.neighborhood().removeClass("dimmed");
    node.addClass("selected");
  };

  useEffect(() => {
    selectedIdRef.current = activeId;
    const cy = cyRef.current;
    if (!cy) return;
    cy.elements().removeClass("dimmed");
    cy.nodes().removeClass("selected");
    if (activeId) {
      const node = cy.getElementById(activeId);
      if (node.length) {
        focusNode(cy, node);
        cy.animate({ center: { eles: node }, duration: 350 });
      }
    }
  }, [activeId]);

  useEffect(() => {
    if (!containerRef.current) return;

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      minZoom: 0.1,
      maxZoom: 5,
      wheelSensitivity: 0.15,
      style: [
        // Base node
        { selector: "node", style: NODE_BASE_STYLE },

        // Entity type specific shapes and colors
        { selector: "node[entityType = 'actor']", style: { "shape": "round-rectangle", "width": 62, "height": 35, "font-size": "9px", "border-width": 2, "border-color": "#52e1ec", "background-color": "#0c1a1d" } },
        { selector: "node[entityType = 'site']", style: { "shape": "hexagon", "width": 64, "height": 64, "font-size": "9px", "border-width": 2, "border-color": "#e4b350", "background-color": "#1a160c" } },
        { selector: "node[entityType = 'identity'], node[entityType = 'identifier'], node[entityType = 'btc'], node[entityType = 'xmr'], node[entityType = 'pgp'], node[entityType = 'pgp_email'], node[entityType = 'jabber'], node[entityType = 'onion']", style: { "shape": "ellipse", "width": 58, "height": 24, "font-size": "8px", "border-width": 1.5, "border-color": "#86aaff", "background-color": "#0c1426" } },
        { selector: "node[entityType = 'handle']", style: { "shape": "round-rectangle", "width": 56, "height": 28, "font-size": "8px", "border-width": 1.5, "border-color": "#52e1ec", "background-color": "#0c1a1d" } },
        { selector: "node[entityType = 'finding'], node[entityType = 'misconfig']", style: { "shape": "cut-rectangle", "width": 60, "height": 30, "font-size": "8px", "border-width": 2, "border-color": "#f27960", "background-color": "#2a0c0c" } },
        { selector: "node[entityType = 'post']", style: { "shape": "concave-hexagon", "width": 52, "height": 30, "font-size": "7px", "border-width": 1.5, "border-color": "#a855f7", "background-color": "#1a0c26" } },

        // Safety status borders
        { selector: "node[safety = 'safe']", style: { "border-width": 3, "border-color": "#22c55e", "background-color": "#0c1a0c" } },
        { selector: "node[safety = 'suspicious']", style: { "border-width": 3, "border-color": "#f59e0b", "background-color": "#1a160c" } },
        { selector: "node[safety = 'malicious'], node[safety = 'ransomware'], node[safety = 'malware'], node[safety = 'phishing']", style: { "border-width": 3, "border-color": "#ef4444", "background-color": "#2a0c0c", "overlay-color": "#ef4444", "overlay-opacity": 0.15, "overlay-padding": 6 } },

        // Search match highlight
        { selector: "node.search-match", style: { "border-width": 4, "border-color": "#fff", "overlay-color": "#fff", "overlay-opacity": 0.3, "overlay-padding": 8 } },

        // Below confidence threshold
        { selector: "node.below-confidence", style: { "opacity": 0.15 } },

        // Selected node
        { selector: "node.selected", style: { "border-width": 3, "border-color": "#fff", "background-color": "#29c4d3", "overlay-color": "#29c4d3", "overlay-opacity": 0.14, "overlay-padding": 8 } },

        // Hover
        { selector: "node.hover", style: { "border-width": 2.5, "border-color": "#fff" } },

        // Dimmed
        { selector: "node.dimmed", style: { "opacity": 0.15 } },
        { selector: "edge.dimmed", style: { "opacity": 0.06 } },

        // Dimming filter (graphFilter.ts). These elements stay on the canvas so
        // the graph keeps its shape; they are only pushed back visually. Declared
        // after .selected so a node the analyst is inspecting is never dimmed by
        // its own filter.
        { selector: "node.filtered", style: { "opacity": 0.13, "text-opacity": 0.08 } },
        { selector: "edge.filtered", style: { "opacity": 0.05, "text-opacity": 0 } },
        { selector: "node.filtered:selected", style: { "opacity": 1, "text-opacity": 1 } },
        { selector: "edge.filtered:selected", style: { "opacity": 1, "text-opacity": 1 } },

        // Base edge
        {
          selector: "edge",
          style: {
            "width": "mapData(confidence, 0, 1, 1, 4)",
            "line-color": "#26373d",
            "target-arrow-shape": "triangle",
            "target-arrow-color": "#26373d",
            "curve-style": "bezier",
            "label": "data(label)",
            "font-size": "7px",
            "color": "#6e858c",
            "font-family": "JetBrains Mono, monospace",
            "text-rotation": "autorotate",
            "text-background-color": "#080c0f",
            "text-background-opacity": 0.9,
            "text-background-padding": "2px",
            "text-outline-width": 0,
          }
        },

        // Edge confidence tiers
        { selector: "edge[confidence >= 0.75]", style: { "line-color": "#29c4d3", "target-arrow-color": "#29c4d3", "target-arrow-fill": "filled" } },
        { selector: "edge[confidence >= 0.4][confidence < 0.75]", style: { "target-arrow-shape": "circle", "target-arrow-fill": "hollow" } },
        { selector: "edge[confidence < 0.4]", style: { "line-style": "dashed", "line-color": "#4a5a5f", "target-arrow-color": "#4a5a5f", "target-arrow-shape": "vee", "target-arrow-fill": "hollow" } },

        // Safety edge indicators
        { selector: "edge[sourceSafety = 'malicious'], edge[targetSafety = 'malicious']", style: { "line-color": "#ef4444", "target-arrow-color": "#ef4444", "line-style": "dashed" } },
      ],
      layout: {
        name: "cose",
        animate: false,
        fit: true,
        padding: 90,
        nodeRepulsion: 18000,
        nodeOverlap: 20,
        idealEdgeLength: 180,
        edgeElasticity: 100,
        gravity: 0.1,
        componentSpacing: 150,
        coolingFactor: 0.9,
        randomize: false,
      },
    });

    cyRef.current = cy;
    if (!labelsRef.current) {
      cy.style().selector("node").style("label", " ").update();
    }

    cy.on("tap", "node", (event) => {
      focusNode(cy, event.target);
      setTappedId(String(event.target.id()));
      onSelectRef.current(event.target.data() as GraphNode);
    });
    cy.on("tap", (event) => {
      if (event.target === cy) {
        cy.elements().removeClass("dimmed");
        cy.nodes().removeClass("selected");
        setTappedId(null);
        onSelectRef.current(null);
      }
    });
    cy.on("mouseover", "node", (event) => event.target.addClass("hover"));
    cy.on("mouseout", "node", (event) => event.target.removeClass("hover"));

    if (selectedIdRef.current) {
      const selected = cy.getElementById(selectedIdRef.current);
      if (selected.length) focusNode(cy, selected);
    }

    const api: GraphApi = {
      zoomIn: () => { const c = cyRef.current; if (c) c.zoom(c.zoom() * 1.2); },
      zoomOut: () => { const c = cyRef.current; if (c) c.zoom(c.zoom() / 1.2); },
      fit: () => { const c = cyRef.current; if (c) c.fit(undefined, 50); },
      resize: () => { const c = cyRef.current; if (c) { c.resize(); c.fit(undefined, 50); } },
      toggleLabels: () => {
        const c = cyRef.current;
        if (!c) return labelsRef.current;
        labelsRef.current = !labelsRef.current;
        c.style().selector("node").style("label", labelsRef.current ? "data(label)" : " ").update();
        return labelsRef.current;
      },
      exportPng: () => {
        const c = cyRef.current;
        if (!c) return null;
        return c.png({ full: true, scale: 2 });
      },
    };
    if (apiRef) apiRef.current = api;

    return () => {
      cy.destroy();
      cyRef.current = null;
      if (apiRef) apiRef.current = null;
    };
  }, [elements, filters]);

  // Apply the dimming filter by class rather than removing elements, so toggling
  // a filter never reflows the cose layout or loses the surrounding shape.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.elements().removeClass("filtered");
    if (!isFilterActive(activeFilter) && !tappedId) return;
    const { visibleNodeIds, visibleEdgeIds } = partitionGraph(graph, activeFilter, tappedId);
    cy.batch(() => {
      cy.nodes().forEach((node) => {
        // Never dim the node the analyst is currently inspecting.
        if (!visibleNodeIds.has(String(node.id())) && String(node.id()) !== tappedId) node.addClass("filtered");
      });
      cy.edges().forEach((edge) => {
        if (!visibleEdgeIds.has(String(edge.id()))) edge.addClass("filtered");
      });
    });
  }, [activeFilter, graph, tappedId, elements]);

  return <div id="cy" ref={containerRef} className="h-full min-h-[420px] w-full" data-testid="relationship-graph-canvas" />;
});

function focusNode(cy: Core, node: NodeSingular) {
  cy.nodes().removeClass("selected");
  cy.elements().removeClass("selected");
  cy.elements().addClass("dimmed");
  node.removeClass("dimmed");
  node.neighborhood().removeClass("dimmed");
  node.addClass("selected");
}