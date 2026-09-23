import { memo, useEffect, useMemo, useRef, type MutableRefObject } from "react";
import cytoscape, { type Core, type ElementDefinition, type NodeSingular } from "cytoscape";
import type { GraphResponse, GraphNode } from "@/lib/darkforce";

export interface GraphApi {
  zoomIn(): void;
  zoomOut(): void;
  fit(): void;
  resize(): void;
  toggleLabels(): boolean;
}

interface GraphCanvasProps {
  graph?: GraphResponse;
  activeId?: string;
  onNodeSelect: (node: GraphNode | null) => void;
  apiRef?: MutableRefObject<GraphApi | null>;
}

function graphElements(graph?: GraphResponse): ElementDefinition[] {
  const nodes = graph?.nodes ?? graph?.elements?.nodes ?? [];
  const edges = graph?.edges ?? graph?.elements?.edges ?? [];
  return [
    ...nodes.map((node) => ({
      group: "nodes" as const,
      data: {
        ...node,
        id: node.id,
        label: node.label ?? node.handle ?? node.name ?? node.id,
        entityType: node.entity_type ?? node.type ?? node.kind ?? "entity",
        confidence: node.confidence ?? (node as { meta?: { conf?: number } }).meta?.conf ?? 0,
      },
    })),
    ...edges.map((edge, index) => ({
      group: "edges" as const,
      data: {
        ...edge,
        id: edge.id ?? `edge-${index}-${edge.source}-${edge.target}`,
        source: edge.source ?? edge.s,
        target: edge.target ?? edge.t,
        label: edge.label ?? edge.relation ?? edge.e ?? "linked",
        confidence: edge.confidence ?? edge.w ?? 0,
      },
    })),
  ];
}

export default memo(function GraphCanvas({ graph, activeId, onNodeSelect, apiRef }: GraphCanvasProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const selectedIdRef = useRef(activeId);
  const onSelectRef = useRef(onNodeSelect);
  onSelectRef.current = onNodeSelect;
  const labelsRef = useRef(true);

  const elements = useMemo(() => graphElements(graph), [graph]);

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
      minZoom: 0.25,
      maxZoom: 4,
      wheelSensitivity: 0.22,
      style: [
        { selector: "node", style: { label: "data(label)", color: "#333333", "font-family": "JetBrains Mono", "font-size": "8px", "text-wrap": "wrap", "text-max-width": "58px", "text-valign": "center", "text-halign": "center", "text-margin-y": 0, "background-color": "#f6f6f6", "border-width": 1.5, "border-color": "#555555", "shape": "ellipse", width: 26, height: 26 } },
        { selector: "node[entityType = 'actor']", style: { "shape": "round-rectangle", width: 62, height: 26, "font-size": "9px", "text-max-width": "58px", "border-width": 2 } },
        { selector: "node[entityType = 'site']", style: { "shape": "cut-rectangle", width: 64, height: 26, "font-size": "9px" } },
        { selector: "node[entityType = 'handle']", style: { "shape": "barrel", "background-color": "#eef1f1", width: 56, height: 28, "border-width": 1.5 } },
        { selector: "node[entityType = 'post']", style: { "shape": "concave-hexagon", "background-color": "#eef1f1", width: 52, height: 30, "font-size": "7px", "text-max-width": "50px" } },
        { selector: "node[entityType = 'identifier'], node[entityType = 'btc'], node[entityType = 'pgp'], node[entityType = 'pgp_email'], node[entityType = 'jabber'], node[entityType = 'onion']", style: { "shape": "ellipse", "background-color": "#eef1f1", width: 58, height: 24, "font-size": "8px" } },
        { selector: "node[entityType = 'misconfig']", style: { "shape": "rectangle", "background-color": "#f6f6f6", "border-width": 2.5, width: 60, height: 30, "font-size": "8px" } },
        { selector: "node.selected", style: { "border-width": 3, "border-color": "#d67614", "overlay-color": "#d67614", "overlay-opacity": 0.14, "overlay-padding": 8, "background-color": "#fbe7d4" } },
        { selector: "node.hover", style: { "border-width": 2.5, "border-color": "#d67614" } },
        { selector: "node.dimmed", style: { opacity: 0.15 } },
        { selector: "edge.dimmed", style: { opacity: 0.06 } },
        { selector: "edge", style: { width: "mapData(confidence, 0, 1, 1, 4)", "line-color": "#555555", "target-arrow-color": "#555555", "target-arrow-shape": "triangle", "target-arrow-fill": "hollow", "curve-style": "bezier", "arrow-scale": 1.1, label: "data(label)", color: "#666666", "font-family": "JetBrains Mono", "font-size": "7px", "text-rotation": "autorotate", "text-background-color": "#ffffff", "text-background-opacity": 0.9, "text-background-padding": "2px", "text-outline-width": 0 } },
        { selector: "edge[confidence >= 0.75]", style: { "line-color": "#2b2b2b", "target-arrow-color": "#2b2b2b", "target-arrow-fill": "filled" } },
        { selector: "edge[confidence >= 0.4][confidence < 0.75]", style: { "target-arrow-shape": "circle", "target-arrow-fill": "hollow" } },
        { selector: "edge[confidence < 0.4]", style: { "line-style": "dashed", "line-color": "#8a8a8a", "target-arrow-color": "#8a8a8a", "target-arrow-shape": "vee", "target-arrow-fill": "hollow" } },
      ],
      layout: {
        name: "cose",
        animate: false,
        fit: true,
        padding: 90,
        nodeRepulsion: 22000,
        nodeOverlap: 40,
        idealEdgeLength: 220,
        edgeElasticity: 90,
        gravity: 0.07,
        componentSpacing: 180,
        coolingFactor: 0.8,
      },
    });
    cyRef.current = cy;
    if (!labelsRef.current) {
      cy.style().selector("node").style("label", " ").update();
    }
    cy.on("tap", "node", (event) => {
      focusNode(cy, event.target);
      onSelectRef.current(event.target.data() as GraphNode);
    });
    cy.on("tap", (event) => {
      if (event.target === cy) {
        cy.elements().removeClass("dimmed");
        cy.nodes().removeClass("selected");
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
      zoomIn: () => { const c = cyRef.current; if (c) c.zoom(c.zoom() * 1.3); },
      zoomOut: () => { const c = cyRef.current; if (c) c.zoom(c.zoom() / 1.3); },
      fit: () => { const c = cyRef.current; if (c) c.fit(undefined, 56); },
      resize: () => { const c = cyRef.current; if (c) { c.resize(); c.fit(undefined, 56); } },
      toggleLabels: () => {
        const c = cyRef.current;
        if (!c) return labelsRef.current;
        labelsRef.current = !labelsRef.current;
        c.style().selector("node").style("label", labelsRef.current ? "data(label)" : " ").update();
        return labelsRef.current;
      },
    };
    if (apiRef) apiRef.current = api;
    return () => {
      cy.destroy();
      cyRef.current = null;
      if (apiRef) apiRef.current = null;
    };
  }, [elements]);

  return <div id="cy" ref={containerRef} className="h-full min-h-[420px] w-full" data-testid="relationship-graph-canvas" />;
});