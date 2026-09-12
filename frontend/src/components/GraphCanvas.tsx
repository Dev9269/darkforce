import { useEffect, useRef } from "react";
import cytoscape, { type Core, type ElementDefinition } from "cytoscape";
import type { GraphResponse, GraphNode } from "@/lib/darkforce";

interface GraphCanvasProps {
  graph?: GraphResponse;
  activeId?: string;
  onNodeSelect: (node: GraphNode) => void;
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
        confidence: node.confidence ?? 0,
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

export default function GraphCanvas({ graph, activeId, onNodeSelect }: GraphCanvasProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const selectedIdRef = useRef(activeId);

  useEffect(() => {
    selectedIdRef.current = activeId;
    const cy = cyRef.current;
    if (!cy) return;
    cy.nodes().removeClass("selected");
    if (activeId) {
      const node = cy.getElementById(activeId);
      if (node.length) {
        node.addClass("selected");
        cy.animate({ center: { eles: node }, duration: 350 });
      }
    }
  }, [activeId]);

  useEffect(() => {
    if (!containerRef.current) return;
    const cy = cytoscape({
      container: containerRef.current,
      elements: graphElements(graph),
      minZoom: 0.35,
      maxZoom: 2.5,
      wheelSensitivity: 0.18,
      style: [
        { selector: "node", style: { label: "data(label)", color: "#d8e5eb", "font-family": "JetBrains Mono", "font-size": "9px", "text-wrap": "wrap", "text-max-width": "90px", "text-valign": "bottom", "text-margin-y": 8, "background-color": "#65808a", width: 22, height: 22, "border-width": 1, "border-color": "#9fb6bd" } },
        { selector: "node[entityType = 'actor']", style: { "background-color": "#00f0ff", "border-color": "#b5fcff", width: 34, height: 34, "font-size": "10px" } },
        { selector: "node[entityType = 'handle']", style: { "background-color": "#10b981" } },
        { selector: "node[entityType = 'site']", style: { "background-color": "#f59e0b" } },
        { selector: "node[entityType = 'post']", style: { "background-color": "#10b981" } },
        { selector: "node[entityType = 'identifier'], node[entityType = 'btc'], node[entityType = 'pgp'], node[entityType = 'pgp_email'], node[entityType = 'jabber'], node[entityType = 'onion']", style: { "background-color": "#a855f7" } },
        { selector: "node[entityType = 'misconfig']", style: { "background-color": "#ef4444" } },
        { selector: "node.selected", style: { "border-width": 3, "border-color": "#f2fbff", "overlay-color": "#51e3ef", "overlay-opacity": 0.15, "overlay-padding": 7 } },
        { selector: "edge", style: { width: "mapData(confidence, 0, 1, 1, 4)", "line-color": "#526770", "target-arrow-color": "#526770", "target-arrow-shape": "triangle", "curve-style": "bezier", label: "data(label)", color: "#71848b", "font-family": "JetBrains Mono", "font-size": "7px", "text-rotation": "autorotate", "text-background-color": "#11191d", "text-background-opacity": 0.9, "text-background-padding": "2px" } },
        { selector: "edge[confidence >= 0.75]", style: { "line-color": "#00f0ff", "target-arrow-color": "#00f0ff" } },
        { selector: "edge[confidence < 0.4]", style: { "line-style": "dashed", "line-color": "#6d4f46", "target-arrow-color": "#6d4f46" } },
      ],
      layout: { name: "cose", animate: false, fit: true, padding: 48, nodeRepulsion: 6500, idealEdgeLength: 130, componentSpacing: 90 },
    });
    cyRef.current = cy;
    cy.on("tap", "node", (event) => {
      const data = event.target.data() as GraphNode;
      cy.nodes().removeClass("selected");
      event.target.addClass("selected");
      onNodeSelect(data);
    });
    if (selectedIdRef.current) {
      const selected = cy.getElementById(selectedIdRef.current);
      if (selected.length) selected.addClass("selected");
    }
    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [graph, onNodeSelect]);

  return <div id="cy" ref={containerRef} className="h-full min-h-[360px] w-full" data-testid="relationship-graph-canvas" />;
}