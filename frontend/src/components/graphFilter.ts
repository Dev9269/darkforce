/**
 * Shared filtering for every relationship graph in the console.
 *
 * Both the analyst overview and the per-actor graph on the home page render
 * through GraphCanvas, so the rules live here once instead of being restated
 * per page. Filtering never deletes anything: an excluded node or edge is
 * marked and dimmed, so the analyst keeps the shape of the graph and can still
 * see what was filtered out.
 */
import type { GraphEdge, GraphNode, GraphResponse } from "@/lib/darkforce";

export interface GraphFilter {
  /** Entity types switched off, e.g. "actor", "handle", "pgp". */
  hiddenTypes: string[];
  /** Relationship/edge labels switched off, e.g. "shared-identifier". */
  hiddenRelations: string[];
  /** Free-text match against the node label; empty means "no text filter". */
  query: string;
  /** Edges below this confidence are dimmed. 0 shows every edge. */
  minConfidence: number;
  /** When a node is selected, dim everything outside its direct connections. */
  neighborhoodOnly: boolean;
}

export interface Facet {
  value: string;
  count: number;
}

export interface GraphFacets {
  types: Facet[];
  relations: Facet[];
  minEdgeConfidence: number;
  maxEdgeConfidence: number;
}

export const EMPTY_FILTER: GraphFilter = {
  hiddenTypes: [],
  hiddenRelations: [],
  query: "",
  minConfidence: 0,
  neighborhoodOnly: false,
};

/** Same precedence GraphCanvas uses when it labels a node, so the chips
 *  always agree with what is actually drawn. */
export function entityTypeOf(node: GraphNode): string {
  return node.entity_type ?? node.type ?? node.kind ?? "entity";
}

export function relationOf(edge: GraphEdge): string {
  return edge.label ?? edge.relation ?? edge.e ?? "linked";
}

export function confidenceOf(edge: GraphEdge): number {
  const value = edge.confidence ?? edge.w;
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

export function nodeLabel(node: GraphNode): string {
  return String(node.label ?? node.handle ?? node.name ?? node.id ?? "");
}

/**
 * The one place an edge id is derived. GraphCanvas and partitionGraph must
 * agree on this: the canvas dims edges whose id is missing from the visible
 * set, so if the two ever disagree by so much as a fallback chain, every edge
 * silently dims the moment an edge filter is switched on.
 *
 * The API emits `s`/`t` rather than `source`/`target`, so both spellings are
 * accepted. Previously the canvas built ids from source/target alone, which
 * produced "edge-0-undefined-undefined" for every edge the API actually sends.
 */
export function edgeId(edge: GraphEdge, index: number): string {
  const source = edge.source ?? edge.s ?? "";
  const target = edge.target ?? edge.t ?? "";
  return String(edge.id ?? `edge-${index}-${source}-${target}`);
}

export function graphParts(graph?: GraphResponse): { nodes: GraphNode[]; edges: GraphEdge[] } {
  return {
    nodes: graph?.nodes ?? graph?.elements?.nodes ?? [],
    edges: graph?.edges ?? graph?.elements?.edges ?? [],
  };
}

function tally(values: string[]): Facet[] {
  const counts = new Map<string, number>();
  for (const value of values) counts.set(value, (counts.get(value) ?? 0) + 1);
  // Most common first, but alphabetical within a count so the chip order is
  // stable between renders and between the two graphs.
  return [...counts.entries()]
    .map(([value, count]) => ({ value, count }))
    .sort((a, b) => b.count - a.count || a.value.localeCompare(b.value));
}

/** What the filter bar can offer for a given graph, with live counts. */
export function graphFacets(graph?: GraphResponse): GraphFacets {
  const { nodes, edges } = graphParts(graph);
  const confidences = edges.map(confidenceOf);
  return {
    types: tally(nodes.map(entityTypeOf)),
    relations: tally(edges.map(relationOf)),
    minEdgeConfidence: confidences.length ? Math.min(...confidences) : 0,
    maxEdgeConfidence: confidences.length ? Math.max(...confidences) : 1,
  };
}

/** Ids of the selected node plus everything one hop away. */
export function neighborhoodIds(selectedId: string | null | undefined, edges: GraphEdge[]): Set<string> {
  const keep = new Set<string>();
  if (!selectedId) return keep;
  keep.add(String(selectedId));
  for (const edge of edges) {
    const source = String(edge.source ?? edge.s ?? "");
    const target = String(edge.target ?? edge.t ?? "");
    if (source === String(selectedId)) keep.add(target);
    if (target === String(selectedId)) keep.add(source);
  }
  return keep;
}

function nodeIsVisible(node: GraphNode, filter: GraphFilter, neighborhood: Set<string> | null): boolean {
  if (filter.hiddenTypes.includes(entityTypeOf(node))) return false;
  const query = filter.query.trim().toLowerCase();
  if (query && !nodeLabel(node).toLowerCase().includes(query)) return false;
  if (neighborhood && !neighborhood.has(String(node.id))) return false;
  return true;
}

function edgeIsVisible(edge: GraphEdge, filter: GraphFilter, nodesById: Map<string, GraphNode>, neighborhood: Set<string> | null): boolean {
  if (filter.hiddenRelations.includes(relationOf(edge))) return false;
  if (confidenceOf(edge) < filter.minConfidence) return false;
  if (neighborhood) {
    const source = String(edge.source ?? edge.s ?? "");
    const target = String(edge.target ?? edge.t ?? "");
    if (!neighborhood.has(source) || !neighborhood.has(target)) return false;
  } else {
    // A node filtered out by type or text takes its edges with it, otherwise
    // the canvas shows edges floating between two dimmed nodes.
    const source = nodesById.get(String(edge.source ?? edge.s ?? ""));
    const target = nodesById.get(String(edge.target ?? edge.t ?? ""));
    if (source && !nodeIsVisible(source, filter, null)) return false;
    if (target && !nodeIsVisible(target, filter, null)) return false;
  }
  return true;
}

export interface GraphPartition {
  visibleNodeIds: Set<string>;
  visibleEdgeIds: Set<string>;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

/**
 * The single source of truth for what a filter leaves visible. GraphCanvas dims
 * everything missing from here and the filter bar reports these counts, so what
 * the analyst is told and what is drawn cannot drift apart.
 */
export function partitionGraph(graph: GraphResponse | undefined, filter: GraphFilter, selectedId?: string | null): GraphPartition {
  const { nodes, edges } = graphParts(graph);
  const nodesById = new Map(nodes.map((node) => [String(node.id), node]));
  const neighborhood = filter.neighborhoodOnly ? neighborhoodIds(selectedId, edges) : null;
  const visibleNodeIds = new Set<string>();
  const visibleEdgeIds = new Set<string>();
  for (const node of nodes) {
    if (nodeIsVisible(node, filter, neighborhood)) visibleNodeIds.add(String(node.id));
  }
  edges.forEach((edge, index) => {
    if (edgeIsVisible(edge, filter, nodesById, neighborhood)) visibleEdgeIds.add(edgeId(edge, index));
  });
  return { visibleNodeIds, visibleEdgeIds, nodes, edges };
}

/** How many nodes/edges survive, so the bar can report "12 of 62 shown". */
export function visibleCounts(graph: GraphResponse | undefined, filter: GraphFilter, selectedId?: string | null): { nodes: number; edges: number; totalNodes: number; totalEdges: number } {
  const { visibleNodeIds, visibleEdgeIds, nodes, edges } = partitionGraph(graph, filter, selectedId);
  return { nodes: visibleNodeIds.size, edges: visibleEdgeIds.size, totalNodes: nodes.length, totalEdges: edges.length };
}

export function isFilterActive(filter: GraphFilter): boolean {
  return (
    filter.hiddenTypes.length > 0 ||
    filter.hiddenRelations.length > 0 ||
    filter.query.trim() !== "" ||
    filter.minConfidence > 0 ||
    filter.neighborhoodOnly
  );
}

export function countActiveChips(filter: GraphFilter): number {
  return filter.hiddenTypes.length + filter.hiddenRelations.length + (filter.query.trim() ? 1 : 0) + (filter.minConfidence > 0 ? 1 : 0) + (filter.neighborhoodOnly ? 1 : 0);
}

/** Toggle a facet value in a hidden list, used by both chip rows. */
export function toggleValue(list: string[], value: string): string[] {
  return list.includes(value) ? list.filter((item) => item !== value) : [...list, value];
}
