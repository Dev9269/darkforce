import { Eye, EyeOff, Focus, RotateCcw, Search, SlidersHorizontal } from "lucide-react";

import {
  EMPTY_FILTER,
  countActiveChips,
  toggleValue,
  type Facet,
  type GraphFacets,
  type GraphFilter,
} from "./graphFilter";

interface GraphFilterBarProps {
  facets: GraphFacets;
  filter: GraphFilter;
  onChange: (next: GraphFilter) => void;
  shownNodes: number;
  shownEdges: number;
  /** Label of the currently selected node, for the neighbourhood toggle. */
  selectedLabel?: string | null;
  testId?: string;
}

const pct = (value: number) => `${Math.round(value * 100)}%`;

function Chip({ facet, hidden, onToggle }: { facet: Facet; hidden: boolean; onToggle: () => void }) {
  return (
    <button
      type="button"
      className={`graph-chip${hidden ? " off" : ""}`}
      onClick={onToggle}
      aria-pressed={!hidden}
      title={hidden ? `Show ${facet.value}` : `Hide ${facet.value}`}
    >
      {hidden ? <EyeOff size={11} /> : <Eye size={11} />}
      <span className="graph-chip-label">{facet.value}</span>
      <span className="graph-chip-count">{facet.count}</span>
    </button>
  );
}

/**
 * Filter controls for a relationship graph. Rendered by every page that shows a
 * GraphCanvas so the two graphs stay consistent. Excluded nodes and edges are
 * dimmed rather than removed, which is why the chips say show/hide instead of
 * include/exclude.
 */
export default function GraphFilterBar({
  facets,
  filter,
  onChange,
  shownNodes,
  shownEdges,
  selectedLabel,
  testId = "graph-filter-bar",
}: GraphFilterBarProps) {
  const set = (patch: Partial<GraphFilter>) => onChange({ ...filter, ...patch });
  const activeChips = countActiveChips(filter);
  const canNarrow = Boolean(selectedLabel);
  const pctMatch = filter.minConfidence > 0;

  return (
    <div className="graph-filters" data-testid={testId}>
      <div className="graph-filter-row">
        <label className="graph-search">
          <Search size={12} />
          <input
            type="search"
            value={filter.query}
            placeholder="Filter nodes by name…"
            aria-label="Filter graph nodes by name"
            data-testid={`${testId}-query`}
            onChange={(event) => set({ query: event.target.value })}
          />
          {filter.query && (
            <button type="button" title="Clear node search" aria-label="Clear node search" onClick={() => set({ query: "" })}>
              ×
            </button>
          )}
        </label>

        <button
          type="button"
          className={`graph-toggle${filter.neighborhoodOnly ? " on" : ""}`}
          disabled={!canNarrow}
          aria-pressed={filter.neighborhoodOnly}
          title={canNarrow ? `Show only ${selectedLabel} and its direct links` : "Select a node first"}
          data-testid={`${testId}-neighborhood`}
          onClick={() => set({ neighborhoodOnly: !filter.neighborhoodOnly })}
        >
          <Focus size={12} />
          <span>Neighbourhood only</span>
        </button>

        <label className="graph-confidence" title="Hide relationships weaker than this confidence">
          <SlidersHorizontal size={12} />
          <span className="graph-confidence-label">Min confidence</span>
          <input
            type="range"
            min={0}
            max={1}
            step={0.05}
            value={filter.minConfidence}
            aria-label="Minimum relationship confidence"
            data-testid={`${testId}-confidence`}
            onChange={(event) => set({ minConfidence: Number(event.target.value) })}
          />
          <span className="mono graph-confidence-value">{pctMatch ? pct(filter.minConfidence) : "all"}</span>
        </label>

        <span className="graph-filter-status mono" data-testid={`${testId}-status`} aria-live="polite">
          {shownNodes}/{facets.types.reduce((sum, facet) => sum + facet.count, 0)} nodes · {shownEdges} links
        </span>

        <button
          type="button"
          className="graph-reset"
          disabled={activeChips === 0}
          title="Clear every graph filter"
          data-testid={`${testId}-reset`}
          onClick={() => onChange({ ...EMPTY_FILTER })}
        >
          <RotateCcw size={12} />
          <span>Reset{activeChips ? ` (${activeChips})` : ""}</span>
        </button>
      </div>

      {facets.types.length > 0 && (
        <div className="graph-filter-row chips" data-testid={`${testId}-types`}>
          <span className="graph-filter-legend">Node type</span>
          {facets.types.map((facet) => (
            <Chip
              key={facet.value}
              facet={facet}
              hidden={filter.hiddenTypes.includes(facet.value)}
              onToggle={() => set({ hiddenTypes: toggleValue(filter.hiddenTypes, facet.value) })}
            />
          ))}
        </div>
      )}

      {facets.relations.length > 0 && (
        <div className="graph-filter-row chips" data-testid={`${testId}-relations`}>
          <span className="graph-filter-legend">Relationship</span>
          {facets.relations.map((facet) => (
            <Chip
              key={facet.value}
              facet={facet}
              hidden={filter.hiddenRelations.includes(facet.value)}
              onToggle={() => set({ hiddenRelations: toggleValue(filter.hiddenRelations, facet.value) })}
            />
          ))}
        </div>
      )}
    </div>
  );
}
