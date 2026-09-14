import { useEffect, useMemo, useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Activity, AlertTriangle, Archive, ArrowUpRight, Check, ChevronRight, CircleHelp, Clipboard, CloudDownload,
  Database, Download, FileJson, FileText, Fingerprint, Gauge, GitFork, Globe2, Hash, LayoutGrid, Link2, LoaderCircle, Radio,
  Network, RefreshCw, Search, ShieldAlert, SlidersHorizontal, Sparkles, Terminal, Timer, UserRound,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Toaster } from "@/components/ui/sonner";
import GraphCanvas from "@/components/GraphCanvas";
import { Link } from "react-router-dom";
import { apiDownload } from "@/lib/api";
import {
  asArray, clampConfidence, displayHandle, errorText, getActors, getAlerts, getCategories, getFindings, getGraph, getIdentifiers, getMisconfigs, getSearch,
  getSites, getStats, getActor, getStylo, getText, getTimeline, normalizeStylo, runCollect, runRefresh, runScan, type Actor, type Finding, type GraphNode, type Identifier, type JsonRecord, type LiveAlert, type Stats,
} from "@/lib/darkforce";

type Severity = "all" | "critical" | "high" | "medium" | "low";

function valueFromStats(stats: Stats | undefined, keys: string[]): number {
  for (const key of keys) {
    const value = stats?.[key];
    if (typeof value === "number") return value;
  }
  return 0;
}

function purposeBadge(purpose?: string) { return <span className={`purpose-tag ${["drugs", "weapons / guns", "hitman / for-hire", "weapons"].some((k) => purpose?.includes(k)) ? "purpose-danger" : "purpose-ok"}`}>{purpose ?? "unknown"}</span>; }

function StatDetail({ view, stats, actors, identifiers, sites, findings, onSelectActor, onClose, categories }: { view: "actors" | "identities" | "sites" | "findings"; stats?: Stats; actors?: Actor[]; identifiers?: Identifier[]; sites?: JsonRecord[]; findings?: Finding[]; onSelectActor?: (actor: Actor) => void; onClose?: () => void; categories?: string[] }) {
  const isActor = view === "actors";
  const isIdentity = view === "identities";
  const isSite = view === "sites";
  const [categoryFilter, setCategoryFilter] = useState("all");

  const filteredSites = isSite && sites ? (categoryFilter === "all" ? sites : sites.filter((site) => getText(site.category, "other").toLowerCase() === categoryFilter.toLowerCase())) : sites;

  const body = isActor ? (
    <QueryState loading={false} error={undefined} empty={!actors?.length} label="actors-list"><div className="inventory-table-wrap"><table className="inventory-table"><thead><tr><th>HANDLE</th><th>CONF</th><th>HANDLES</th><th>POSTS</th><th>CATEGORY</th><th>SEEN</th></tr></thead><tbody>{(actors ?? []).map((actor) => <tr key={String(actor.id)}><td className="inventory-handle"><a href="#" onClick={(e) => { e.preventDefault(); onSelectActor?.(actor); }}>{displayHandle(actor)}</a></td><td className="mono">{formatConfidence(actor.confidence)}</td><td className="mono">{actor.n_handles ?? actor.handles?.length ?? 0}</td><td className="mono">{actor.n_posts ?? actor.posts?.length ?? 0}</td><td>{getText(actor.category ?? actor.kind, "—")}</td><td>{getText(actor.last_seen ?? actor.last_scan, "—")}</td></tr>)}</tbody></table></div></QueryState>
  ) : isIdentity ? (
    <QueryState loading={false} error={undefined} empty={!identifiers?.length} label="identities-list"><div className="inventory-table-wrap"><table className="inventory-table"><thead><tr><th>KIND</th><th>VALUE</th><th>DETAIL</th><th>ACTOR</th><th>SOURCE</th></tr></thead><tbody>{(identifiers ?? []).map((item, index) => <tr key={String(item.id ?? `${item.kind}-${index}`)}><td><span className="severity-dot db-dot" />{getText(item.kind, "id")}</td><td className="mono inventory-value">{getText(item.value)}</td><td className="inventory-detail">{getText(item.detail, "—")}</td><td>{getText(item.actor_canon ?? item.handle, "unattributed")}</td><td className="mono inventory-url">{getText(item.url, "—")}</td></tr>)}</tbody></table></div></QueryState>
  ) : isSite ? (
    <div className="stat-detail-table-stack"><div className="stat-filter-row"><span className="micro-label">CATEGORY FILTER</span><select value={categoryFilter} onChange={(event) => setCategoryFilter(event.target.value)} className="console-select category-filter" aria-label="Filter sites by category" data-testid="site-category-filter"><option value="all">ALL CATEGORIES</option>{(categories ?? []).map((category) => <option key={category} value={category}>{category.toUpperCase()}</option>)}</select><span className="mono category-filter-count">{filteredSites?.length ?? 0} / {sites?.length ?? 0} SITES</span></div><QueryState loading={false} error={undefined} empty={!filteredSites?.length} label="sites-list"><div className="inventory-table-wrap"><table className="inventory-table"><thead><tr><th>PURPOSE</th><th>URL</th><th>TITLE</th><th>SERVER</th><th>POSTS</th></tr></thead><tbody>{(filteredSites ?? []).map((site) => <tr key={String(site.id)}><td>{purposeBadge(getText(site.category, getText(site.purpose, "other")))}</td><td className="mono inventory-url"><a href={getText(site.url)} target="_blank" rel="noreferrer">{getText(site.url)}</a></td><td className="inventory-detail">{getText(site.title, "—")}</td><td className="mono">{getText(site.server, "—")}</td><td className="mono">{Number(site.post_count ?? site.n_posts ?? 0)}</td></tr>)}</tbody></table></div></QueryState></div>
  ) : (
    <QueryState loading={false} error={undefined} empty={!findings?.length} label="findings-list"><div className="inventory-table-wrap"><table className="inventory-table"><thead><tr><th>SEV</th><th>KIND</th><th>DETAIL</th><th>SITE</th><th>CONF</th></tr></thead><tbody>{(findings ?? []).map((finding, index) => <tr key={String(finding.id ?? `${finding.site_id}-${index}`)}><td><span className={`severity-dot sev-${(finding.severity ?? "medium").toLowerCase()}`} />{getText(finding.severity, "—").toUpperCase()}</td><td>{getText(finding.kind ?? finding.title ?? finding.name, "finding")}</td><td className="inventory-detail">{getText(finding.detail ?? finding.evidence, "—")}</td><td className="mono inventory-url">{getText(finding.site_url ?? finding.site, "—")}</td><td className="mono">{(typeof finding.confidence === "number" ? finding.confidence : 0).toFixed(2)}</td></tr>)}</tbody></table></div></QueryState>
  );

  const count = isActor ? valueFromStats(stats, ["actors", "actor_count"]) : isIdentity ? valueFromStats(stats, ["identifiers", "identities"]) : isSite ? valueFromStats(stats, ["sites", "site_count"]) : (findings?.length ?? (stats ? valueFromStats(stats, ["findings", "finding_count"]) : 0));
  return <div className="stat-detail" data-testid={`stat-detail-${view}`}><div className="stat-detail-head"><strong>{view.toUpperCase()} — FULL REGISTER</strong><span className="mono">{count} RECORD(S)</span><button type="button" className="stat-detail-close" onClick={onClose}>× CLOSE</button></div>{body}</div>;
}

function formatConfidence(value?: number) { return `${Math.round(clampConfidence(value) * 100)}%`; }
function statusLabel(status?: string) { return status ?? "STATUS NOT REPORTED"; }

function StatBlock({ label, value, icon: Icon, accent, active, onClick }: { label: string; value: number; icon: typeof Activity; accent: string; active?: boolean; onClick?: () => void }) {
  return <button type="button" className={`stat-block ${onClick ? "stat-clickable" : ""} ${active ? "stat-active" : ""}`} onClick={onClick} data-testid={`stat-${label.toLowerCase().replaceAll(" ", "-")}`}><div className="stat-icon" style={{ color: accent }}><Icon size={16} /></div><div><div className="stat-value">{value.toLocaleString()}</div><div className="stat-label">{label}{onClick ? " ⟶ view" : ""}</div></div></button>;
}

function QueryState({ loading, error, empty, children, label }: { loading: boolean; error: unknown; empty?: boolean; children: ReactNode; label: string }) {
  if (loading) return <div className="query-state" data-testid={`${label}-loading-state`}><LoaderCircle className="animate-spin" size={16} /> Querying source…</div>;
  if (error) return <div className="query-state query-error" data-testid={`${label}-error-state`}><AlertTriangle size={16} /> {errorText(error)}</div>;
  if (empty) return <div className="query-state" data-testid={`${label}-empty-state`}><CircleHelp size={16} /> No API records returned.</div>;
  return <>{children}</>;
}

function ConfidenceBar({ value }: { value?: number }) {
  const confidence = clampConfidence(value);
  return <div className="confidence-wrap" aria-label={`confidence ${formatConfidence(value)}`} data-testid="actor-confidence-visual"><div className="confidence-bar"><span style={{ width: `${confidence * 100}%` }} /></div><span className="mono confidence-value">{formatConfidence(value)}</span></div>;
}

function CopyButton({ value, label }: { value: string; label: string }) {
  const copy = async () => {
    try { await navigator.clipboard.writeText(value); toast.success("Copied to clipboard"); } catch { toast.error("Clipboard unavailable"); }
  };
  return <Button variant="ghost" size="icon-xs" className="copy-button" onClick={copy} aria-label={`Copy ${label}`} data-testid={`copy-${label.toLowerCase().replaceAll(" ", "-")}`}><Clipboard size={13} /></Button>;
}

function EvidenceText({ value }: { value: unknown }) {
  const text = Array.isArray(value) ? value.map((item) => typeof item === "string" ? item : JSON.stringify(item)).join("\n") : typeof value === "object" && value ? JSON.stringify(value, null, 2) : getText(value);
  return <div className="evidence-text mono" title={text} data-testid="evidence-detail-text">{text}</div>;
}

export default function Home() {
  const queryClient = useQueryClient();
  const [search, setSearch] = useState("");
  const [kind, setKind] = useState("actor");
  const [selectedActor, setSelectedActor] = useState<Actor | undefined>();
  const [selectedGraphNode, setSelectedGraphNode] = useState<GraphNode | undefined>();
  const [severity, setSeverity] = useState<Severity>("all");
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const [timelineRange, setTimelineRange] = useState({ start: "", end: "" });
  const [refreshing, setRefreshing] = useState(false);
  const [scanUrl, setScanUrl] = useState("");
  const [statView, setStatView] = useState<"actors" | "identities" | "sites" | "findings" | null>(null);
  const [liveAlerts, setLiveAlerts] = useState<LiveAlert[]>([]);
  const [sseConnected, setSseConnected] = useState(false);

  const statsQuery = useQuery({ queryKey: ["stats"], queryFn: getStats, retry: false });
  const categoriesQuery = useQuery({ queryKey: ["categories"], queryFn: getCategories, retry: false });
  const alertsQuery = useQuery({ queryKey: ["alerts"], queryFn: getAlerts, refetchInterval: 30_000, retry: false });
  const categories = categoriesQuery.data?.categories ?? [];
  const liveAlertCount = alertsQuery.data?.length ?? 0;
  const allActorsQuery = useQuery({ queryKey: ["actors-all"], queryFn: getActors, enabled: statView === "actors", retry: false });
  const allIdentifiersQuery = useQuery({ queryKey: ["identifiers-all"], queryFn: getIdentifiers, enabled: statView === "identities", retry: false });
  const allSitesQuery = useQuery({ queryKey: ["sites-all"], queryFn: getSites, enabled: statView === "sites", retry: false });
  const searchQuery = useQuery({ queryKey: ["search", search, kind], queryFn: () => getSearch(search, kind), retry: false });
  const actorResults = useMemo(() => asArray(searchQuery.data), [searchQuery.data]);
  const activeActor = selectedActor ?? actorResults[0];
  const actorQuery = useQuery({ queryKey: ["actor", activeActor?.id], queryFn: () => getActor(activeActor!.id), enabled: Boolean(activeActor?.id), retry: false });
  const profileActor = actorQuery.data ?? activeActor;
  const graphQuery = useQuery({ queryKey: ["graph", activeActor?.id], queryFn: () => getGraph(activeActor!.id), enabled: Boolean(activeActor?.id), retry: false });
  const misconfigQuery = useQuery({ queryKey: ["misconfigs"], queryFn: getMisconfigs, retry: false });
  const misconfigs = useMemo(() => asArray(misconfigQuery.data), [misconfigQuery.data]);
  const activeFindingSite = misconfigs[0]?.site_id ?? misconfigs[0]?.siteId;
  const findingsQuery = useQuery({ queryKey: ["findings", activeFindingSite], queryFn: () => getFindings(activeFindingSite!), enabled: Boolean(activeFindingSite), retry: false });
  const styloHandle = profileActor?.canonical_handle ?? profileActor?.handle ?? profileActor?.canon;
  const styloQuery = useQuery({ queryKey: ["stylo", styloHandle], queryFn: () => getStylo(styloHandle!), enabled: Boolean(styloHandle), retry: false });
  const timelineQuery = useQuery({ queryKey: ["timeline", timelineRange], queryFn: () => getTimeline(timelineRange.start, timelineRange.end), retry: false });

  useEffect(() => {
    const source = new EventSource("/api/alerts/stream");
    source.onopen = () => setSseConnected(true);
    source.onerror = () => setSseConnected(false);
    source.onmessage = (event) => {
      if (!event.data || event.data.trim().startsWith(":")) return;
      try {
        const alert = JSON.parse(event.data) as LiveAlert;
        setLiveAlerts((current) => {
          const merged = [alert, ...current];
          return merged.slice(0, 20);
        });
        toast.success(`Live alert: ${getText(alert.title, "Detector fired")}`);
        void queryClient.invalidateQueries({ queryKey: ["stats"] });
        void queryClient.invalidateQueries({ queryKey: ["alerts"] });
        void queryClient.invalidateQueries({ queryKey: ["sites-all"] });
      } catch {
        return;
      }
    };
    return () => source.close();
  }, [queryClient]);

  const scanMutation = useMutation({ mutationFn: () => runScan(scanUrl), onSuccess: (response) => { toast.success(getText(response?.message, "Scan completed")); queryClient.invalidateQueries(); }, onError: (error) => toast.error(`Scan failed: ${errorText(error)}`) });
  const collectMutation = useMutation({ mutationFn: runCollect, onSuccess: (response) => { toast.success(getText(response?.message, "Collection completed")); queryClient.invalidateQueries(); }, onError: (error) => toast.error(`Collection failed: ${errorText(error)}`) });
  const filteredFindings = useMemo(() => { const all = [...misconfigs, ...asArray(findingsQuery.data)]; return severity === "all" ? all : all.filter((item) => item.severity?.toLowerCase() === severity); }, [findingsQuery.data, misconfigs, severity]);
  const stats = statsQuery.data;
  const sourceList = Array.isArray(stats?.sources) ? stats.sources : [];
  const topActors = actorResults.slice(0, 5);
  const graphNodeSelected = (node: GraphNode) => {
    setSelectedGraphNode(node);
    const nodeActorId = node.actor_id ?? node.actorId;
    const isActor = (node.entity_type ?? node.type ?? node.kind)?.toLowerCase() === "actor";
    if (isActor && nodeActorId) { const match = actorResults.find((actor) => String(actor.id) === String(nodeActorId) || actor.id === node.id); setSelectedActor(match ?? { id: nodeActorId, handle: node.label, kind: "actor", confidence: node.confidence }); }
  };
  const refresh = async () => {
    setRefreshing(true);
    try {
      const response = await runRefresh();
      toast.success(getText(response?.message, "Investigation data refreshed"));
      void queryClient.invalidateQueries();
    } catch (error) {
      toast.error(`Refresh failed: ${errorText(error)}`);
    } finally {
      setRefreshing(false);
    }
  };
  const exportReport = (format: "csv" | "json" | "pdf") => {
    void apiDownload(`/export?fmt=${format}&kind=all`, `darkforce_report.${format}`).then(() => toast.success(`${format.toUpperCase()} export requested`)).catch((error: unknown) => toast.error(`Export failed: ${errorText(error)}`));
  };
  const submitSearch = (event: React.FormEvent) => { event.preventDefault(); setSelectedActor(undefined); void searchQuery.refetch(); };
  const toggleStat = (view: NonNullable<typeof statView>) => { setStatView((current) => current === view ? null : view); };
  const selectStatActor = (actor: Actor) => { setSelectedActor(actor); setStatView(null); window.scrollTo({ top: 0, behavior: "smooth" }); };
  const stylo = normalizeStylo(styloQuery.data);
  const profileIdentifiers = profileActor?.identifiers ?? [];
  const submitTimeline = (event: React.FormEvent) => { event.preventDefault(); if (start && end && start > end) { toast.error("Start date must be before end date"); return; } setTimelineRange({ start, end }); };

  return <div className="console-shell" data-testid="console-shell">
    <Toaster richColors />
    <header className="console-header" data-testid="console-header"><div className="brand-lockup"><div className="brand-mark"><Terminal size={18} /></div><div><div className="brand-name">DARKFORCE</div><div className="brand-subtitle">NTRO / INVESTIGATOR CONSOLE</div></div></div><div className="header-context"><span className="live-dot" /> <span data-testid="session-state">READ-ONLY PIPELINE</span><span className="header-divider" /><span className="mono" data-testid="utc-clock">UTC / ANALYST VIEW</span>{sseConnected && <span className="sse-badge live-alerts-badge" data-testid="live-alerts-badge"><Radio size={11} /> LIVE {liveAlerts.length || liveAlertCount} ALERT{(liveAlerts.length || liveAlertCount) === 1 ? "" : "S"}</span>}</div><div className="header-actions"><Link to="/registry" data-testid="master-registry-link"><Button variant="outline" size="sm"><LayoutGrid size={14} /> Master Registry</Button></Link><Link to="/analyst" data-testid="analyst-page-link"><Button variant="outline" size="sm"><Network size={14} /> Analyst</Button></Link><Link to="/evidence" data-testid="evidence-page-link"><Button variant="outline" size="sm"><Fingerprint size={14} /> Evidence</Button></Link><Link to="/wallets" data-testid="wallets-page-link"><Button variant="outline" size="sm"><Archive size={14} /> Wallets</Button></Link><Link to="/breaches" data-testid="breaches-page-link"><Button variant="outline" size="sm"><ShieldAlert size={14} /> Breaches</Button></Link><Link to="/cases" data-testid="cases-page-link"><Button variant="outline" size="sm"><GitFork size={14} /> Cases</Button></Link><Button variant="ghost" size="sm" onClick={refresh} disabled={refreshing} data-testid="refresh-data-button"><RefreshCw size={14} className={refreshing ? "animate-spin" : ""} /> Refresh</Button><Button variant="outline" size="sm" onClick={() => exportReport("pdf")} data-testid="export-report-button"><Download size={14} /> Export report</Button></div></header>
    <main className="console-main">
      <section className="stats-rail" aria-label="Dashboard statistics" data-testid="stats-rail"><div className="section-kicker"><Gauge size={14} /> SYSTEM SNAPSHOT <span className="mono">/ API STATS</span></div><div className="stat-grid"><StatBlock label="Actors" value={valueFromStats(stats, ["actors", "actor_count"])} icon={UserRound} accent="#52e1ec" active={statView === "actors"} onClick={() => toggleStat("actors")} /><StatBlock label="Identities" value={valueFromStats(stats, ["identifiers", "identities", "identity_count", "handles"])} icon={Fingerprint} accent="#86aaff" active={statView === "identities"} onClick={() => toggleStat("identities")} /><StatBlock label="Sites" value={valueFromStats(stats, ["sites", "site_count"])} icon={Globe2} accent="#e3b64d" active={statView === "sites"} onClick={() => toggleStat("sites")} /><StatBlock label="Findings" value={valueFromStats(stats, ["findings", "finding_count", "misconfigs"])} icon={ShieldAlert} accent="#f27960" active={statView === "findings"} onClick={() => toggleStat("findings")} /></div>{statView && <StatDetail view={statView} stats={stats} actors={allActorsQuery.data} identifiers={allIdentifiersQuery.data} sites={allSitesQuery.data} findings={filteredFindings} onSelectActor={selectStatActor} onClose={() => setStatView(null)} categories={categories} />}<div className="provenance-strip" data-testid="source-provenance-strip"><Database size={14} /><span>PROVENANCE</span><strong>{statusLabel(stats?.source_status)}</strong><span className="provenance-detail">{sourceList.length ? sourceList.join(" · ") : getText(stats?.source, "No source reported by API")}</span></div></section>
      <section className="search-row" data-testid="search-section"><form onSubmit={submitSearch} className="search-form" data-testid="investigator-search-form"><div className="section-kicker"><Search size={14} /> DISCOVER ACTOR / ENTITY</div><div className="search-controls"><div className="search-input-wrap"><Search size={16} /><Input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search handle, identifier, site, or evidence…" aria-label="Search intelligence" data-testid="investigator-search-input" /></div><select value={kind} onChange={(event) => setKind(event.target.value)} className="console-select" aria-label="Search entity type" data-testid="search-kind-select"><option value="actor">ACTOR</option><option value="identity">IDENTITY</option><option value="site">SITE</option><option value="identifier">IDENTIFIER</option></select><Button type="submit" disabled={searchQuery.isFetching} data-testid="investigator-search-submit"><Search size={14} /> Investigate</Button></div></form><div className="action-rail"><div className="section-kicker"><Activity size={14} /> PIPELINE ACTIONS</div><div className="pipeline-buttons"><Input value={scanUrl} onChange={(event) => setScanUrl(event.target.value)} placeholder="URL to scan" aria-label="URL to scan" data-testid="scan-url-input" /><Button variant="outline" onClick={() => scanMutation.mutate()} disabled={!scanUrl.trim() || scanMutation.isPending || collectMutation.isPending} data-testid="scan-pipeline-button">{scanMutation.isPending ? <LoaderCircle className="animate-spin" size={14} /> : <Sparkles size={14} />} Scan</Button><Button variant="outline" onClick={() => collectMutation.mutate()} disabled={collectMutation.isPending || scanMutation.isPending} data-testid="collect-pipeline-button">{collectMutation.isPending ? <LoaderCircle className="animate-spin" size={14} /> : <Archive size={14} />} Collect</Button></div></div></section>
      <div className="dashboard-grid">
        <aside className="left-column"><section className="console-panel actor-list-panel" data-testid="actor-results-panel"><div className="panel-heading"><div><div className="section-kicker"><UserRound size={14} /> TOP ACTORS</div><div className="panel-subtitle">API-ranked candidates / select to inspect</div></div><Badge variant="outline" data-testid="actor-result-count">{topActors.length} returned</Badge></div><QueryState loading={searchQuery.isLoading} error={searchQuery.error} empty={!topActors.length} label="actor-results"><div id="sres" className="actor-results" data-testid="actor-search-results">{topActors.map((actor, index) => <button className={`actor-row ${activeActor?.id === actor.id ? "active" : ""}`} key={actor.id} onClick={() => setSelectedActor(actor)} data-testid={`actor-result-${index + 1}`}><span className="rank mono">0{index + 1}</span><span className="actor-row-copy"><strong>{displayHandle(actor)}</strong><small>{getText(actor.name ?? actor.detail, "API record")}</small></span><span className="actor-row-score mono">{formatConfidence(actor.confidence)}</span><ChevronRight size={14} /></button>)}</div></QueryState></section><section className="console-panel source-panel" data-testid="source-register-panel"><div className="section-kicker"><Link2 size={14} /> SOURCE REGISTER</div><QueryState loading={statsQuery.isLoading} error={statsQuery.error} empty={!sourceList.length && !stats?.source} label="source-register"><div className="source-list">{sourceList.map((source, index) => <div className="source-item" key={source}><span className="source-index mono">0{index + 1}</span><span>{source}</span><span className="source-state">API REPORTED</span></div>)}</div></QueryState></section></aside>
        <section className="center-column"><section className="console-panel profile-panel" id="aprof" data-testid="actor-profile-panel"><div className="panel-heading"><div><div className="section-kicker"><Fingerprint size={14} /> ACTOR PROFILE</div><div className="panel-subtitle">Canonical identity / evidence ledger</div></div>{profileActor && <Badge variant="outline" data-testid="actor-profile-kind">{getText(profileActor.category ?? profileActor.kind, "ACTOR").toUpperCase()}</Badge>}</div><QueryState loading={Boolean(activeActor) && actorQuery.isLoading} error={actorQuery.error} empty={!profileActor} label="actor-profile">{profileActor && <><div className="profile-hero"><div className="profile-avatar"><UserRound size={26} /></div><div className="profile-name-block"><div className="profile-handle mono" data-testid="actor-canonical-handle">{displayHandle(profileActor)} <CopyButton value={displayHandle(profileActor)} label="canonical handle" /></div><div className="profile-meta">{getText(profileActor.bio, profileActor.risk ?? "Canonical actor record")} <span className="meta-separator">·</span> record <span className="mono">{profileActor.id}</span></div></div><div className="profile-confidence"><div className="micro-label">CONFIDENCE</div><ConfidenceBar value={profileActor.confidence} /></div></div><div className="profile-columns"><div className="profile-block"><div className="micro-label">LINKED ALIASES</div><div className="tag-list">{profileActor.handles?.length ? profileActor.handles.map((handle) => <span className="data-tag mono" key={`${handle.handle}-${handle.site_id}`}>{getText(handle.handle)}</span>) : <span className="muted-text">No aliases reported</span>}</div></div><div className="profile-block"><div className="micro-label">IDENTIFIERS / SITES</div><div className="identifier-list">{profileIdentifiers.slice(0, 5).map((item, index) => { const value = typeof item === "string" ? item : getText(item.value); return <div className="identifier-item" key={`${value}-${index}`}><Hash size={12} /><span className="mono truncate-safe">{value}</span><CopyButton value={value} label={`identifier ${value}`} /></div>; })}{!profileIdentifiers.length && <span className="muted-text">No linked identifiers reported</span>}</div></div></div><div className="evidence-ledger"><div className="micro-label">EVIDENCE / DETAIL TEXT</div>{profileActor.findings?.length ? <div className="evidence-stack">{profileActor.findings.slice(0, 5).map((item, index) => <div className="evidence-row" key={item.id ?? index}><span className="evidence-index mono">E{String(index + 1).padStart(2, "0")}</span><EvidenceText value={item.detail ?? item.kind} /></div>)}</div> : <EvidenceText value={profileActor.bio ?? profileActor.detail} />}</div></>}</QueryState></section><section className="console-panel graph-panel" data-testid="graph-panel"><div className="panel-heading"><div><div className="section-kicker"><Network size={14} /> RELATIONSHIP GRAPH <span className="mono">/ CYTOSCAPE</span></div><div className="panel-subtitle">Select a node to inspect its relationship context</div></div><div className="graph-legend" data-testid="graph-legend"><span><i className="legend-dot actor" /> actor</span><span><i className="legend-dot identity" /> identity</span><span><i className="legend-dot site" /> site</span><span><i className="legend-dot finding" /> evidence</span></div></div><QueryState loading={graphQuery.isLoading} error={graphQuery.error} empty={!graphQuery.data?.nodes?.length && !graphQuery.data?.elements?.nodes?.length} label="graph"><div className="graph-stage"><GraphCanvas graph={graphQuery.data} activeId={activeActor ? `actor:${displayHandle(activeActor)}` : undefined} onNodeSelect={graphNodeSelected} />{selectedGraphNode && <div className="graph-detail" data-testid="graph-node-detail"><span className="micro-label">SELECTED NODE</span><strong className="mono">{getText(selectedGraphNode.label ?? selectedGraphNode.id)}</strong><span>{getText(selectedGraphNode.entity_type ?? selectedGraphNode.type ?? selectedGraphNode.kind, "ENTITY").toUpperCase()}</span><span className="mono">{selectedGraphNode.actor_id ?? selectedGraphNode.actorId ? "actor identity available" : "not an actor profile"}</span></div>}</div></QueryState></section></section>
        <aside className="right-column"><section className="console-panel findings-panel" data-testid="findings-panel"><div className="panel-heading"><div><div className="section-kicker"><ShieldAlert size={14} /> INFRASTRUCTURE FINDINGS</div><div className="panel-subtitle">Misconfiguration / raw evidence</div></div><select value={severity} onChange={(event) => setSeverity(event.target.value as Severity)} className="mini-select" aria-label="Filter finding severity" data-testid="finding-severity-filter"><option value="all">ALL</option><option value="critical">CRITICAL</option><option value="high">HIGH</option><option value="medium">MEDIUM</option><option value="low">LOW</option></select></div><QueryState loading={misconfigQuery.isLoading} error={misconfigQuery.error} empty={!filteredFindings.length} label="findings"><div className="finding-stack">{filteredFindings.slice(0, 6).map((finding: Finding, index) => <details className={`finding-item severity-${finding.severity?.toLowerCase() ?? "unknown"}`} key={finding.id ?? `${finding.site_id}-${index}`} open={index === 0}><summary><span className="severity-dot" /><span className="finding-title">{getText(finding.title ?? finding.name ?? finding.kind, "Untitled finding")}</span><Badge variant="outline">{getText(finding.severity, "UNRATED").toUpperCase()}</Badge></summary><div className="finding-detail"><div className="micro-label">{getText(finding.site ?? finding.site_url ?? finding.site_id ?? finding.url, "SITE NOT REPORTED")}</div><EvidenceText value={finding.evidence ?? finding.detail} />{(finding.source ?? finding.url) && <div className="finding-source mono">SOURCE / {finding.source ?? finding.url}</div>}</div></details>)}</div></QueryState></section><section className="console-panel stylo-panel" data-testid="stylometry-panel"><div className="section-kicker"><Fingerprint size={14} /> REBRAND ANALYSIS</div><div className="panel-subtitle">Stylometric explainability / handle lineage</div><QueryState loading={styloQuery.isLoading} error={styloQuery.error} empty={!stylo} label="stylometry">{stylo && <div className="stylo-content"><div className="handle-pair"><span className="mono">{getText(stylo.old_handle ?? stylo.handle, "old handle")}</span><ArrowUpRight size={14} /><span className="mono">{getText(stylo.new_handle ?? styloHandle, "new handle")}</span></div><div className="match-result"><div className={`match-score ${stylo.match ? "match" : "uncertain"}`}><span>{stylo.match === true ? <Check size={21} /> : <CircleHelp size={21} />}</span><strong>{stylo.match === true ? "MATCH INDICATED" : "RESULT UNCERTAIN"}</strong></div><ConfidenceBar value={stylo.score ?? stylo.confidence} /></div><div className="stylo-explanation">{getText(stylo.explanation, "No explainability text reported by API")}</div>{stylo.features?.length ? <div className="feature-list">{stylo.features.map((feature, index) => <div className="feature-row" key={feature.name ?? feature.label ?? index}><span>{getText(feature.label ?? feature.name)}</span><strong className="mono">{getText(feature.value ?? feature.detail)}</strong></div>)}</div> : null}</div>}</QueryState></section><section className="console-panel timeline-panel" data-testid="timeline-panel"><div className="panel-heading"><div><div className="section-kicker"><Timer size={14} /> INVESTIGATION TIMELINE</div><div className="panel-subtitle">Filter server-reported sequence</div></div><SlidersHorizontal size={15} className="muted-icon" /></div><form className="date-form" onSubmit={submitTimeline} data-testid="timeline-filter-form"><Input id="ts" type="date" value={start} onChange={(event) => setStart(event.target.value)} aria-label="Timeline start date" data-testid="timeline-start-date" /><span className="mono">→</span><Input id="te" type="date" value={end} onChange={(event) => setEnd(event.target.value)} aria-label="Timeline end date" data-testid="timeline-end-date" /><Button size="sm" type="submit" data-testid="timeline-apply-button">Apply</Button></form><QueryState loading={timelineQuery.isLoading} error={timelineQuery.error} empty={!timelineQuery.data?.length} label="timeline"><div className="timeline-list">{timelineQuery.data?.slice(0, 8).map((item, index) => <div className="timeline-event" key={item.id ?? `${item.ts}-${index}`}><span className="timeline-marker" /><div><div className="mono timeline-date">{getText(item.date ?? item.timestamp ?? item.ts, "DATE NOT REPORTED")}</div><strong>{getText(item.title ?? item.event, "Untitled event")}</strong><div className="timeline-detail">{getText(item.detail ?? item.handle ?? item.url)}</div></div></div>)}</div></QueryState></section></aside>
      </div>
      <footer className="console-footer" data-testid="console-footer"><div><span className="mono">DARKFORCE / NTRO</span><span className="footer-divider" /> lawfully collected, read-only intelligence view<span className="footer-divider" /><span className="mono footer-owner">dev9269 · Jainam H. Maru</span></div><div className="export-actions"><span className="micro-label">EXPORT REPORT</span><Button variant="ghost" size="sm" onClick={() => exportReport("csv")} data-testid="export-csv-button"><FileText size={13} /> CSV</Button><Button variant="ghost" size="sm" onClick={() => exportReport("json")} data-testid="export-json-button"><FileJson size={13} /> JSON</Button><Button variant="ghost" size="sm" onClick={() => exportReport("pdf")} data-testid="export-pdf-button"><CloudDownload size={13} /> PDF</Button></div></footer>
    </main>
  </div>;
}
