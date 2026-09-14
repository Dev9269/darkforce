import { apiDelete, apiGet, apiPatch, apiPost, apiPut } from "@/lib/api";

export type JsonRecord = Record<string, unknown>;

export interface Actor {
  id: string | number;
  handle?: string;
  canonical_handle?: string;
  canon?: string;
  name?: string;
  label?: string;
  confidence?: number;
  aliases?: string[];
  identifiers?: Identifier[] | string[];
  sites?: string[];
  posts?: string[];
  categories?: string[];
  evidence?: string[] | JsonRecord[];
  detail?: string;
  source?: string;
  kind?: string;
  category?: string;
  bio?: string;
  risk?: string;
  handles?: Handle[];
  n_handles?: number;
  n_posts?: number;
  findings?: Finding[];
  stylo?: StyloResult[];
  [key: string]: unknown;
}

export interface Handle {
  id?: number;
  handle?: string;
  site_id?: number;
  site_url?: string;
  url?: string;
  role?: string;
  trust_level?: string;
  joined?: string;
  category?: string;
  [key: string]: unknown;
}

export interface Identifier {
  id?: number;
  actor_id?: number;
  handle?: string;
  kind?: string;
  value?: string;
  detail?: string;
  site_id?: number;
  url?: string;
  [key: string]: unknown;
}

export interface Stats {
  actors?: number;
  identities?: number;
  sites?: number;
  posts?: number;
  findings?: number;
  sources?: string[];
  source?: string;
  source_status?: string;
  top_actors?: Actor[];
  [key: string]: unknown;
}

export interface GraphNode {
  id: string;
  label?: string;
  type?: string;
  entity_type?: string;
  kind?: string;
  confidence?: number;
  actor_id?: string;
  actorId?: string;
  detail?: string;
  meta?: { conf?: number; [key: string]: unknown };
  [key: string]: unknown;
}

export interface GraphEdge {
  id?: string;
  source?: string;
  target?: string;
  s?: string;
  t?: string;
  label?: string;
  relation?: string;
  confidence?: number;
  e?: string;
  w?: number;
  [key: string]: unknown;
}

export interface GraphResponse {
  nodes?: GraphNode[];
  edges?: GraphEdge[];
  elements?: { nodes?: GraphNode[]; edges?: GraphEdge[] };
  [key: string]: unknown;
}

export interface Finding {
  id?: string;
  site_id?: string;
  siteId?: string;
  site?: string;
  title?: string;
  name?: string;
  kind?: string;
  site_url?: string;
  severity?: string;
  detail?: string;
  evidence?: string | JsonRecord | string[];
  source?: string;
  created_at?: string;
  [key: string]: unknown;
}

export interface StyloResult {
  handle?: string;
  old_handle?: string;
  new_handle?: string;
  match?: boolean;
  score?: number;
  confidence?: number;
  explanation?: string;
  features?: Array<{ name?: string; label?: string; value?: string | number; detail?: string }>;
  feature?: string;
  in_a?: number;
  in_b?: number;
  [key: string]: unknown;
}

export interface TimelineEvent {
  id?: string;
  date?: string;
  timestamp?: string;
  title?: string;
  event?: string;
  detail?: string;
  source?: string;
  kind?: string;
  ts?: string;
  etype?: string;
  handle?: string;
  url?: string;
  [key: string]: unknown;
}

export interface OperationResponse {
  ok?: boolean;
  message?: string;
  detail?: string;
  [key: string]: unknown;
}

export interface CategoriesResponse {
  categories?: string[];
  counts?: Record<string, number>;
  total?: number;
}

export interface LiveAlert {
  id?: string | number;
  kind?: string;
  title?: string;
  detail?: string;
  url?: string;
  confidence?: number;
  created_at?: string;
  ts?: string;
  [key: string]: unknown;
}

export interface TrustRow {
  source?: string;
  source_name?: string;
  trust?: number;
  rated_by?: string;
  rated_at?: string;
  notes?: string;
  source_type?: string;
  [key: string]: unknown;
}

export interface EvidenceObservation {
  id?: number;
  content_hash?: string;
  method?: string;
  kind?: string;
  raw?: string;
  trust?: number;
  evidence?: string;
  source_name?: string;
  observed_at?: string;
  [key: string]: unknown;
}

export interface EvidenceChain {
  type?: string;
  id?: number;
  object?: JsonRecord | null;
  observations?: EvidenceObservation[];
  attribution?: Attribution[];
  trust?: number | null;
  [key: string]: unknown;
}

export interface Attribution {
  id?: number;
  subject_type?: string;
  subject?: string;
  claim?: string;
  statement?: string;
  confidence?: number;
  note?: string;
  analyst?: string;
  ts?: string;
  [key: string]: unknown;
}

export interface Wallet {
  id?: number;
  address?: string;
  kind?: string;
  category?: string;
  first_seen?: string;
  last_seen?: string;
  n_identifiers?: number;
  [key: string]: unknown;
}

export interface WalletCluster {
  seed?: string;
  wallets?: string[];
  handles?: string[];
  actors?: (string | number)[];
}

export interface WalletDetail extends Wallet {
  cluster?: WalletCluster;
  identifiers?: Identifier[];
}

export interface Breach {
  id?: number;
  name?: string;
  type?: string;
  primary_entity?: string;
  source_url?: string;
  ts_acquired?: string;
  [key: string]: unknown;
}

export interface PivotRow {
  name?: string;
  type?: string;
  primary_entity?: string;
  kind?: string;
  value?: string;
  handle?: string;
  site_id?: number | string;
  [key: string]: unknown;
}

export interface PivotResult {
  query?: string;
  matches?: Breach[];
  corpus?: Identifier[];
  [key: string]: unknown;
}

export interface CaseHeader {
  id?: number;
  name?: string;
  status?: string;
  owner?: string;
  notes?: string;
  created_at?: string;
  updated_at?: string;
  n_members?: number;
  [key: string]: unknown;
}

export interface CaseMember {
  id?: number;
  case_id?: number;
  object_type?: string;
  object_id?: number;
  label?: string;
  note?: string;
  tag?: string;
  added_by?: string;
  ts?: string;
  site_url?: string;
  site_title?: string;
  [key: string]: unknown;
}

export interface CaseDetail extends CaseHeader {
  members?: CaseMember[];
}

export interface DetectRow {
  url?: string;
  title?: string;
  category?: string;
  last_scan?: string;
  hint?: string;
  [key: string]: unknown;
}

export interface OpsDetectResult {
  gone_dark?: DetectRow[];
  gone_dark_alerts?: number;
  candidates?: DetectRow[];
  successor_alerts?: number;
  alerts?: number;
  [key: string]: unknown;
}

export interface ImportResult {
  breach?: string;
  emails?: number;
  btc?: number;
  xmr?: number;
  lines?: number;
  identifiers?: number;
  imported?: number;
  examples?: JsonRecord[];
  [key: string]: unknown;
}

export const getStats = () => apiGet<Stats>("/stats");
export const getSites = () => apiGet<JsonRecord[]>("/sites");
export const getSiteCatalog = (options?: { category?: string; q?: string; page?: number; perPage?: number }) =>
  apiGet<{ items: JsonRecord[]; total: number; page: number; per_page: number }>(
    `/sites?page=${options?.page ?? 1}&per_page=${options?.perPage ?? 100}` +
      (options?.category ? `&category=${encodeURIComponent(options.category)}` : "") +
      (options?.q ? `&q=${encodeURIComponent(options.q)}` : ""),
  );
export const getCategories = () => apiGet<CategoriesResponse>("/categories");
export const getAlerts = () => apiGet<LiveAlert[]>("/alerts");

export interface ResourceSite {
  id?: string | number;
  url?: string;
  title?: string;
  category?: string;
  status?: string;
  first_seen?: string;
  last_scan?: string;
  lang?: string;
  headline?: string | null;
  [key: string]: unknown;
}

export interface NewsItem {
  id?: string | number;
  handle?: string;
  title?: string;
  url?: string;
  ts?: string;
  site_id?: string | number;
  site_url?: string;
  site_title?: string;
  status?: string;
  [key: string]: unknown;
}

export const getResources = (category?: string) =>
  apiGet<ResourceSite[]>(`/resources${category ? `?category=${encodeURIComponent(category)}` : ""}`);
export const getNews = (limit = 60) => apiGet<NewsItem[]>(`/news?limit=${limit}`);
export const getIdentifiers = () => apiGet<Identifier[]>("/identifiers");
export const getActors = () => apiGet<Actor[]>("/actors");
export const getNetworkAnalysis = () =>
  apiGet<{
    n_nodes?: number;
    n_edges?: number;
    n_communities?: number;
    communities?: JsonRecord[];
    centrality?: JsonRecord[];
    bridges?: JsonRecord[];
    actor_centrality?: JsonRecord[];
    summary?: JsonRecord;
  }>("/network/analysis");
export const getSearch = (q: string, kind: string, category?: string) =>
  apiGet<{ actors?: Actor[]; identifiers?: Identifier[]; sites?: JsonRecord[] }>(
    `/search?q=${encodeURIComponent(q)}&kind=${encodeURIComponent(kind)}` +
      (category ? `&category=${encodeURIComponent(category)}` : ""),
  );
export const getActor = (actorId: string | number) => apiGet<Actor>(`/actor/${encodeURIComponent(String(actorId))}`);
export const getGraph = (actorId: string) =>
  apiGet<GraphResponse>(`/graph?actor_id=${encodeURIComponent(actorId)}`);
export const getMisconfigs = () => apiGet<Finding[] | { findings?: Finding[] }>("/misconfigs");
export const getFindings = (siteId: string) => apiGet<Finding[]>(`/findings/${encodeURIComponent(siteId)}`);
export const getStylo = (handle: string) => apiGet<StyloResult | StyloResult[]>(`/stylo/${encodeURIComponent(handle)}`);
export const getTimeline = (start: string, end: string) =>
  apiGet<TimelineEvent[]>(`/timeline?start=${encodeURIComponent(start)}&end=${encodeURIComponent(end)}`);
export const runScan = (url: string, useTor = false) => apiPost<OperationResponse>("/scan", { url, use_tor: useTor });
export const runCollect = () => apiPost<OperationResponse>("/collect", {});
export const runRefresh = () => apiPost<OperationResponse>("/refresh", {});

export const getEvidenceChain = (objtype: string, objid: string | number) =>
  apiGet<EvidenceChain>(`/evidence/${encodeURIComponent(objtype)}/${encodeURIComponent(String(objid))}`);
export const getSourceTrusts = () => apiGet<TrustRow[]>("/sources/trust");
export const setSourceTrust = (source: string, trust: number, notes?: string) =>
  apiPut<TrustRow>("/sources/trust", { source, trust, notes: notes ?? "" });
export const getAttribution = (subjectType?: string, subject?: string) => {
  const params = new URLSearchParams();
  if (subjectType) params.set("subject_type", subjectType);
  if (subject) params.set("subject", subject);
  const qs = params.toString();
  return apiGet<Attribution[]>(`/attribution${qs ? `?${qs}` : ""}`);
};
export const addAttribution = (input: { subject_type?: string; subject: string; claim?: string; statement?: string; confidence?: number; note?: string }) =>
  apiPost<OperationResponse>("/attribution", {
    subject_type: input.subject_type ?? "link",
    subject: input.subject,
    claim: input.claim ?? "",
    statement: input.statement ?? "asserts",
    confidence: input.confidence ?? 0.5,
    note: input.note ?? "",
  });
export const getWallets = (options?: { q?: string; kind?: string; page?: number; perPage?: number }) =>
  apiGet<{ items: Wallet[]; total: number; page: number; per_page: number }>(
    `/wallets?page=${options?.page ?? 1}&per_page=${options?.perPage ?? 50}` +
      (options?.q ? `&q=${encodeURIComponent(options.q)}` : "") +
      (options?.kind ? `&kind=${encodeURIComponent(options.kind)}` : ""),
  );
export const getWallet = (address: string) => apiGet<WalletDetail>(`/wallets/${encodeURIComponent(address)}`);
export const getWalletCluster = (address: string) =>
  apiGet<WalletCluster>(`/clusters/${encodeURIComponent(address)}`);
export const getBreaches = (q?: string) => apiGet<Breach[]>(`/breaches${q ? `?q=${encodeURIComponent(q)}` : ""}`);
export const getPivots = (value?: string) => apiGet<PivotRow[] | PivotResult>(`/pivots${value ? `?value=${encodeURIComponent(value)}` : ""}`);
export const importStealer = (text: string, source: string) =>
  apiPost<ImportResult>("/import/stealer", { source, text });
export const importHibp = () => apiPost<ImportResult>("/import/hibp", {});
export const getCases = (status?: string) => apiGet<CaseHeader[]>(`/cases${status ? `?status=${encodeURIComponent(status)}` : ""}`);
export const createCase = (input: { name: string; status?: string; owner?: string; notes?: string }) =>
  apiPost<OperationResponse>("/cases", { name: input.name, status: input.status ?? "open", owner: input.owner ?? "analyst", notes: input.notes ?? "" });
export const getCase = (cid: string | number) => apiGet<CaseDetail>(`/cases/${encodeURIComponent(String(cid))}`);
export const patchCaseStatus = (cid: string | number, status: string) =>
  apiPatch<OperationResponse>(`/cases/${encodeURIComponent(String(cid))}`, { status });
export const addCaseMember = (cid: string | number, input: { object_type?: string; object_id: number; label?: string; note?: string; tag?: string }) =>
  apiPost<OperationResponse>(`/cases/${encodeURIComponent(String(cid))}/members`, {
    object_type: input.object_type ?? "site",
    object_id: input.object_id,
    label: input.label ?? "",
    note: input.note ?? "",
    tag: input.tag ?? "",
  });
export const removeCaseMember = (cid: string | number, mid: string | number) =>
  apiDelete<OperationResponse>(`/cases/${encodeURIComponent(String(cid))}/members/${encodeURIComponent(String(mid))}`);
export const runOpsDetect = () => apiPost<OpsDetectResult>("/ops/detect", {});

export function asArray<T>(value: T[] | { results?: T[]; actors?: T[]; findings?: T[] } | undefined): T[] {
  if (Array.isArray(value)) return value;
  if (value && "results" in value && Array.isArray(value.results)) return value.results;
  if (value && "actors" in value && Array.isArray(value.actors)) return value.actors;
  if (value && "findings" in value && Array.isArray(value.findings)) return value.findings;
  return [];
}

export function getText(value: unknown, fallback = "—"): string {
  if (typeof value === "string" && value.trim()) return value;
  if (typeof value === "number") return String(value);
  return fallback;
}

export function displayHandle(actor?: Actor | GraphNode): string {
  return getText(actor?.canonical_handle ?? actor?.handle ?? actor?.canon ?? actor?.label ?? actor?.name, "unresolved entity");
}

export function normalizeStylo(value: StyloResult | StyloResult[] | undefined): StyloResult | undefined {
  if (Array.isArray(value)) return value[0];
  return value;
}

export function clampConfidence(value?: number): number {
  if (typeof value !== "number" || Number.isNaN(value)) return 0;
  return Math.max(0, Math.min(1, value));
}

export function errorText(error: unknown): string {
  if (error instanceof Error && error.message) return error.message;
  return "The backend did not return a usable response.";
}