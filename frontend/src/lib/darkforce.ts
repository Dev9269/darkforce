import { apiGet, apiPost } from "@/lib/api";

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

export const getStats = () => apiGet<Stats>("/stats");
export const getSites = () => apiGet<JsonRecord[]>("/sites");
export const getCategories = () => apiGet<CategoriesResponse>("/categories");
export const getAlerts = () => apiGet<LiveAlert[]>("/alerts");
export const getIdentifiers = () => apiGet<Identifier[]>("/identifiers");
export const getActors = () => apiGet<Actor[]>("/actors");
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