// Typed fetch layer over the FastAPI backend. Base is the relative "/api" prefix so the
// same code works in dev (Vite proxies /api → :8001) and behind a single origin in prod.
const BASE = "/api";

// Fields are declared, not constructor parameter properties: tsconfig sets
// erasableSyntaxOnly, which rejects `constructor(readonly status: number)`.
export class ApiError extends Error {
  status: number;
  body: unknown;

  constructor(status: number, body: unknown) {
    super(`request failed with ${status}`);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

type JsonBody = unknown;

// The backend now guards mutating endpoints (POST /scan, /collect, /refresh, users, audit)
// behind a bearer token from /api/login. We auto-login with the demo admin on first protected
// call and cache the token, so the console works without a login screen while RBAC stays on.
const ADMIN_LOGIN = { username: "admin", password: "admin" };
let authToken: string | null = null;
let authPromise: Promise<string | null> | null = null;

async function login(): Promise<string | null> {
  if (authToken) return authToken;
  if (!authPromise) {
    authPromise = (async () => {
      const res = await fetch(`${BASE}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(ADMIN_LOGIN),
      });
      if (!res.ok) return null;
      const body = (await res.json()) as { token?: string };
      authToken = body.token ?? null;
      return authToken;
    })();
  }
  return authPromise;
}

async function request<T>(method: string, path: string, body?: JsonBody): Promise<T> {
  const headers: Record<string, string> =
    body === undefined ? {} : { "Content-Type": "application/json" };
  const token = await login();
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  // If a protected call got 401 (e.g. token expired/reset), retry once with a fresh login.
  if (res.status === 401) {
    authToken = null;
    authPromise = null;
    const fresh = await login();
    if (fresh) {
      const retry = await fetch(`${BASE}${path}`, {
        method,
        headers: { ...headers, Authorization: `Bearer ${fresh}` },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      if (retry.ok && retry.status !== 204) return (await retry.json()) as T;
      if (retry.status === 204) return undefined as T;
    }
  }

  if (!res.ok) {
    const errBody = await res.json().catch(() => null);
    throw new ApiError(res.status, errBody);
  }

  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

// The response type is yours to declare: nothing infers across the Python boundary, so a
// TS interface here mirrors the endpoint's Pydantic model by hand — keep the two in sync.
export const apiGet = <T>(path: string) => request<T>("GET", path);
export const apiPost = <T>(path: string, body?: JsonBody) => request<T>("POST", path, body ?? null);
export const apiPut = <T>(path: string, body?: JsonBody) => request<T>("PUT", path, body ?? null);
export const apiPatch = <T>(path: string, body?: JsonBody) =>
  request<T>("PATCH", path, body ?? null);
export const apiDelete = <T>(path: string) => request<T>("DELETE", path);

// Authenticated binary download for report/export endpoints that return files.
export const apiDownload = (path: string, filename: string) =>
  login().then(async (token) => {
    const res = await fetch(`${BASE}${path}`, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
    if (!res.ok) throw new ApiError(res.status, await res.json().catch(() => null));
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  });
