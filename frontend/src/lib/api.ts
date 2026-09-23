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

// The backend guards mutating endpoints (POST /scan, /collect, /refresh, users, audit)
// behind a bearer token from /api/login. The frontend no longer hardcodes credentials;
// the admin must configure ADMIN_USER/ADMIN_PASSWORD via env vars (or DF_INSECURE=1).
// Auto-login is disabled; call login(username, password) explicitly from a login UI.
let authToken: string | null = null;

async function login(username?: string, password?: string): Promise<string | null> {
  if (authToken) return authToken;
  if (!username || !password) return null;
  const res = await fetch(`${BASE}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) return null;
  const body = (await res.json()) as { token?: string };
  authToken = body.token ?? null;
  return authToken;
}

function setAuthToken(token: string | null) {
  authToken = token;
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
export { login, setAuthToken };

// Authenticated binary download for report/export endpoints that return files.
// Assumes caller has already logged in (authToken is set).
export const apiDownload = (path: string, filename: string) => {
  const token = authToken;
  if (!token) throw new ApiError(401, "not authenticated — call login() first");
  return fetch(`${BASE}${path}`, { headers: { Authorization: `Bearer ${token}` } })
    .then(async (res) => {
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
};
