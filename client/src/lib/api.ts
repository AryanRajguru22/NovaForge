const API_BASE = "/api";

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
  }
}

// Access tokens are 15-minute httpOnly cookies (server/src/routes/auth.ts) --
// short-lived on purpose so a stolen token has a small blast radius. Without
// this, every page would silently bounce back to /login 15 minutes into any
// session even though a 30-day refresh cookie exists specifically to prevent
// that. A single in-flight promise is shared across concurrent 401s so a
// burst of requests that all expire together triggers one refresh, not one
// per request.
let refreshPromise: Promise<boolean> | null = null;

// Exported so the app root can also call this proactively on an interval --
// the session's trustLevel only gets recomputed inside this endpoint, so a
// tab that's open but idle (making no other API calls) would never see trust
// decay or recover without something calling it on a timer independent of
// whatever the user happens to click.
export async function refreshSession(): Promise<boolean> {
  if (!refreshPromise) {
    refreshPromise = fetch(`${API_BASE}/auth/session/refresh`, {
      method: "POST",
      credentials: "include",
    })
      .then((res) => res.ok)
      .catch(() => false)
      .finally(() => {
        refreshPromise = null;
      });
  }
  return refreshPromise;
}

async function request<T>(path: string, init: RequestInit, retryOn401 = true): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, { credentials: "include", ...init });

  if (res.status === 401 && retryOn401) {
    const refreshed = await refreshSession();
    if (refreshed) {
      return request<T>(path, init, false);
    }
  }

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new ApiError(data.error ?? `Request failed (${res.status})`, res.status);
  }
  return data as T;
}

export async function apiPost<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export async function apiPatch<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export async function apiGet<T>(path: string): Promise<T> {
  return request<T>(path, { method: "GET" });
}

export async function apiDelete<T>(path: string): Promise<T> {
  return request<T>(path, { method: "DELETE" });
}

export async function apiPut<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}
