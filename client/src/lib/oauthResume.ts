// Resuming an OpenID Connect sign-in.
//
// When a relying application sends a browser to /api/oauth/authorize and the
// user has no NovaForge session, the server redirects to /oauth/signin with the
// original authorize query. That page remembers the query across the normal
// /login flow (passkey, TOTP or recovery code) and, once a session exists,
// sends the browser back to the authorize endpoint so it can finish.
//
// Only the query string is carried. The destination path is fixed here, and the
// server re-validates every parameter (client, exact redirect URI, PKCE, state,
// nonce), so nothing in this file can be steered to another site.

const KEY = "nf.oauth.resume";
export const OAUTH_SIGNIN_PATH = "/oauth/signin";
export const AUTHORIZE_PATH = "/api/oauth/authorize";
const DEFAULT_DESTINATION = "/approvals";
const MAX_QUERY_LENGTH = 4000;
// An abandoned sign-in must not redirect a much later, unrelated login.
export const RESUME_TTL_MS = 10 * 60 * 1000;
// "/oauth/signin" followed by "?" and printable ASCII only.
const RESUME_PATTERN = /^\/oauth\/signin\?[\x21-\x7e]+$/;

function storage(): Storage | null {
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}

/** Remembers an authorize query ("?client_id=…") to resume after sign-in. Returns false if it is not usable. */
export function rememberOAuthResume(search: string): boolean {
  if (!search.startsWith("?") || search.length < 2 || search.length > MAX_QUERY_LENGTH) return false;
  const value = `${OAUTH_SIGNIN_PATH}${search}`;
  if (!RESUME_PATTERN.test(value)) return false;
  try {
    storage()?.setItem(KEY, JSON.stringify({ value, at: Date.now() }));
    return true;
  } catch {
    return false;
  }
}

export function clearOAuthResume(): void {
  try {
    storage()?.removeItem(KEY);
  } catch {
    /* storage unavailable: nothing to clear */
  }
}

/** Where to go after a successful sign-in: a pending OAuth resume, else the app. Does not consume it. */
export function postLoginDestination(): string {
  try {
    const raw = storage()?.getItem(KEY);
    if (raw) {
      const { value, at } = JSON.parse(raw) as { value?: unknown; at?: unknown };
      if (typeof value === "string" && typeof at === "number" && Date.now() - at < RESUME_TTL_MS && RESUME_PATTERN.test(value)) {
        return value;
      }
    }
  } catch {
    /* fall through */
  }
  return DEFAULT_DESTINATION;
}

/** The authorize endpoint URL for a query string; the path is constant. */
export function authorizeUrl(search: string): string {
  return `${AUTHORIZE_PATH}${search}`;
}
