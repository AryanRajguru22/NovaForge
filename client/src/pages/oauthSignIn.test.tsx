import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import OAuthSignIn from "./OAuthSignIn.js";
import { PublicOnlyRoute, ProtectedRoute } from "../components/RouteGuards.js";
import { rememberOAuthResume } from "../lib/oauthResume.js";

const auth = vi.hoisted(() => ({ status: "loading" as "loading" | "authenticated" | "anonymous" }));
vi.mock("../lib/auth.js", () => ({
  useAuth: () => ({ status: auth.status, user: null, refresh: async () => {}, logout: async () => {} }),
}));

const QUERY = "?client_id=pashupatastra&state=s1&nonce=n1&code_challenge=c&code_challenge_method=S256&scope=openid";
const replace = vi.fn();

function stubLocation(search: string) {
  vi.stubGlobal("location", { search, replace, pathname: "/oauth/signin", href: `http://localhost/oauth/signin${search}` });
}

function renderApp(initial: string) {
  return render(
    <MemoryRouter initialEntries={[initial]}>
      <Routes>
        <Route path="/oauth/signin" element={<OAuthSignIn />} />
        <Route element={<PublicOnlyRoute />}>
          <Route path="/login" element={<div>LOGIN PAGE</div>} />
        </Route>
        <Route element={<ProtectedRoute />}>
          <Route path="/approvals" element={<div>APPROVALS PAGE</div>} />
        </Route>
      </Routes>
    </MemoryRouter>,
  );
}

describe("OAuth sign-in page and route guards", () => {
  beforeEach(() => {
    window.sessionStorage.clear();
    replace.mockReset();
  });
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("hands an authenticated browser straight back to the authorize endpoint with the original query", () => {
    auth.status = "authenticated";
    stubLocation(QUERY);
    renderApp(`/oauth/signin${QUERY}`);
    expect(replace).toHaveBeenCalledTimes(1);
    expect(replace).toHaveBeenCalledWith(`/api/oauth/authorize${QUERY}`);
  });

  it("sends an anonymous browser to /login and remembers the request", () => {
    auth.status = "anonymous";
    stubLocation(QUERY);
    renderApp(`/oauth/signin${QUERY}`);
    expect(screen.getByText("LOGIN PAGE")).toBeTruthy();
    expect(replace).not.toHaveBeenCalled();
    expect(window.sessionStorage.getItem("nf.oauth.resume")).toContain("client_id=pashupatastra");
  });

  it("waits while the session state is unknown and does not redirect", () => {
    auth.status = "loading";
    stubLocation(QUERY);
    renderApp(`/oauth/signin${QUERY}`);
    expect(screen.getByText("Continuing sign-in…")).toBeTruthy();
    expect(replace).not.toHaveBeenCalled();
  });

  it("explains itself, instead of redirecting, when opened with no authorize request", () => {
    auth.status = "authenticated";
    stubLocation("");
    renderApp("/oauth/signin");
    expect(screen.getByRole("alert").textContent).toContain("Nothing to sign in to");
    expect(replace).not.toHaveBeenCalled();
  });

  it("an already signed-in user opening /login is sent to a pending OAuth resume, not the dashboard", () => {
    auth.status = "authenticated";
    rememberOAuthResume(QUERY);
    stubLocation(QUERY);
    renderApp("/login");
    // /login bounces to /oauth/signin, which forwards to the authorize endpoint.
    expect(replace).toHaveBeenCalledWith(`/api/oauth/authorize${QUERY}`);
  });

  it("without a pending resume, an authenticated user at /login lands on the dashboard", () => {
    auth.status = "authenticated";
    stubLocation("");
    renderApp("/login");
    expect(screen.getByText("APPROVALS PAGE")).toBeTruthy();
  });

  it("protected routes bounce anonymous users to /login", () => {
    auth.status = "anonymous";
    stubLocation("");
    renderApp("/approvals");
    expect(screen.getByText("LOGIN PAGE")).toBeTruthy();
  });
});
