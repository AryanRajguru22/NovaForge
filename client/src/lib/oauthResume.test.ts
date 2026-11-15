import { describe, it, expect, beforeEach, vi } from "vitest";
import { authorizeUrl, clearOAuthResume, postLoginDestination, rememberOAuthResume, RESUME_TTL_MS } from "./oauthResume.js";

const KEY = "nf.oauth.resume";
const QUERY = "?client_id=pashupatastra&state=abc&code_challenge=xyz&scope=openid";

describe("OIDC sign-in resume", () => {
  beforeEach(() => {
    window.sessionStorage.clear();
    vi.useRealTimers();
  });

  it("defaults to the app when nothing is pending", () => {
    expect(postLoginDestination()).toBe("/approvals");
  });

  it("remembers an authorize query and resumes at the fixed sign-in path", () => {
    expect(rememberOAuthResume(QUERY)).toBe(true);
    expect(postLoginDestination()).toBe(`/oauth/signin${QUERY}`);
    // Peeking does not consume it: Login and the route guard both read it.
    expect(postLoginDestination()).toBe(`/oauth/signin${QUERY}`);
    clearOAuthResume();
    expect(postLoginDestination()).toBe("/approvals");
  });

  it.each([
    ["", "empty"],
    ["?", "bare question mark"],
    ["client_id=a", "no leading ?"],
    ["?a=b c", "whitespace"],
    ["?" + "a".repeat(4001), "too long"],
  ])("refuses to remember %j (%s)", (query) => {
    expect(rememberOAuthResume(query)).toBe(false);
    expect(window.sessionStorage.getItem(KEY)).toBeNull();
  });

  it.each([
    ["https://evil.example/steal"],
    ["//evil.example"],
    ["/approvals"],
    ["/oauth/signin"],
    ["/oauth/signin?x y"],
    ["javascript:alert(1)"],
  ])("ignores a tampered stored destination %j", (value) => {
    window.sessionStorage.setItem(KEY, JSON.stringify({ value, at: Date.now() }));
    expect(postLoginDestination()).toBe("/approvals");
  });

  it("ignores malformed stored data", () => {
    window.sessionStorage.setItem(KEY, "not json");
    expect(postLoginDestination()).toBe("/approvals");
    window.sessionStorage.setItem(KEY, JSON.stringify({ value: 5, at: "x" }));
    expect(postLoginDestination()).toBe("/approvals");
  });

  it("expires an abandoned sign-in so it cannot redirect a later, unrelated login", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
    rememberOAuthResume(QUERY);
    vi.setSystemTime(new Date(Date.now() + RESUME_TTL_MS - 1000));
    expect(postLoginDestination()).toBe(`/oauth/signin${QUERY}`);
    vi.setSystemTime(new Date(Date.now() + 2000));
    expect(postLoginDestination()).toBe("/approvals");
  });

  it("builds the authorize URL on a constant path, whatever the query contains", () => {
    expect(authorizeUrl(QUERY)).toBe(`/api/oauth/authorize${QUERY}`);
    expect(authorizeUrl("?redirect_uri=https://evil.example").startsWith("/api/oauth/authorize?")).toBe(true);
  });
});
