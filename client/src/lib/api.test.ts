import { describe, it, expect, vi, beforeEach } from "vitest";
import { apiGet, apiPost, ApiError } from "./api.js";

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

describe("api client session refresh", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("returns data for a normal response without refreshing", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(json(200, { ok: 1 }));
    await expect(apiGet("/x")).resolves.toEqual({ ok: 1 });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("refreshes once on 401 and retries the original request with credentials", async () => {
    const calls: string[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = String(input);
      calls.push(url);
      expect(init?.credentials).toBe("include");
      if (url.endsWith("/auth/session/refresh")) return json(200, {});
      return calls.filter((c) => c.endsWith("/x")).length === 1 ? json(401, { error: "expired" }) : json(200, { ok: true });
    });
    await expect(apiGet("/x")).resolves.toEqual({ ok: true });
    expect(calls).toEqual(["/api/x", "/api/auth/session/refresh", "/api/x"]);
  });

  it("shares a single in-flight refresh between concurrent 401s", async () => {
    let refreshes = 0;
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const seen = new Map<string, number>();
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith("/auth/session/refresh")) {
        refreshes++;
        await gate;
        return json(200, {});
      }
      const n = (seen.get(url) ?? 0) + 1;
      seen.set(url, n);
      return n === 1 ? json(401, { error: "expired" }) : json(200, { url });
    });
    const all = Promise.all([apiGet("/a"), apiGet("/b"), apiGet("/c")]);
    await vi.waitFor(() => expect(refreshes).toBe(1));
    release();
    await all;
    expect(refreshes).toBe(1);
  });

  it("does not loop: a request still 401 after a successful refresh fails with ApiError", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      return String(input).endsWith("/auth/session/refresh") ? json(200, {}) : json(401, { error: "nope" });
    });
    await expect(apiGet("/x")).rejects.toMatchObject({ status: 401, message: "nope" });
    // original + refresh + exactly one retry, never more
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("surfaces the original 401 when the refresh itself fails, without retrying", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      return String(input).endsWith("/auth/session/refresh") ? json(401, {}) : json(401, { error: "expired" });
    });
    await expect(apiGet("/x")).rejects.toBeInstanceOf(ApiError);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("treats a network failure during refresh as a failed refresh", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      if (String(input).endsWith("/auth/session/refresh")) throw new TypeError("network down");
      return json(401, { error: "expired" });
    });
    await expect(apiGet("/x")).rejects.toMatchObject({ status: 401 });
  });

  it("sends JSON bodies for POST and uses a generic message when the error body has none", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(json(500, {}));
    await expect(apiPost("/y", { a: 1 })).rejects.toMatchObject({ status: 500, message: "Request failed (500)" });
    const init = fetchMock.mock.calls[0][1]!;
    expect(init.method).toBe("POST");
    expect(init.body).toBe(JSON.stringify({ a: 1 }));
  });
});
