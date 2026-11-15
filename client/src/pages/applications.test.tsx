import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import Applications from "./Applications.js";

const mocks = vi.hoisted(() => ({
  role: "SUPER_ADMIN" as "SUPER_ADMIN" | "ADMIN",
  apiGet: vi.fn(),
  apiPost: vi.fn(),
  apiDelete: vi.fn(),
  governanceProof: vi.fn(),
}));

vi.mock("../lib/api.js", async () => {
  const actual = await vi.importActual<typeof import("../lib/api.js")>("../lib/api.js");
  return { ...actual, apiGet: mocks.apiGet, apiPost: mocks.apiPost, apiDelete: mocks.apiDelete };
});
vi.mock("../lib/stepUp.js", () => ({
  APPLICATION_STEP_UP_PATH: "/applications/step-up/options",
  governanceProof: mocks.governanceProof,
}));
vi.mock("../lib/auth.js", () => ({
  useAuth: () => ({ status: "authenticated", user: { id: "me", role: mocks.role, email: "me@x.io", name: "Me" }, refresh: async () => {}, logout: async () => {} }),
}));

const APP = { id: "app-1", clientId: "pashupatastra", name: "Pashupatastra", type: "CONFIDENTIAL", status: "ACTIVE", _count: { roles: 1, permissions: 2, assignments: 1, grants: 1 } };
const DETAIL = {
  ...APP,
  description: "Rail console",
  redirectUris: ["https://pp.example/cb"],
  postLogoutRedirectUris: [],
  allowedScopes: ["openid", "roles"],
  audience: "pashupatastra-api",
  requireAssignment: true,
  accessTokenTtlSec: 600,
  secrets: [{ id: "s1", label: "prod", createdAt: "2026-01-01T00:00:00Z", expiresAt: null, revokedAt: null, lastUsedAt: null }],
  roles: [{ id: "role-1", key: "authority", name: "Authority", description: null, assignmentCount: 1, permissions: ["corridor:approve"] }],
};
const ASSIGNMENT = { id: "as-1", user: { id: "u1", email: "ops@x.io", name: "Ops", status: "ACTIVE" }, role: { id: "role-1", key: "authority", name: "Authority" }, resource: "*", expiresAt: null };
const GRANT = { id: "g-1", user: { email: "ops@x.io", name: "Ops" }, scope: "openid roles", createdAt: "2026-02-01T00:00:00Z" };

function routeGets() {
  mocks.apiGet.mockImplementation(async (path: string) => {
    if (path.startsWith("/applications?")) return { items: [APP], total: 1 };
    if (path === "/applications/app-1") return DETAIL;
    if (path.startsWith("/applications/app-1/assignments")) return { items: [ASSIGNMENT], total: 1 };
    if (path.startsWith("/applications/app-1/grants")) return { items: [GRANT], total: 1 };
    if (path === "/users") return [{ id: "u2", email: "new@x.io", name: "Newbie" }];
    throw new Error(`unexpected GET ${path}`);
  });
}

async function openPanel() {
  render(
    <MemoryRouter>
      <Applications />
    </MemoryRouter>,
  );
  fireEvent.click(await screen.findByRole("button", { name: "Manage" }));
  await screen.findByRole("region", { name: "Pashupatastra details" });
}

describe("Applications console", () => {
  beforeEach(() => {
    for (const m of [mocks.apiGet, mocks.apiPost, mocks.apiDelete, mocks.governanceProof]) m.mockReset();
    routeGets();
    mocks.apiPost.mockResolvedValue({});
    mocks.apiDelete.mockResolvedValue({ revoked: true });
    mocks.governanceProof.mockResolvedValue({ id: "assertion" });
  });
  afterEach(cleanup);

  it("lists applications and shows redirect URIs, roles, assignments and grants", async () => {
    mocks.role = "SUPER_ADMIN";
    await openPanel();
    const panel = screen.getByRole("region", { name: "Pashupatastra details" });
    expect(within(panel).getByText("https://pp.example/cb")).toBeTruthy();
    expect(within(panel).getByText("corridor:approve")).toBeTruthy();
    expect(within(panel).getByText("ops@x.io", { selector: "span" })).toBeTruthy();
  });

  it("a super admin assigns a role: passkey ceremony first, then POST carrying its proof", async () => {
    mocks.role = "SUPER_ADMIN";
    await openPanel();
    const form = screen.getByRole("form", { name: "Assign a role" });
    fireEvent.change(within(form).getByLabelText("User"), { target: { value: "u2" } });
    fireEvent.change(within(form).getByLabelText("Role"), { target: { value: "role-1" } });
    fireEvent.click(within(form).getByRole("button", { name: "Assign" }));

    await waitFor(() => expect(mocks.apiPost).toHaveBeenCalledTimes(1));
    expect(mocks.governanceProof).toHaveBeenCalledWith("/applications/step-up/options");
    expect(mocks.apiPost).toHaveBeenCalledWith("/applications/app-1/assignments", {
      userId: "u2",
      roleId: "role-1",
      resource: "*",
      response: { id: "assertion" },
    });
    expect(mocks.governanceProof.mock.invocationCallOrder[0]).toBeLessThan(mocks.apiPost.mock.invocationCallOrder[0]);
    await screen.findByText("Role assigned.");
  });

  it("revoking an assignment needs the passkey proof; revoking a live grant does not", async () => {
    mocks.role = "SUPER_ADMIN";
    await openPanel();
    const [revokeAssignment, revokeGrant] = screen.getAllByRole("button", { name: "Revoke" });

    fireEvent.click(revokeAssignment);
    await waitFor(() => expect(mocks.apiDelete).toHaveBeenCalledWith("/applications/app-1/assignments/as-1", { response: { id: "assertion" } }));
    expect(mocks.governanceProof).toHaveBeenCalledTimes(1);

    fireEvent.click(revokeGrant);
    await waitFor(() => expect(mocks.apiDelete).toHaveBeenCalledWith("/applications/app-1/grants/g-1"));
    expect(mocks.governanceProof).toHaveBeenCalledTimes(1); // no second ceremony
  });

  it("shows the server's error and does not claim success when the change is refused", async () => {
    mocks.role = "SUPER_ADMIN";
    const { ApiError } = await vi.importActual<typeof import("../lib/api.js")>("../lib/api.js");
    mocks.apiPost.mockRejectedValue(new ApiError("Fresh passkey confirmation required", 403));
    await openPanel();
    const form = screen.getByRole("form", { name: "Assign a role" });
    fireEvent.change(within(form).getByLabelText("User"), { target: { value: "u2" } });
    fireEvent.change(within(form).getByLabelText("Role"), { target: { value: "role-1" } });
    fireEvent.click(within(form).getByRole("button", { name: "Assign" }));
    expect((await screen.findByRole("alert")).textContent).toContain("Fresh passkey confirmation required");
    expect(screen.queryByText("Role assigned.")).toBeNull();
  });

  it("an ADMIN gets a read-only view: no assign form, no revoke buttons, no user list fetched", async () => {
    mocks.role = "ADMIN";
    await openPanel();
    expect(screen.queryByRole("form", { name: "Assign a role" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Revoke" })).toBeNull();
    expect(mocks.apiGet).not.toHaveBeenCalledWith("/users");
  });
});
