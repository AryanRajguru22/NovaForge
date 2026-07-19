import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  startTestServer,
  stopTestServer,
  apiRequest,
  createUserWithToken,
  cleanupUsers,
  cleanupPolicies,
  runSuffix,
} from "./testServer.js";
import { prisma } from "../src/lib/prisma.js";

describe("trust-level gating on sensitive-action writes", () => {
  const email = `trust-test-${runSuffix}@example.com`;
  const actionType = "test:trust-gate";

  let user: { id: string; token: string };
  let sessionId: string;

  beforeAll(async () => {
    await startTestServer();
    await cleanupUsers([email]);
    await prisma.approvalRequest.deleteMany({ where: { policy: { actionType } } });
    await prisma.sensitiveAction.deleteMany({ where: { type: actionType } });
    await cleanupPolicies([actionType]);

    const created = await createUserWithToken({ email, role: "MEMBER" });
    user = { id: created.user.id, token: created.token };

    const payload = JSON.parse(Buffer.from(created.token.split(".")[1], "base64url").toString());
    sessionId = payload.sessionId;

    await prisma.approvalPolicy.create({
      data: { actionType, quorumType: "N_OF_M", minApprovals: 1, eligibleRoles: ["APPROVER"], escalationTimeoutSec: 300 },
    });
  });

  afterAll(async () => {
    await prisma.approvalRequest.deleteMany({ where: { policy: { actionType } } });
    await prisma.sensitiveAction.deleteMany({ where: { requestedBy: { email } } });
    await cleanupPolicies([actionType]);
    await cleanupUsers([email]);
    await stopTestServer();
  });

  it("allows creating a sensitive action at full trust", async () => {
    const res = await apiRequest("/actions", {
      method: "POST",
      token: user.token,
      body: { type: actionType, payload: { amount: 1 } },
    });
    expect(res.status).toBe(201);
  });

  it("blocks creating a sensitive action once session trust decays below the threshold", async () => {
    await prisma.session.update({ where: { id: sessionId }, data: { trustLevel: 10 } });

    const res = await apiRequest("/actions", {
      method: "POST",
      token: user.token,
      body: { type: actionType, payload: { amount: 2 } },
    });
    expect(res.status).toBe(403);
    expect(res.data.error).toMatch(/trust/i);
  });
});
