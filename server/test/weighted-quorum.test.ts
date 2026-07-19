import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  startTestServer,
  stopTestServer,
  apiRequest,
  createUserWithToken,
  addMockPasskey,
  cleanupUsers,
  cleanupPolicies,
  runSuffix,
} from "./testServer.js";
import { prisma } from "../src/lib/prisma.js";

function mockVoteResponse(credentialId: string, signature: string) {
  return {
    id: credentialId,
    response: {
      clientDataJSON: "mock-client-data",
      authenticatorData: "mock-authenticator-data",
      signature,
    },
  };
}

async function castVote(requestId: string, voter: { id: string; token: string }, decision: "APPROVE" | "REJECT", signature: string) {
  const options = await apiRequest(`/approvals/${requestId}/options`, { method: "POST", token: voter.token });
  if (options.status !== 200) return options;
  return apiRequest(`/approvals/${requestId}/vote`, {
    method: "POST",
    token: voter.token,
    body: { decision, response: mockVoteResponse(`mock-cred-${voter.id}`, signature) },
  });
}

describe("WEIGHTED quorum resolution", () => {
  const emails = [
    `weighted-creator-${runSuffix}@example.com`,
    `weighted-light-${runSuffix}@example.com`,
    `weighted-heavy-${runSuffix}@example.com`,
  ];
  const weightedType = "test:vote-weighted";

  let creator: { id: string; token: string };
  let lightVoter: { id: string; token: string };
  let heavyVoter: { id: string; token: string };

  beforeAll(async () => {
    await startTestServer();
    await cleanupUsers(emails);
    await cleanupPolicies([weightedType]);

    const c = await createUserWithToken({ email: emails[0], role: "MEMBER" });
    const light = await createUserWithToken({ email: emails[1], role: "APPROVER" });
    const heavy = await createUserWithToken({ email: emails[2], role: "APPROVER" });

    creator = { id: c.user.id, token: c.token };
    lightVoter = { id: light.user.id, token: light.token };
    heavyVoter = { id: heavy.user.id, token: heavy.token };

    for (const u of [lightVoter, heavyVoter]) {
      await addMockPasskey(u.id);
    }

    // heavyVoter's single vote (weight 3) alone clears the threshold (3);
    // lightVoter's alone (weight 1) doesn't.
    await prisma.user.update({ where: { id: lightVoter.id }, data: { voteWeight: 1 } });
    await prisma.user.update({ where: { id: heavyVoter.id }, data: { voteWeight: 3 } });

    await prisma.approvalPolicy.create({
      data: {
        actionType: weightedType,
        quorumType: "WEIGHTED",
        minApprovals: 3,
        eligibleRoles: ["APPROVER"],
        escalationTimeoutSec: 300,
      },
    });
  });

  afterAll(async () => {
    await prisma.approvalVote.deleteMany({ where: { request: { policy: { actionType: weightedType } } } });
    await prisma.approvalRequest.deleteMany({ where: { policy: { actionType: weightedType } } });
    await prisma.sensitiveAction.deleteMany({ where: { requestedBy: { email: { in: emails } } } });
    await cleanupPolicies([weightedType]);
    await cleanupUsers(emails);
    await stopTestServer();
  });

  it("does not resolve APPROVED when combined vote weight is below the threshold", async () => {
    const { data: created } = await apiRequest("/actions", {
      method: "POST",
      token: creator.token,
      body: { type: weightedType, payload: { amount: 100 } },
    });
    const requestId = created.approvalRequest.id;

    const vote = await castVote(requestId, lightVoter, "APPROVE", "sig-light");
    expect(vote.status).toBe(200);
    expect(vote.data.requestStatus).toBe("PENDING");
  });

  it("resolves APPROVED once combined vote weight reaches the threshold", async () => {
    const { data: created } = await apiRequest("/actions", {
      method: "POST",
      token: creator.token,
      body: { type: weightedType, payload: { amount: 200 } },
    });
    const requestId = created.approvalRequest.id;

    const vote = await castVote(requestId, heavyVoter, "APPROVE", "sig-heavy");
    expect(vote.status).toBe(200);
    expect(vote.data.requestStatus).toBe("APPROVED");

    const dbRequest = await prisma.approvalRequest.findUnique({ where: { id: requestId } });
    expect(dbRequest?.status).toBe("APPROVED");
  });

  it("still lets a single REJECT vote veto a WEIGHTED request regardless of weight", async () => {
    const { data: created } = await apiRequest("/actions", {
      method: "POST",
      token: creator.token,
      body: { type: weightedType, payload: { amount: 300 } },
    });
    const requestId = created.approvalRequest.id;

    const vote = await castVote(requestId, lightVoter, "REJECT", "sig-light-reject");
    expect(vote.status).toBe(200);
    expect(vote.data.requestStatus).toBe("REJECTED");
  });
});
