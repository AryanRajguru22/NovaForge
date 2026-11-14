import { Prisma } from "@prisma/client";
import { prisma } from "../prisma.js";
import { appendAuditLog, auditedTransaction } from "../audit.js";
import { generateClientSecret } from "./clientAuth.js";
import { DEFAULT_CLIENT_SCOPES } from "./config.js";

// Operator-side provisioning of relying applications (used by
// scripts/iam.ts and the tests). Idempotent: running it again converges the
// application to the declared shape and never rotates a secret unless asked.
//
// This is the break-glass / bootstrap path (it needs database access, i.e. it
// is run by the operator). Day-to-day administration goes through the
// admin API and console, which add trust and passkey step-up checks.

export interface ApplicationSpec {
  clientId: string;
  name: string;
  description?: string;
  audience: string;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  permissions: { key: string; description?: string }[];
  roles: { key: string; name: string; description?: string; permissions: string[] }[];
}

// Pashupatastra's authorization model. Permission keys are `job.<action>` for
// every action in its JobAction enum, and the roles carry exactly the actions
// its own role table (backend/app/identity/role_actions.py) already grants.
// Pashupatastra stays the enforcing party and treats NovaForge permissions as
// an additional requirement that can only narrow what its own table allows.
const READS = ["read_job", "read_job_history", "read_block_proposal", "read_job_execution", "read_job_obligations"];
export const PASHUPATASTRA_ACTIONS = [
  "report_job",
  "request_optimization",
  "assign_schedule",
  "commit_block",
  "complete_job",
  "read_job_history",
  "read_block_proposal",
  "reject_proposal",
  "postpone_proposal",
  "start_execution",
  "report_execution_not_completed",
  "read_job_execution",
  "release_committed_block",
  "read_job_obligations",
  "read_optimization_run",
  "read_job",
];

export function pashupatastraSpec(frontendOrigin: string): ApplicationSpec {
  const origin = frontendOrigin.replace(/\/+$/, "");
  const perm = (actions: string[]) => actions.map((a) => `job.${a}`);
  return {
    clientId: "pashupatastra",
    name: "Pashupatastra",
    description: "Maintenance block planning and decision support for Indian Railways",
    audience: "pashupatastra-api",
    redirectUris: [`${origin}/api/pp/auth/callback`],
    postLogoutRedirectUris: [`${origin}/`],
    permissions: PASHUPATASTRA_ACTIONS.map((a) => ({ key: `job.${a}`, description: `Pashupatastra action ${a.toUpperCase()}` })),
    roles: [
      {
        key: "worker",
        name: "Field worker / crew",
        description: "Reports defects and executes approved blocks",
        permissions: perm(["report_job", "start_execution", "complete_job", "report_execution_not_completed", ...READS]),
      },
      {
        key: "engineer",
        name: "Planning engineer",
        description: "Requests optimization runs and reads their results",
        permissions: perm(["request_optimization", "read_optimization_run", ...READS]),
      },
      {
        key: "authority",
        name: "Section authority",
        description: "Approves, rejects, postpones and releases proposed blocks",
        permissions: perm(["commit_block", "reject_proposal", "postpone_proposal", "release_committed_block", ...READS]),
      },
      { key: "admin", name: "Administrator", description: "Administrative role; holds no railway action or scope", permissions: [] },
    ],
  };
}

export interface ProvisionResult {
  applicationId: string;
  created: boolean;
  /** Present only when a secret was issued by this call. Shown once. */
  secret?: string;
}

export async function ensureApplication(spec: ApplicationSpec, opts: { rotateSecret?: boolean; issueSecretIfNone?: boolean } = {}): Promise<ProvisionResult> {
  return auditedTransaction(async (tx) => {
    const existing = await tx.oAuthClient.findUnique({ where: { clientId: spec.clientId } });
    const data = {
      name: spec.name,
      description: spec.description,
      redirectUris: spec.redirectUris,
      postLogoutRedirectUris: spec.postLogoutRedirectUris,
      allowedScopes: [...DEFAULT_CLIENT_SCOPES],
      audience: spec.audience,
    };
    const client = existing
      ? await tx.oAuthClient.update({ where: { id: existing.id }, data: { ...data, status: "ACTIVE" } })
      : await tx.oAuthClient.create({ data: { clientId: spec.clientId, type: "CONFIDENTIAL", requireAssignment: true, ...data } });

    const permissionIds = new Map<string, string>();
    for (const p of spec.permissions) {
      const row = await tx.appPermission.upsert({
        where: { clientId_key: { clientId: client.id, key: p.key } },
        create: { clientId: client.id, key: p.key, description: p.description },
        update: { description: p.description },
      });
      permissionIds.set(p.key, row.id);
    }
    for (const r of spec.roles) {
      const role = await tx.appRole.upsert({
        where: { clientId_key: { clientId: client.id, key: r.key } },
        create: { clientId: client.id, key: r.key, name: r.name, description: r.description },
        update: { name: r.name, description: r.description },
      });
      await tx.appRolePermission.deleteMany({ where: { roleId: role.id } });
      if (r.permissions.length) {
        await tx.appRolePermission.createMany({ data: r.permissions.map((k) => ({ roleId: role.id, permissionId: permissionIds.get(k)! })) });
      }
    }

    let secret: string | undefined;
    const liveSecrets = await tx.oAuthClientSecret.count({ where: { clientId: client.id, revokedAt: null } });
    if (opts.rotateSecret || (!existing && opts.issueSecretIfNone !== false) || (liveSecrets === 0 && opts.issueSecretIfNone)) {
      const generated = generateClientSecret();
      const row = await tx.oAuthClientSecret.create({ data: { clientId: client.id, secretHash: generated.hash, label: opts.rotateSecret ? "rotated by operator" : "provisioned by operator" } });
      secret = generated.secret;
      await appendAuditLog(tx, {
        entityType: "OAuthClient",
        entityId: client.id,
        event: "APPLICATION_SECRET_ISSUED",
        actorId: null,
        metadata: { clientId: client.clientId, secretId: row.id, by: "operator-script" },
      });
    }
    await appendAuditLog(tx, {
      entityType: "OAuthClient",
      entityId: client.id,
      event: existing ? "APPLICATION_UPDATED" : "APPLICATION_CREATED",
      actorId: null,
      metadata: { clientId: client.clientId, by: "operator-script", redirectUris: spec.redirectUris, roles: spec.roles.map((r) => r.key) },
    });
    return { applicationId: client.id, created: !existing, secret } satisfies ProvisionResult;
  });
}

/** Operator-side role assignment (break-glass; the admin API enforces step-up). */
export async function assignRoleByEmail(opts: { clientId: string; email: string; roleKey: string; resource?: string; actorNote?: string }) {
  return auditedTransaction(async (tx) => {
    const client = await tx.oAuthClient.findUnique({ where: { clientId: opts.clientId } });
    if (!client) throw new Error(`Unknown application ${opts.clientId}`);
    const [role, user] = await Promise.all([
      tx.appRole.findUnique({ where: { clientId_key: { clientId: client.id, key: opts.roleKey } } }),
      tx.user.findUnique({ where: { email: opts.email.trim().toLowerCase() } }),
    ]);
    if (!role) throw new Error(`Unknown role ${opts.roleKey} in ${opts.clientId}`);
    if (!user || user.status !== "ACTIVE") throw new Error(`No active user ${opts.email}`);
    const resource = opts.resource ?? "*";
    try {
      const row = await tx.appRoleAssignment.create({ data: { clientId: client.id, roleId: role.id, userId: user.id, resource } });
      await appendAuditLog(tx, {
        entityType: "OAuthClient",
        entityId: client.id,
        event: "APP_ROLE_ASSIGNED",
        actorId: null,
        metadata: { clientId: client.clientId, role: role.key, userId: user.id, resource, by: "operator-script" },
      });
      return row;
    } catch (err) {
      if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002") throw new Error("That assignment already exists");
      throw err;
    }
  });
}

export { prisma };
