import { randomBytes } from "node:crypto";
import { Router, type NextFunction, type Request, type Response } from "express";
import { z } from "zod";
import { AccountStatus, OAuthClientType, Prisma, Role } from "@prisma/client";
import { prisma } from "../lib/prisma.js";
import { requireAuth } from "../middleware/requireAuth.js";
import { appendAuditLog, auditedTransaction } from "../lib/audit.js";
import { enforceGovernanceStepUp, governanceStepUpOptions, governanceTrust } from "../lib/governance.js";
import { recordStepUpCounter } from "../lib/stepUp.js";
import { generateClientSecret } from "../lib/oauth/clientAuth.js";
import { DEFAULT_CLIENT_SCOPES, SUPPORTED_SCOPES } from "../lib/oauth/config.js";
import { PERMISSION_KEY, ROLE_KEY, isValidResourcePattern } from "../lib/oauth/rbac.js";
import { revokeGrant } from "../lib/oauth/tokens.js";

// Administration of relying applications: registration, redirect URIs,
// credentials, per-application roles and permissions, who holds what, and the
// live grants applications hold.
//
// Authorization model
//   read    SUPER_ADMIN or ADMIN
//   write   SUPER_ADMIN only
//   Every mutation that can widen access (create/enable an application, change
//   redirect URIs, issue or revoke credentials, assign or revoke a role) also
//   needs session trust and a fresh passkey assertion (step-up), and is
//   audited in the same transaction. Nobody may assign a role to themselves.

export const applicationsRouter = Router();

async function requireAdmin(req: Request, res: Response, next: NextFunction): Promise<void> {
  const user = req.user ? await prisma.user.findUnique({ where: { id: req.user.id } }) : null;
  if (!user || user.status !== AccountStatus.ACTIVE || (user.role !== Role.SUPER_ADMIN && user.role !== Role.ADMIN)) {
    res.status(403).json({ error: "Forbidden: Admins only" });
    return;
  }
  next();
}

async function requireSuperAdmin(req: Request, res: Response, next: NextFunction): Promise<void> {
  const user = req.user ? await prisma.user.findUnique({ where: { id: req.user.id } }) : null;
  if (!user || user.status !== AccountStatus.ACTIVE || user.role !== Role.SUPER_ADMIN) {
    res.status(403).json({ error: "Forbidden: Super admins only" });
    return;
  }
  next();
}

const write = [requireAuth, requireSuperAdmin] as const;
const read = [requireAuth, requireAdmin] as const;

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** A redirect URI must be absolute, canonical, fragment-free, https (or http on loopback only). */
export function validateRedirectUri(value: string): string | null {
  if (value.length > 2000 || value.includes("*")) return null;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  const loopback = LOOPBACK_HOSTS.has(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) return null;
  if (url.hash || url.username || url.password || url.href !== value) return null;
  return value;
}

const uriList = z
  .array(z.string())
  .max(20)
  .refine((list) => list.every((u) => validateRedirectUri(u) !== null), {
    message: "Each URI must be absolute and canonical, https (http only for localhost), with no fragment, credentials or wildcard",
  })
  .transform((list) => [...new Set(list)]);

const scopeList = z.array(z.enum(SUPPORTED_SCOPES)).min(1);
const permissionKey = z.string().regex(PERMISSION_KEY, "lowercase letters, digits and : . _ - (max 100)");
const roleKey = z.string().regex(ROLE_KEY, "letters, digits and _ . - (max 64)");

const permissionDef = z.object({ key: permissionKey, description: z.string().trim().max(300).optional() });
const roleDef = z.object({
  key: roleKey,
  name: z.string().trim().min(1).max(100),
  description: z.string().trim().max(300).optional(),
  permissions: z.array(permissionKey).max(200).default([]),
});

const createSchema = z.object({
  name: z.string().trim().min(1).max(100),
  clientId: z.string().regex(/^[a-z0-9][a-z0-9_-]{2,62}$/).optional(),
  description: z.string().trim().max(500).optional(),
  type: z.nativeEnum(OAuthClientType).default("CONFIDENTIAL"),
  audience: z.string().trim().min(1).max(200).regex(/^[A-Za-z0-9._:/-]+$/).optional(),
  redirectUris: uriList,
  postLogoutRedirectUris: uriList.default([]),
  allowedScopes: scopeList.default([...DEFAULT_CLIENT_SCOPES]),
  requireAssignment: z.boolean().default(true),
  accessTokenTtlSec: z.number().int().min(60).max(3600).default(600),
  permissions: z.array(permissionDef).max(200).default([]),
  roles: z.array(roleDef).max(100).default([]),
});

const updateSchema = z
  .object({
    name: z.string().trim().min(1).max(100),
    description: z.string().trim().max(500).nullable(),
    redirectUris: uriList,
    postLogoutRedirectUris: uriList,
    allowedScopes: scopeList,
    requireAssignment: z.boolean(),
    accessTokenTtlSec: z.number().int().min(60).max(3600),
    status: z.nativeEnum(AccountStatus),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Nothing to update" });

const clientPublicSelect = {
  id: true,
  clientId: true,
  name: true,
  description: true,
  type: true,
  status: true,
  redirectUris: true,
  postLogoutRedirectUris: true,
  allowedScopes: true,
  audience: true,
  requireAssignment: true,
  accessTokenTtlSec: true,
  createdAt: true,
  updatedAt: true,
} as const;

function badRequest(res: Response, issues: z.ZodIssue[]): void {
  res.status(400).json({ error: "Invalid request", issues });
}

function isUniqueViolation(err: unknown): boolean {
  return err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002";
}

function pageParams(req: Request): { skip: number; take: number; page: number; pageSize: number } {
  const page = Math.max(1, Number.parseInt(String(req.query.page ?? "1"), 10) || 1);
  const pageSize = Math.min(100, Math.max(1, Number.parseInt(String(req.query.pageSize ?? "25"), 10) || 25));
  return { skip: (page - 1) * pageSize, take: pageSize, page, pageSize };
}

function searchTerm(req: Request): string | undefined {
  const q = typeof req.query.search === "string" ? req.query.search.trim().slice(0, 100) : "";
  return q || undefined;
}

class RouteError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

function handleRouteError(err: unknown, res: Response): boolean {
  if (err instanceof RouteError) {
    res.status(err.status).json({ error: err.message });
    return true;
  }
  if (isUniqueViolation(err)) {
    res.status(409).json({ error: "That already exists" });
    return true;
  }
  if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2025") {
    res.status(404).json({ error: "Not found" });
    return true;
  }
  return false;
}

async function findClient(idOrClientId: string) {
  const uuid = /^[0-9a-f-]{36}$/i.test(idOrClientId);
  return prisma.oAuthClient.findFirst({ where: uuid ? { id: idOrClientId } : { clientId: idOrClientId } });
}

// ---------------------------------------------------------------------------
// Step-up ceremony
// ---------------------------------------------------------------------------

applicationsRouter.post("/step-up/options", ...write, governanceTrust("app:step-up"), governanceStepUpOptions("app-governance"));

// ---------------------------------------------------------------------------
// Applications
// ---------------------------------------------------------------------------

applicationsRouter.get("/", ...read, async (req, res) => {
  const { skip, take, page, pageSize } = pageParams(req);
  const search = searchTerm(req);
  const where: Prisma.OAuthClientWhereInput = search
    ? { OR: [{ name: { contains: search, mode: "insensitive" } }, { clientId: { contains: search, mode: "insensitive" } }] }
    : {};
  const [total, items] = await Promise.all([
    prisma.oAuthClient.count({ where }),
    prisma.oAuthClient.findMany({
      where,
      skip,
      take,
      orderBy: { createdAt: "desc" },
      select: { ...clientPublicSelect, _count: { select: { roles: true, permissions: true, assignments: true, grants: { where: { revokedAt: null } } } } },
    }),
  ]);
  res.json({ items, total, page, pageSize });
});

applicationsRouter.post("/", ...write, governanceTrust("app:create"), async (req, res) => {
  const stepUp = await enforceGovernanceStepUp(req, res, "app-governance", "app:create");
  if (!stepUp) return;
  const parsed = createSchema.safeParse(req.body);
  if (!parsed.success) return badRequest(res, parsed.error.issues);
  const data = parsed.data;
  if (data.type === "CONFIDENTIAL" && data.redirectUris.length === 0) {
    res.status(400).json({ error: "At least one redirect URI is required" });
    return;
  }
  const clientId = data.clientId ?? `app_${randomBytes(9).toString("base64url").toLowerCase().replace(/[^a-z0-9]/g, "x")}`;
  const declared = new Set(data.permissions.map((p) => p.key));
  for (const role of data.roles) {
    for (const key of role.permissions) {
      if (!declared.has(key)) {
        res.status(400).json({ error: `Role ${role.key} references undefined permission ${key}` });
        return;
      }
    }
  }

  try {
    const result = await auditedTransaction(async (tx) => {
      await recordStepUpCounter(tx, stepUp);
      const client = await tx.oAuthClient.create({
        data: {
          clientId,
          name: data.name,
          description: data.description,
          type: data.type,
          audience: data.audience ?? clientId,
          redirectUris: data.redirectUris,
          postLogoutRedirectUris: data.postLogoutRedirectUris,
          allowedScopes: data.allowedScopes,
          requireAssignment: data.requireAssignment,
          accessTokenTtlSec: data.accessTokenTtlSec,
          createdById: req.user!.id,
        },
        select: clientPublicSelect,
      });
      const permissionIds = new Map<string, string>();
      for (const p of data.permissions) {
        const created = await tx.appPermission.create({ data: { clientId: client.id, key: p.key, description: p.description } });
        permissionIds.set(p.key, created.id);
      }
      for (const r of data.roles) {
        const role = await tx.appRole.create({ data: { clientId: client.id, key: r.key, name: r.name, description: r.description } });
        if (r.permissions.length > 0) {
          await tx.appRolePermission.createMany({
            data: r.permissions.map((key) => ({ roleId: role.id, permissionId: permissionIds.get(key)! })),
          });
        }
      }
      let secret: { id: string; value: string } | null = null;
      if (client.type === "CONFIDENTIAL") {
        const generated = generateClientSecret();
        const row = await tx.oAuthClientSecret.create({ data: { clientId: client.id, secretHash: generated.hash, label: "initial" } });
        secret = { id: row.id, value: generated.secret };
      }
      await appendAuditLog(tx, {
        entityType: "OAuthClient",
        entityId: client.id,
        event: "APPLICATION_CREATED",
        actorId: req.user!.id,
        metadata: {
          clientId: client.clientId,
          name: client.name,
          type: client.type,
          redirectUris: client.redirectUris,
          roles: data.roles.map((r) => r.key),
          permissions: data.permissions.map((p) => p.key),
          stepUpCredentialId: stepUp.credentialId,
        },
      });
      return { client, secret };
    });
    // The secret is returned exactly once; only its hash is stored.
    res.status(201).json({ application: result.client, secret: result.secret });
  } catch (err) {
    if (!handleRouteError(err, res)) throw err;
  }
});

applicationsRouter.get("/:id", ...read, async (req, res) => {
  const client = await prisma.oAuthClient.findFirst({
    where: /^[0-9a-f-]{36}$/i.test(req.params.id) ? { id: req.params.id } : { clientId: req.params.id },
    select: {
      ...clientPublicSelect,
      secrets: { select: { id: true, label: true, createdAt: true, expiresAt: true, revokedAt: true, lastUsedAt: true }, orderBy: { createdAt: "desc" } },
      permissions: { orderBy: { key: "asc" } },
      roles: {
        orderBy: { key: "asc" },
        include: { permissions: { include: { permission: true } }, _count: { select: { assignments: true } } },
      },
      _count: { select: { assignments: true, grants: { where: { revokedAt: null } } } },
    },
  });
  if (!client) {
    res.status(404).json({ error: "Application not found" });
    return;
  }
  const { roles, ...rest } = client;
  res.json({
    ...rest,
    roles: roles.map((r) => ({
      id: r.id,
      key: r.key,
      name: r.name,
      description: r.description,
      assignmentCount: r._count.assignments,
      permissions: r.permissions.map((p) => p.permission.key).sort(),
    })),
  });
});

applicationsRouter.patch("/:id", ...write, governanceTrust("app:update"), async (req, res) => {
  const stepUp = await enforceGovernanceStepUp(req, res, "app-governance", "app:update");
  if (!stepUp) return;
  const parsed = updateSchema.safeParse(req.body);
  if (!parsed.success) return badRequest(res, parsed.error.issues);
  const client = await findClient(req.params.id);
  if (!client) {
    res.status(404).json({ error: "Application not found" });
    return;
  }
  const changes = parsed.data;
  const redirectUris = changes.redirectUris ?? client.redirectUris;
  if (client.type === "CONFIDENTIAL" && redirectUris.length === 0) {
    res.status(400).json({ error: "At least one redirect URI is required" });
    return;
  }
  const before = { name: client.name, status: client.status, redirectUris: client.redirectUris, allowedScopes: client.allowedScopes, requireAssignment: client.requireAssignment };
  const updated = await auditedTransaction(async (tx) => {
    await recordStepUpCounter(tx, stepUp);
    const row = await tx.oAuthClient.update({ where: { id: client.id }, data: changes, select: clientPublicSelect });
    // Disabling an application, or tightening what it may do, ends what it holds now.
    if (changes.status && changes.status !== "ACTIVE") {
      await tx.oAuthGrant.updateMany({ where: { clientId: client.id, revokedAt: null }, data: { revokedAt: new Date(), revokedReason: "application_disabled" } });
    }
    await appendAuditLog(tx, {
      entityType: "OAuthClient",
      entityId: client.id,
      event: changes.status && changes.status !== client.status ? "APPLICATION_STATUS_CHANGED" : "APPLICATION_UPDATED",
      actorId: req.user!.id,
      metadata: { clientId: client.clientId, before, changed: Object.keys(changes), stepUpCredentialId: stepUp.credentialId },
    });
    return row;
  });
  res.json(updated);
});

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

const secretSchema = z.object({ label: z.string().trim().max(60).optional(), expiresInDays: z.number().int().min(1).max(730).optional() });

applicationsRouter.post("/:id/secrets", ...write, governanceTrust("app:secret"), async (req, res) => {
  const stepUp = await enforceGovernanceStepUp(req, res, "app-governance", "app:secret:issue");
  if (!stepUp) return;
  const parsed = secretSchema.safeParse(req.body ?? {});
  if (!parsed.success) return badRequest(res, parsed.error.issues);
  const client = await findClient(req.params.id);
  if (!client) {
    res.status(404).json({ error: "Application not found" });
    return;
  }
  if (client.type !== "CONFIDENTIAL") {
    res.status(400).json({ error: "Public applications do not have a client secret" });
    return;
  }
  const generated = generateClientSecret();
  const expiresAt = parsed.data.expiresInDays ? new Date(Date.now() + parsed.data.expiresInDays * 86_400_000) : null;
  const row = await auditedTransaction(async (tx) => {
    await recordStepUpCounter(tx, stepUp);
    const created = await tx.oAuthClientSecret.create({
      data: { clientId: client.id, secretHash: generated.hash, label: parsed.data.label, expiresAt },
    });
    await appendAuditLog(tx, {
      entityType: "OAuthClient",
      entityId: client.id,
      event: "APPLICATION_SECRET_ISSUED",
      actorId: req.user!.id,
      metadata: { clientId: client.clientId, secretId: created.id, expiresAt, stepUpCredentialId: stepUp.credentialId },
    });
    return created;
  });
  res.status(201).json({ id: row.id, secret: generated.secret, expiresAt });
});

applicationsRouter.delete("/:id/secrets/:secretId", ...write, governanceTrust("app:secret"), async (req, res) => {
  const stepUp = await enforceGovernanceStepUp(req, res, "app-governance", "app:secret:revoke");
  if (!stepUp) return;
  const client = await findClient(req.params.id);
  if (!client) {
    res.status(404).json({ error: "Application not found" });
    return;
  }
  const revoked = await auditedTransaction(async (tx) => {
    await recordStepUpCounter(tx, stepUp);
    const result = await tx.oAuthClientSecret.updateMany({ where: { id: req.params.secretId, clientId: client.id, revokedAt: null }, data: { revokedAt: new Date() } });
    if (result.count === 1) {
      await appendAuditLog(tx, {
        entityType: "OAuthClient",
        entityId: client.id,
        event: "APPLICATION_SECRET_REVOKED",
        actorId: req.user!.id,
        metadata: { clientId: client.clientId, secretId: req.params.secretId, stepUpCredentialId: stepUp.credentialId },
      });
    }
    return result.count === 1;
  });
  if (!revoked) {
    res.status(404).json({ error: "Active secret not found" });
    return;
  }
  res.json({ revoked: true });
});

// ---------------------------------------------------------------------------
// Permissions and roles (definitions)
// ---------------------------------------------------------------------------

applicationsRouter.post("/:id/permissions", ...write, governanceTrust("app:permission"), async (req, res) => {
  const parsed = permissionDef.safeParse(req.body);
  if (!parsed.success) return badRequest(res, parsed.error.issues);
  const client = await findClient(req.params.id);
  if (!client) {
    res.status(404).json({ error: "Application not found" });
    return;
  }
  try {
    const created = await auditedTransaction(async (tx) => {
      const row = await tx.appPermission.create({ data: { clientId: client.id, key: parsed.data.key, description: parsed.data.description } });
      await appendAuditLog(tx, {
        entityType: "OAuthClient",
        entityId: client.id,
        event: "APP_PERMISSION_CREATED",
        actorId: req.user!.id,
        metadata: { clientId: client.clientId, permission: row.key },
      });
      return row;
    });
    res.status(201).json(created);
  } catch (err) {
    if (!handleRouteError(err, res)) throw err;
  }
});

applicationsRouter.delete("/:id/permissions/:permissionId", ...write, governanceTrust("app:permission"), async (req, res) => {
  const client = await findClient(req.params.id);
  if (!client) {
    res.status(404).json({ error: "Application not found" });
    return;
  }
  try {
    await auditedTransaction(async (tx) => {
      const row = await tx.appPermission.findFirst({ where: { id: req.params.permissionId, clientId: client.id } });
      if (!row) throw new RouteError(404, "Permission not found");
      await tx.appPermission.delete({ where: { id: row.id } });
      await appendAuditLog(tx, {
        entityType: "OAuthClient",
        entityId: client.id,
        event: "APP_PERMISSION_DELETED",
        actorId: req.user!.id,
        metadata: { clientId: client.clientId, permission: row.key },
      });
    });
    res.json({ deleted: true });
  } catch (err) {
    if (!handleRouteError(err, res)) throw err;
  }
});

async function resolvePermissionIds(tx: Prisma.TransactionClient, clientDbId: string, keys: string[]): Promise<string[]> {
  const unique = [...new Set(keys)];
  const rows = await tx.appPermission.findMany({ where: { clientId: clientDbId, key: { in: unique } } });
  if (rows.length !== unique.length) throw new RouteError(400, "One or more permissions are not defined for this application");
  return rows.map((r) => r.id);
}

applicationsRouter.post("/:id/roles", ...write, governanceTrust("app:role"), async (req, res) => {
  const parsed = roleDef.safeParse(req.body);
  if (!parsed.success) return badRequest(res, parsed.error.issues);
  const client = await findClient(req.params.id);
  if (!client) {
    res.status(404).json({ error: "Application not found" });
    return;
  }
  try {
    const created = await auditedTransaction(async (tx) => {
      const permissionIds = await resolvePermissionIds(tx, client.id, parsed.data.permissions);
      const role = await tx.appRole.create({ data: { clientId: client.id, key: parsed.data.key, name: parsed.data.name, description: parsed.data.description } });
      if (permissionIds.length) await tx.appRolePermission.createMany({ data: permissionIds.map((permissionId) => ({ roleId: role.id, permissionId })) });
      await appendAuditLog(tx, {
        entityType: "OAuthClient",
        entityId: client.id,
        event: "APP_ROLE_CREATED",
        actorId: req.user!.id,
        metadata: { clientId: client.clientId, role: role.key, permissions: parsed.data.permissions },
      });
      return role;
    });
    res.status(201).json(created);
  } catch (err) {
    if (!handleRouteError(err, res)) throw err;
  }
});

const roleUpdateSchema = z.object({
  name: z.string().trim().min(1).max(100).optional(),
  description: z.string().trim().max(300).nullable().optional(),
  permissions: z.array(permissionKey).max(200).optional(),
});

applicationsRouter.put("/:id/roles/:roleId", ...write, governanceTrust("app:role"), async (req, res) => {
  const parsed = roleUpdateSchema.safeParse(req.body);
  if (!parsed.success) return badRequest(res, parsed.error.issues);
  const client = await findClient(req.params.id);
  if (!client) {
    res.status(404).json({ error: "Application not found" });
    return;
  }
  try {
    const updated = await auditedTransaction(async (tx) => {
      const role = await tx.appRole.findFirst({ where: { id: req.params.roleId, clientId: client.id }, include: { permissions: { include: { permission: true } } } });
      if (!role) throw new RouteError(404, "Role not found");
      const before = role.permissions.map((p) => p.permission.key).sort();
      if (parsed.data.name !== undefined || parsed.data.description !== undefined) {
        await tx.appRole.update({ where: { id: role.id }, data: { name: parsed.data.name, description: parsed.data.description } });
      }
      let after = before;
      if (parsed.data.permissions) {
        const ids = await resolvePermissionIds(tx, client.id, parsed.data.permissions);
        await tx.appRolePermission.deleteMany({ where: { roleId: role.id } });
        if (ids.length) await tx.appRolePermission.createMany({ data: ids.map((permissionId) => ({ roleId: role.id, permissionId })) });
        after = [...new Set(parsed.data.permissions)].sort();
      }
      await appendAuditLog(tx, {
        entityType: "OAuthClient",
        entityId: client.id,
        event: "APP_ROLE_UPDATED",
        actorId: req.user!.id,
        metadata: { clientId: client.clientId, role: role.key, permissionsBefore: before, permissionsAfter: after },
      });
      return tx.appRole.findUniqueOrThrow({ where: { id: role.id } });
    });
    res.json(updated);
  } catch (err) {
    if (!handleRouteError(err, res)) throw err;
  }
});

applicationsRouter.delete("/:id/roles/:roleId", ...write, governanceTrust("app:role"), async (req, res) => {
  const client = await findClient(req.params.id);
  if (!client) {
    res.status(404).json({ error: "Application not found" });
    return;
  }
  try {
    await auditedTransaction(async (tx) => {
      const role = await tx.appRole.findFirst({ where: { id: req.params.roleId, clientId: client.id }, include: { _count: { select: { assignments: true } } } });
      if (!role) throw new RouteError(404, "Role not found");
      if (role._count.assignments > 0) throw new RouteError(409, "Revoke this role's assignments before deleting it");
      await tx.appRole.delete({ where: { id: role.id } });
      await appendAuditLog(tx, {
        entityType: "OAuthClient",
        entityId: client.id,
        event: "APP_ROLE_DELETED",
        actorId: req.user!.id,
        metadata: { clientId: client.clientId, role: role.key },
      });
    });
    res.json({ deleted: true });
  } catch (err) {
    if (!handleRouteError(err, res)) throw err;
  }
});

// ---------------------------------------------------------------------------
// Assignments (who holds which role)
// ---------------------------------------------------------------------------

applicationsRouter.get("/:id/assignments", ...read, async (req, res) => {
  const client = await findClient(req.params.id);
  if (!client) {
    res.status(404).json({ error: "Application not found" });
    return;
  }
  const { skip, take, page, pageSize } = pageParams(req);
  const search = searchTerm(req);
  const where: Prisma.AppRoleAssignmentWhereInput = {
    clientId: client.id,
    ...(search ? { user: { OR: [{ email: { contains: search, mode: "insensitive" } }, { name: { contains: search, mode: "insensitive" } }] } } : {}),
  };
  const [total, rows] = await Promise.all([
    prisma.appRoleAssignment.count({ where }),
    prisma.appRoleAssignment.findMany({
      where,
      skip,
      take,
      orderBy: { createdAt: "desc" },
      include: { user: { select: { id: true, email: true, name: true, status: true } }, role: { select: { id: true, key: true, name: true } } },
    }),
  ]);
  res.json({
    items: rows.map((r) => ({ id: r.id, user: r.user, role: r.role, resource: r.resource, expiresAt: r.expiresAt, createdAt: r.createdAt, grantedById: r.grantedById })),
    total,
    page,
    pageSize,
  });
});

const assignSchema = z.object({
  userId: z.string().uuid(),
  roleId: z.string().uuid(),
  resource: z.string().refine(isValidResourcePattern, "Use '*', an exact path like 'a/b', or a prefix like 'a/*'").default("*"),
  expiresAt: z
    .string()
    .datetime()
    .refine((v) => new Date(v).getTime() > Date.now(), "expiresAt must be in the future")
    .optional(),
});

applicationsRouter.post("/:id/assignments", ...write, governanceTrust("app:assign"), async (req, res) => {
  const stepUp = await enforceGovernanceStepUp(req, res, "app-governance", "app:assign");
  if (!stepUp) return;
  const parsed = assignSchema.safeParse(req.body);
  if (!parsed.success) return badRequest(res, parsed.error.issues);
  const client = await findClient(req.params.id);
  if (!client) {
    res.status(404).json({ error: "Application not found" });
    return;
  }
  if (parsed.data.userId === req.user!.id) {
    res.status(403).json({ error: "You cannot assign application roles to yourself" });
    return;
  }
  try {
    const created = await auditedTransaction(async (tx) => {
      await recordStepUpCounter(tx, stepUp);
      const [role, target] = await Promise.all([
        tx.appRole.findFirst({ where: { id: parsed.data.roleId, clientId: client.id } }),
        tx.user.findUnique({ where: { id: parsed.data.userId } }),
      ]);
      if (!role) throw new RouteError(404, "Role not found in this application");
      if (!target || target.status !== "ACTIVE") throw new RouteError(404, "Active user not found");
      const row = await tx.appRoleAssignment.create({
        data: {
          clientId: client.id,
          roleId: role.id,
          userId: target.id,
          resource: parsed.data.resource,
          expiresAt: parsed.data.expiresAt ? new Date(parsed.data.expiresAt) : null,
          grantedById: req.user!.id,
        },
      });
      await appendAuditLog(tx, {
        entityType: "OAuthClient",
        entityId: client.id,
        event: "APP_ROLE_ASSIGNED",
        actorId: req.user!.id,
        metadata: { clientId: client.clientId, role: role.key, userId: target.id, resource: row.resource, expiresAt: row.expiresAt, stepUpCredentialId: stepUp.credentialId },
      });
      return row;
    });
    res.status(201).json(created);
  } catch (err) {
    if (!handleRouteError(err, res)) throw err;
  }
});

applicationsRouter.delete("/:id/assignments/:assignmentId", ...write, governanceTrust("app:assign"), async (req, res) => {
  const stepUp = await enforceGovernanceStepUp(req, res, "app-governance", "app:unassign");
  if (!stepUp) return;
  const client = await findClient(req.params.id);
  if (!client) {
    res.status(404).json({ error: "Application not found" });
    return;
  }
  try {
    await auditedTransaction(async (tx) => {
      await recordStepUpCounter(tx, stepUp);
      const row = await tx.appRoleAssignment.findFirst({ where: { id: req.params.assignmentId, clientId: client.id }, include: { role: true } });
      if (!row) throw new RouteError(404, "Assignment not found");
      await tx.appRoleAssignment.delete({ where: { id: row.id } });
      await appendAuditLog(tx, {
        entityType: "OAuthClient",
        entityId: client.id,
        event: "APP_ROLE_REVOKED",
        actorId: req.user!.id,
        metadata: { clientId: client.clientId, role: row.role.key, userId: row.userId, resource: row.resource, stepUpCredentialId: stepUp.credentialId },
      });
    });
    res.json({ revoked: true });
  } catch (err) {
    if (!handleRouteError(err, res)) throw err;
  }
});

// ---------------------------------------------------------------------------
// Live grants (an application's authorised sessions)
// ---------------------------------------------------------------------------

applicationsRouter.get("/:id/grants", ...read, async (req, res) => {
  const client = await findClient(req.params.id);
  if (!client) {
    res.status(404).json({ error: "Application not found" });
    return;
  }
  const { skip, take, page, pageSize } = pageParams(req);
  const where: Prisma.OAuthGrantWhereInput = { clientId: client.id, revokedAt: null };
  const [total, rows] = await Promise.all([
    prisma.oAuthGrant.count({ where }),
    prisma.oAuthGrant.findMany({
      where,
      skip,
      take,
      orderBy: { createdAt: "desc" },
      include: { user: { select: { id: true, email: true, name: true } } },
    }),
  ]);
  res.json({
    items: rows.map((g) => ({ id: g.id, user: g.user, scope: g.scope, createdAt: g.createdAt, lastUsedAt: g.lastUsedAt })),
    total,
    page,
    pageSize,
  });
});

applicationsRouter.delete("/:id/grants/:grantId", ...write, governanceTrust("app:grant"), async (req, res) => {
  const client = await findClient(req.params.id);
  if (!client) {
    res.status(404).json({ error: "Application not found" });
    return;
  }
  const revoked = await auditedTransaction(async (tx) => {
    const grant = await tx.oAuthGrant.findFirst({ where: { id: req.params.grantId, clientId: client.id } });
    if (!grant) return false;
    const done = await revokeGrant(tx, grant.id, "revoked_by_admin");
    if (done) {
      await appendAuditLog(tx, {
        entityType: "OAuthClient",
        entityId: client.id,
        event: "OAUTH_GRANT_REVOKED",
        actorId: req.user!.id,
        metadata: { clientId: client.clientId, grantId: grant.id, userId: grant.userId, by: "admin" },
      });
    }
    return done;
  });
  if (!revoked) {
    res.status(404).json({ error: "Active grant not found" });
    return;
  }
  res.json({ revoked: true });
});
