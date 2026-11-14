import type { Prisma, PrismaClient } from "@prisma/client";
import { prisma } from "../prisma.js";

// Per-application role-based access control with default-deny.
//
// A user's access to an application is the union of the permissions of the
// roles they hold in THAT application. Nothing is inherited between
// applications, between roles, or from NovaForge's own platform role. A user
// with no live assignment has no access and no permissions.
//
// An assignment may be limited to a resource:
//   "*"        the whole application
//   "a/b"      exactly that resource
//   "a/*"      that resource and everything beneath it
// A check that names no resource is answered from "*" assignments only, so a
// resource-limited grant never leaks into a resource-less question.

type Db = PrismaClient | Prisma.TransactionClient;

export const PERMISSION_KEY = /^[a-z0-9][a-z0-9:._-]{0,99}$/;
export const ROLE_KEY = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;
const RESOURCE_PATTERN = /^(\*|[A-Za-z0-9_.:@-]+(\/[A-Za-z0-9_.:@-]+)*(\/\*)?)$/;
const RESOURCE_EXACT = /^[A-Za-z0-9_.:@-]+(\/[A-Za-z0-9_.:@-]+)*$/;
const MAX_RESOURCE_LENGTH = 200;

/** A resource limit as stored on an assignment: "*", an exact path, or "path/*". */
function hasDotSegment(value: string): boolean {
  return value.split("/").some((segment) => segment === "." || segment === "..");
}

export function isValidResourcePattern(value: string): boolean {
  return value.length <= MAX_RESOURCE_LENGTH && RESOURCE_PATTERN.test(value) && !hasDotSegment(value);
}

/** A concrete resource named in an access check (never a pattern). */
export function isValidResource(value: string): boolean {
  return value.length <= MAX_RESOURCE_LENGTH && RESOURCE_EXACT.test(value) && !hasDotSegment(value);
}

export function resourceMatches(pattern: string, resource: string | undefined): boolean {
  if (pattern === "*") return true;
  if (resource === undefined) return false;
  if (pattern.endsWith("/*")) {
    const base = pattern.slice(0, -2);
    return resource === base || resource.startsWith(`${base}/`);
  }
  return pattern === resource;
}

export interface AssignmentView {
  assignmentId: string;
  role: string;
  resource: string;
  permissions: string[];
  expiresAt: Date | null;
}

export interface AccessContext {
  assignments: AssignmentView[];
  /** Role keys held application-wide ("*" assignments). */
  roles: string[];
  /** Permissions held application-wide ("*" assignments). */
  permissions: string[];
}

/** Every live (unexpired) assignment of `userId` in the application `clientDbId`. */
export async function loadAccess(
  clientDbId: string,
  userId: string,
  db: Db = prisma,
  now: Date = new Date(),
): Promise<AccessContext> {
  const rows = await db.appRoleAssignment.findMany({
    where: { clientId: clientDbId, userId, OR: [{ expiresAt: null }, { expiresAt: { gt: now } }] },
    include: { role: { include: { permissions: { include: { permission: true } } } } },
    orderBy: { createdAt: "asc" },
  });
  const assignments: AssignmentView[] = rows.map((row) => ({
    assignmentId: row.id,
    role: row.role.key,
    resource: row.resource,
    permissions: row.role.permissions.map((p) => p.permission.key).sort(),
    expiresAt: row.expiresAt,
  }));
  const global = assignments.filter((a) => a.resource === "*");
  return {
    assignments,
    roles: [...new Set(global.map((a) => a.role))].sort(),
    permissions: [...new Set(global.flatMap((a) => a.permissions))].sort(),
  };
}

/** True when some live assignment grants `permission` for `resource`. */
export function isPermitted(access: AccessContext, permission: string, resource?: string): boolean {
  return access.assignments.some((a) => a.permissions.includes(permission) && resourceMatches(a.resource, resource));
}

/** Whether the user holds any role at all in the application (default-deny at sign-in). */
export function hasAnyAccess(access: AccessContext): boolean {
  return access.assignments.length > 0;
}
