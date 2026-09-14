import { createHash } from "node:crypto";

// Deterministic JSON serialization following RFC 8785 (JSON Canonicalization
// Scheme): object members sorted by UTF-16 code units, no whitespace, and
// strings/numbers serialized exactly as ECMAScript JSON.stringify does (which
// is what RFC 8785 specifies for both). Anything that has no single canonical
// JSON form -- undefined, functions, symbols, bigint, NaN/Infinity, Dates or
// other non-plain objects -- is rejected rather than silently coerced, so two
// parties can never disagree about the bytes being hashed or signed.
//
// Used for every value that is hashed or signed: audit chain entries
// (server/src/lib/audit.ts) and approval decision statements / subject
// digests (server/src/lib/approvalSignature.ts).

export class CanonicalJsonError extends Error {}

export function canonicalJson(value: unknown): string {
  return serialize(value, "$");
}

function serialize(value: unknown, path: string): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "string":
      return JSON.stringify(value);
    case "number":
      if (!Number.isFinite(value)) throw new CanonicalJsonError(`${path}: non-finite number has no JSON form`);
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) {
        return `[${value.map((v, i) => serialize(v, `${path}[${i}]`)).join(",")}]`;
      }
      const proto = Object.getPrototypeOf(value);
      if (proto !== Object.prototype && proto !== null) {
        throw new CanonicalJsonError(`${path}: only plain objects can be canonicalized`);
      }
      const record = value as Record<string, unknown>;
      const members = Object.keys(record)
        .sort()
        .map((key) => {
          if (record[key] === undefined) throw new CanonicalJsonError(`${path}.${key}: undefined has no JSON form`);
          return `${JSON.stringify(key)}:${serialize(record[key], `${path}.${key}`)}`;
        });
      return `{${members.join(",")}}`;
    }
    default:
      throw new CanonicalJsonError(`${path}: ${typeof value} has no JSON form`);
  }
}

/** Round-trips a value through JSON so it contains only JSON-representable
 * data (Dates -> ISO strings, undefined members dropped). Used before
 * persisting data that will later be re-read from JSONB and re-hashed, so the
 * stored form and the hashed form are identical by construction. */
export function toJsonValue<T = unknown>(value: unknown): T {
  return value === undefined ? (null as T) : (JSON.parse(JSON.stringify(value)) as T);
}

export function sha256Hex(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}
