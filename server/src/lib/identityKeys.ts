import { createPrivateKey, createPublicKey, generateKeyPairSync, randomUUID, type JsonWebKey, type KeyObject } from "node:crypto";

// Asymmetric key ring for identity assertions issued to downstream services.
//
// Why a separate key family from session tokens: browser session tokens stay
// HS256 with secrets only NovaForge holds (server/src/lib/jwt.ts), because
// sessions are validated against the database on every request and never
// leave NovaForge. Downstream services instead receive ES256 assertions and
// verify them with the PUBLIC keys published at /.well-known/jwks.json --
// holding a public key lets a service verify NovaForge identities but never
// mint one.
//
// Configuration (lazy -- nothing here is required at boot):
//   IDENTITY_SIGNING_PRIVATE_KEY    PKCS#8 PEM of a P-256 private key
//                                   (literal "\n" sequences are accepted)
//   IDENTITY_SIGNING_KEY_ID         kid for that key
//   IDENTITY_PREVIOUS_PUBLIC_KEYS   optional JSON array of public JWKs (each
//                                   with "kid") still accepted during rotation
// Outside production, if no key is configured, an ephemeral key is generated
// per process (assertions then stop verifying after a restart). In
// production an unconfigured key ring refuses to issue assertions.

export interface SigningKey {
  kid: string;
  privateKey: KeyObject;
  publicKey: KeyObject;
}

export interface VerificationKey {
  kid: string;
  publicKey: KeyObject;
}

export interface IdentityKeyRing {
  current: SigningKey;
  previous: VerificationKey[];
}

export class IdentityKeysUnavailableError extends Error {}

let configuredRing: IdentityKeyRing | null = null;

function assertP256(key: KeyObject, what: string): void {
  if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
    throw new Error(`${what} must be an EC P-256 key (ES256)`);
  }
}

export function signingKeyFromPrivateKey(privateKey: KeyObject, kid: string): SigningKey {
  assertP256(privateKey, "Identity signing key");
  return { kid, privateKey, publicKey: createPublicKey(privateKey) };
}

export function generateSigningKey(kid: string = `nf-${randomUUID()}`): SigningKey {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return signingKeyFromPrivateKey(privateKey, kid);
}

/** Explicitly installs a key ring (used for rotation and by tests). */
export function configureIdentityKeyRing(ring: IdentityKeyRing | null): void {
  if (ring) {
    assertP256(ring.current.privateKey, "Identity signing key");
    for (const k of ring.previous) assertP256(k.publicKey, `Verification key ${k.kid}`);
  }
  configuredRing = ring;
}

function loadFromEnvironment(): IdentityKeyRing | null {
  const pem = process.env.IDENTITY_SIGNING_PRIVATE_KEY;
  if (!pem) return null;
  const kid = process.env.IDENTITY_SIGNING_KEY_ID;
  if (!kid) throw new IdentityKeysUnavailableError("IDENTITY_SIGNING_KEY_ID is required with IDENTITY_SIGNING_PRIVATE_KEY");
  const current = signingKeyFromPrivateKey(createPrivateKey(pem.replace(/\\n/g, "\n")), kid);
  const previous: VerificationKey[] = [];
  const previousRaw = process.env.IDENTITY_PREVIOUS_PUBLIC_KEYS;
  if (previousRaw) {
    const parsed = JSON.parse(previousRaw) as (JsonWebKey & { kid?: string })[];
    for (const jwk of parsed) {
      if (!jwk.kid) throw new IdentityKeysUnavailableError("Every IDENTITY_PREVIOUS_PUBLIC_KEYS entry needs a kid");
      const publicKey = createPublicKey({ key: jwk, format: "jwk" });
      assertP256(publicKey, `Verification key ${jwk.kid}`);
      previous.push({ kid: jwk.kid, publicKey });
    }
  }
  return { current, previous };
}

export function getIdentityKeyRing(): IdentityKeyRing {
  if (configuredRing) return configuredRing;
  const fromEnv = loadFromEnvironment();
  if (fromEnv) {
    configuredRing = fromEnv;
    return fromEnv;
  }
  if (process.env.NODE_ENV === "production") {
    throw new IdentityKeysUnavailableError("Identity assertion signing key is not configured");
  }
  console.warn("[identity] No IDENTITY_SIGNING_PRIVATE_KEY configured; using an ephemeral development key");
  configuredRing = { current: generateSigningKey(`dev-ephemeral-${randomUUID()}`), previous: [] };
  return configuredRing;
}

export function toPublicJwk(key: VerificationKey | SigningKey): JsonWebKey & { kid: string; alg: string; use: string } {
  const jwk = key.publicKey.export({ format: "jwk" });
  return { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, kid: key.kid, alg: "ES256", use: "sig" };
}

/** Public JWKS: the current key plus any still-accepted previous keys. */
export function getPublicJwks(): { keys: ReturnType<typeof toPublicJwk>[] } {
  const ring = getIdentityKeyRing();
  return { keys: [toPublicJwk(ring.current), ...ring.previous.map(toPublicJwk)] };
}
