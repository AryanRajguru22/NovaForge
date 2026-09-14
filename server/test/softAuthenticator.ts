import { createHash, createSign, generateKeyPairSync, randomBytes, type KeyObject } from "node:crypto";
import { isoBase64URL, isoCBOR } from "@simplewebauthn/server/helpers";
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from "@simplewebauthn/types";

// A software WebAuthn authenticator for tests. It produces real,
// cryptographically valid registration and authentication responses that
// the unmodified @simplewebauthn/server verifiers accept -- so tests exercise
// actual signature verification instead of a bypass flag.
//
// Key: ES256 (P-256), COSE alg -7. Signatures are DER-encoded ECDSA, which is
// what WebAuthn authenticators emit for ES256.

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_AT = 0x40;

function sha256(data: Uint8Array | string): Buffer {
  return createHash("sha256").update(data).digest();
}

export interface SoftAuthenticatorOptions {
  rpId?: string;
  origin?: string;
  userVerified?: boolean;
  credentialId?: string;
}

export class SoftAuthenticator {
  readonly credentialId: string;
  readonly rpId: string;
  readonly origin: string;
  readonly userVerified: boolean;
  private readonly privateKey: KeyObject;
  private readonly coseKey: Uint8Array;
  private counter = 0;

  constructor(opts: SoftAuthenticatorOptions = {}) {
    this.rpId = opts.rpId ?? process.env.RP_ID ?? "localhost";
    this.origin = opts.origin ?? process.env.RP_ORIGIN ?? "http://localhost:5173";
    this.userVerified = opts.userVerified ?? true;
    this.credentialId = opts.credentialId ?? isoBase64URL.fromBuffer(randomBytes(32));
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    this.privateKey = privateKey;
    const jwk = publicKey.export({ format: "jwk" });
    const x = Buffer.from(jwk.x!, "base64url");
    const y = Buffer.from(jwk.y!, "base64url");
    const cose = new Map<number, number | Uint8Array>([
      [1, 2], // kty: EC2
      [3, -7], // alg: ES256
      [-1, 1], // crv: P-256
      [-2, new Uint8Array(x)],
      [-3, new Uint8Array(y)],
    ]);
    this.coseKey = isoCBOR.encode(cose);
  }

  /** base64url COSE public key, in the exact form NovaForge stores on Credential.publicKey. */
  get publicKeyBase64url(): string {
    return isoBase64URL.fromBuffer(this.coseKey);
  }

  private flags(extra = 0): number {
    return FLAG_UP | (this.userVerified ? FLAG_UV : 0) | extra;
  }

  private counterBytes(): Buffer {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(this.counter);
    return b;
  }

  createRegistrationResponse(challenge: string): RegistrationResponseJSON {
    const credIdBytes = isoBase64URL.toBuffer(this.credentialId);
    const credIdLen = Buffer.alloc(2);
    credIdLen.writeUInt16BE(credIdBytes.length);
    const authData = Buffer.concat([
      sha256(this.rpId),
      Buffer.from([this.flags(FLAG_AT)]),
      this.counterBytes(),
      Buffer.alloc(16), // AAGUID
      credIdLen,
      Buffer.from(credIdBytes),
      Buffer.from(this.coseKey),
    ]);
    const attestationObject = isoCBOR.encode(
      new Map<string, unknown>([
        ["fmt", "none"],
        ["attStmt", new Map()],
        ["authData", new Uint8Array(authData)],
      ]) as never,
    );
    const clientDataJSON = JSON.stringify({ type: "webauthn.create", challenge, origin: this.origin, crossOrigin: false });
    return {
      id: this.credentialId,
      rawId: this.credentialId,
      type: "public-key",
      clientExtensionResults: {},
      response: {
        clientDataJSON: isoBase64URL.fromUTF8String(clientDataJSON),
        attestationObject: isoBase64URL.fromBuffer(attestationObject),
        transports: ["internal"],
      },
    };
  }

  /** Signs an assertion over `challenge` (the base64url string from the server's options). */
  createAssertion(challenge: string, overrides: { origin?: string; rpId?: string; type?: string } = {}): AuthenticationResponseJSON {
    this.counter += 1;
    const authData = Buffer.concat([sha256(overrides.rpId ?? this.rpId), Buffer.from([this.flags()]), this.counterBytes()]);
    const clientDataJSON = JSON.stringify({
      type: overrides.type ?? "webauthn.get",
      challenge,
      origin: overrides.origin ?? this.origin,
      crossOrigin: false,
    });
    const signer = createSign("SHA256");
    signer.update(Buffer.concat([authData, sha256(clientDataJSON)]));
    const signature = signer.sign(this.privateKey); // DER
    return {
      id: this.credentialId,
      rawId: this.credentialId,
      type: "public-key",
      clientExtensionResults: {},
      response: {
        clientDataJSON: isoBase64URL.fromUTF8String(clientDataJSON),
        authenticatorData: isoBase64URL.fromBuffer(authData),
        signature: isoBase64URL.fromBuffer(signature),
      },
    };
  }
}
