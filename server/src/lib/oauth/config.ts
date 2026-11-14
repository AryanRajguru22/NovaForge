import { identityIssuer } from "../identityAssertion.js";

// One issuer string is used everywhere: the `iss` of every token, the
// discovery document's `issuer`, and the prefix of every advertised endpoint.
// Relying parties pin it byte-for-byte. All endpoints live under /api so the
// same URLs work behind nginx (which strips /api), in the combined single-
// origin image (which serves only /api) and in local development.

export const SUPPORTED_SCOPES = ["openid", "profile", "email", "roles", "offline_access"] as const;
export type SupportedScope = (typeof SUPPORTED_SCOPES)[number];
export const DEFAULT_CLIENT_SCOPES: SupportedScope[] = ["openid", "profile", "email", "roles", "offline_access"];

export const AUTH_CODE_TTL_SEC = 60;
export const ID_TOKEN_TTL_SEC = 300;
export const ACCESS_TOKEN_TYP = "at+jwt";
export const ID_TOKEN_TYP = "JWT";
export const ACCESS_TOKEN_USE = "access_token";
export const ID_TOKEN_USE = "id_token";

export function issuer(): string {
  return identityIssuer().replace(/\/+$/, "");
}

export function oauthBase(): string {
  return `${issuer()}/api/oauth`;
}

export function endpoints() {
  const base = oauthBase();
  return {
    issuer: issuer(),
    authorization_endpoint: `${base}/authorize`,
    token_endpoint: `${base}/token`,
    userinfo_endpoint: `${base}/userinfo`,
    introspection_endpoint: `${base}/introspect`,
    revocation_endpoint: `${base}/revoke`,
    end_session_endpoint: `${base}/logout`,
    jwks_uri: `${issuer()}/.well-known/jwks.json`,
    authorization_check_endpoint: `${issuer()}/api/v1/authz/check`,
  };
}

export function discoveryDocument() {
  return {
    ...endpoints(),
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["ES256"],
    scopes_supported: [...SUPPORTED_SCOPES],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
    introspection_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
    revocation_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
    code_challenge_methods_supported: ["S256"],
    claims_supported: ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "sid", "name", "email", "roles", "permissions"],
    authorization_response_iss_parameter_supported: true,
    claims_parameter_supported: false,
    request_parameter_supported: false,
    request_uri_parameter_supported: false,
  };
}
