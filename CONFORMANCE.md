# Conformance: @prefig/upact-oidc

**Spec version:** upact v0.1.1
**Package version:** 0.1.0
**Date:** 2026-05-01

## Substrate

Any OIDC-compliant Identity Provider. The adapter uses OpenID Connect Discovery (`/.well-known/openid-configuration`) and authorization-code + PKCE (RFC 9700). Tested against Dex v2.41.1; compatible with Authentik, Keycloak, ZITADEL, Google, and any standard OIDC IDP.

## Threat model

Standard OIDC delegate trust. The IDP is a trusted substrate; the adapter enforces the upact privacy contract at the adapter boundary regardless of how much the IDP exposes. Suitable for medium-to-high-stakes deployments where the IDP is operated by or contractually trusted by the application. Not suitable for adversarial-IDP contexts.

## Capabilities self-declared

`[]` — always empty. OIDC IDPs vary too widely to make capability claims on their behalf. Capability assignment is left to the application layer (application-layer petnames, roles, or group claims can be mapped downstream).

## AuthError mapping table

| Substrate error | AuthErrorCode |
|---|---|
| `invalid_grant`, `access_denied`, `interaction_required` | `credential_rejected` |
| `invalid_token`, `invalid_client`, `invalid_request` | `credential_invalid` |
| `server_error`, network/fetch failure, ECONNREFUSED | `substrate_unavailable` |
| `slow_down`, rate-limit, HTTP 429 | `rate_limited` |
| Discovery failure, IDP not found | `identity_unavailable` |
| Any other error | `auth_failed` |

## Session opacity

This adapter uses `createSession` from `@prefig/upact` for Session construction. The session value serialises as `"[upact:session]"`. Substrate tokens (access token, refresh token, ID token) are stored exclusively in an HMAC-SHA256 signed session cookie (`__upact_oidc`) — they never appear on the returned `Session` object or `Upactor`.

## Adapter back-channel closure

This adapter passes a sixteen-vector reflection test at `tests/back-channel.test.ts`. The cookie jar, the OidcClient, config secrets, and all substrate tokens are held in closure scope. Sentinel values planted on the mock client and cookie jar are verified unreachable through: JSON.stringify, Object.keys, Object.getOwnPropertyNames, Reflect.ownKeys, Object.getOwnPropertySymbols, for-in, structuredClone (DataCloneError is the proof — functions are not clonable), util.inspect, direct property access by name (`client`, `cookies`, `cookieKey`, `clientSecret`, `_config`), Object spread, wrapped JSON.stringify with replacer, and Object.entries.

## Identifier derivation

`Upactor.id` is derived as the first 32 hex characters of `SHA-256("${sub}@${iss}")`. The derivation is:

- Deterministic per identity (same sub + iss always → same id)
- Not reversible from the id alone (pre-image resistance of SHA-256)
- Not derivable from email or any user-supplied identifier (`sub` and `iss` are IDP-opaque values)
- Stable across refresh token rotations (sub and iss are invariant within a session)

## display_hint

Sourced from `preferred_username` then `name` (allow-list order). Email-shaped values are rejected by pattern match (`/^[^\s@]+@[^\s@]+\.[^\s@]+$/`). If no non-email display hint is available, `display_hint` is omitted.

## Lifecycle and provenance

Every Upactor returned by this adapter carries:

- `lifecycle.expires_at`: the ID token expiry (`exp` claim) as a `Date`
- `lifecycle.renewable`: always `'reauth'` — OIDC refresh is an IDP decision, so renewal ultimately requires IDP consent
- `provenance.substrate`: `'oidc'`
- `provenance.instance`: the issuer URL (for cross-IDP discrimination in multi-IDP deployments)

## Scope policy

The `email`, `phone`, `address`, and `groups` scopes are forbidden — they violate upact §7 privacy minima. Passing a forbidden scope to `createOidcAdapter` throws immediately at construction time. Default scopes: `['openid', 'offline_access']`.

## OidcAdapterExtensions

Two out-of-port methods are exposed on the returned adapter:

- `buildAuthRedirect(options?)` — builds the authorization URL, sets the state cookie
- `buildLogoutRedirect(postLogoutRedirectUri?)` — builds the end-session URL, clears the session cookie

These are intentionally outside the `IdentityPort` interface (Decision 10): the OIDC init phase (authorization code redirect) is an IDP-specific concern, not a port primitive.

## Deviations from SHOULD clauses

None.

## issueRenewal

Normatively OPTIONAL (Decision 9, SPEC §6.4). Returns `null` when no refresh token is present. Returns `null` on `invalid_grant` (refresh token expired or revoked), clearing the session cookie. Sub mismatch on refresh → `null` + session cleared (Decision 3A identity-bound).
