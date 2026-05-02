# @prefig/upact-oidc

A generic OIDC adapter for the [upact](https://github.com/prefig/upact) identity port. One adapter, any compliant IDP — Dex, Authentik, Keycloak, ZITADEL, Google, or any IDP that supports OpenID Connect Discovery.

## Install

```sh
npm install @prefig/upact-oidc @prefig/upact openid-client
```

## Usage

```ts
import { createOidcAdapter } from '@prefig/upact-oidc';

// Initialise once per request (SvelteKit example)
const adapter = createOidcAdapter(
  {
    issuer: 'https://accounts.example.com',
    clientId: process.env.OIDC_CLIENT_ID,
    clientSecret: process.env.OIDC_CLIENT_SECRET,
    redirectUri: 'https://app.example.com/auth/callback',
    cookieKey: process.env.COOKIE_KEY, // 64 hex chars (32 bytes)
  },
  event.cookies, // SvelteKit Cookies, or any CookieJar implementation
);
```

### Init phase (authorization redirect)

```ts
// In your /auth/login route handler:
const url = await adapter.buildAuthRedirect();
throw redirect(302, url.toString());
```

### Callback phase

```ts
// In your /auth/callback route handler:
const result = await adapter.authenticate({
  kind: 'oidc-callback',
  request: event.request,
});
if ('code' in result) {
  // AuthError — redirect to error page
  throw redirect(302, `/login?error=${result.code}`);
}
// result is a Session — store or use as needed
```

### Reading the current identity

```ts
const upactor = await adapter.currentUpactor(event.request);
if (!upactor) {
  throw redirect(302, '/login');
}
// upactor.id — deterministic, privacy-preserving identifier
// upactor.lifecycle.expires_at — token expiry
// upactor.provenance.instance — issuer URL
```

### Logout

```ts
const url = await adapter.buildLogoutRedirect('https://app.example.com/');
throw redirect(302, url.toString());
```

## Scope policy

`email`, `phone`, `address`, and `groups` are forbidden — requesting them violates upact §7 privacy minima and throws immediately at adapter construction. Default scopes: `openid`, `offline_access`. Add `profile` to receive a `display_hint` (`preferred_username` or `name`, email-shaped values rejected).

```ts
createOidcAdapter({ ..., scopes: ['openid', 'offline_access', 'profile'] }, cookies);
```

### Capability consequences

Because the `email`, `phone`, and `address` scopes are forbidden, this adapter cannot declare the corresponding upact capabilities. `capabilities.has('email')` always returns `false` against this adapter, even when the upstream IDP knows the user's email — the adapter has no way to learn it. Applications that need email-bound features (transactional email, recovery flows) require a different substrate.

The `groups` scope is forbidden separately, to prevent applications from deriving authorization roles from the substrate. Per upact §3.1, authorization is out of scope for the port; use an application-layer authorization model instead of substrate group claims.

## Configuration

| Field | Required | Description |
|---|---|---|
| `issuer` | yes | OIDC issuer URL (discovery endpoint root) |
| `clientId` | yes | OAuth2 client ID |
| `clientSecret` | yes | OAuth2 client secret |
| `redirectUri` | yes | Callback URI — must match IDP registration |
| `cookieKey` | yes | 64-char hex (32 bytes) for HMAC-SHA256 cookie signing |
| `scopes` | no | Default: `['openid', 'offline_access']` |
| `sessionCookieName` | no | Default: `'__upact_oidc'` |
| `stateCookieName` | no | Default: `'__upact_oidc_state'` |
| `allowInsecureRequests` | no | Allow HTTP issuers — **local development only** |

Generate a cookie key:

```sh
node -e "console.log(Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('hex'))"
```

## Identifier derivation

`Upactor.id` is the first 32 hex characters of `SHA-256("${sub}@${iss}")` — deterministic per identity, not reversible from the id alone, and stable across token refreshes.

## Conformance

See [CONFORMANCE.md](./CONFORMANCE.md) for the full conformance statement against upact v0.1.1.

## Local development rig

A Dex IDP is provided at `../upact-oidc-poc/` for integration testing:

```sh
docker compose -f ../upact-oidc-poc/docker-compose.yml up -d
npm run test:integration
```

## Status

v0.1.0. Breaking changes between v0.x revisions are permitted; v1.0 marks the first stable version.

## Licence

Apache-2.0.
