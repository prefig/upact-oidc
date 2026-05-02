// SPDX-License-Identifier: Apache-2.0
/**
 * Public types for @prefig/upact-oidc.
 */

/** Options for CookieJar.set (subset of standard Set-Cookie attributes). */
export interface CookieSetOptions {
	httpOnly?: boolean;
	secure?: boolean;
	sameSite?: 'Lax' | 'Strict' | 'None';
	path?: string;
	/** Max age in seconds. */
	maxAge?: number;
}

/**
 * Minimal cookie interface satisfied by SvelteKit's `event.cookies`, a plain
 * object with get/set/delete, or a test double. Per-request: each adapter
 * instance captures its own cookie jar.
 */
export interface CookieJar {
	get(name: string): string | undefined;
	set(name: string, value: string, options?: CookieSetOptions): void;
	delete(name: string, options?: { path?: string }): void;
}

/** Configuration for createOidcAdapter. */
export interface OidcConfig {
	/** OIDC issuer URL — used for discovery ({issuer}/.well-known/openid-configuration). */
	issuer: string;
	/** OAuth2 client ID. */
	clientId: string;
	/** OAuth2 client secret. */
	clientSecret: string;
	/** OAuth2 redirect URI — must match the IDP's registered redirect URI exactly. */
	redirectUri: string;
	/**
	 * OAuth2 scopes to request. Validated at construction time; forbidden scopes
	 * (email, phone, address, groups) cause an immediate throw.
	 * Default: ['openid', 'offline_access']
	 */
	scopes?: string[];
	/**
	 * Cookie name for the OIDC session (encrypted token store).
	 * Default: '__upact_oidc'
	 */
	sessionCookieName?: string;
	/**
	 * Cookie name for the OAuth2 state (PKCE verifier + nonce, short-lived).
	 * Default: '__upact_oidc_state'
	 */
	stateCookieName?: string;
	/**
	 * Hex-encoded 32-byte key for HMAC-SHA256 cookie signing.
	 * Generate with: crypto.getRandomValues(new Uint8Array(32)) then hex-encode.
	 */
	cookieKey: string;
	/**
	 * Allow HTTP (non-TLS) issuer endpoints. Local development only.
	 * Production deployments MUST NOT set this — all OIDC traffic must be HTTPS.
	 */
	allowInsecureRequests?: boolean;
}

/**
 * Credential shape accepted by createOidcAdapter's authenticate().
 * Only the callback phase is handled at the port — the init phase
 * (building the authorization URL) is exposed via buildAuthRedirect,
 * an out-of-port method on the adapter (Decision 10 / SPEC §6 note).
 */
export type OidcCredential = { kind: 'oidc-callback'; request: Request };

/** Pending OAuth state stored in the state cookie during the redirect round-trip. */
export interface PendingState {
	state: string;
	codeVerifier: string;
	nonce: string;
	returnTo?: string;
}

/** OIDC session data stored (HMAC-signed) in the session cookie. */
export interface OidcSessionData {
	accessToken: string;
	refreshToken?: string;
	idToken: string;
	/** Unix timestamp seconds (JWT exp). */
	expiresAt: number;
	sub: string;
	issuer: string;
}

/** Subset of ID token claims the adapter reads. Allow-list — all others ignored. */
export interface IDTokenClaims {
	sub: string;
	iss: string;
	aud: string | string[];
	exp: number;
	iat: number;
	nonce?: string;
	preferred_username?: string;
	name?: string;
}
