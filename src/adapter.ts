// SPDX-License-Identifier: Apache-2.0
/**
 * createOidcAdapter — generic OIDC client adapter for upact.
 *
 * Factory-only. Per-request: accepts a cookie jar (e.g. SvelteKit
 * event.cookies) that is bound to the current request/response cycle.
 * Substrate state (tokens) is held in the cookie jar (HMAC-signed session
 * cookie), not on the returned object. Decision 11 / SPEC.md §7.5.
 *
 * Out-of-port extensions (buildAuthRedirect, buildLogoutRedirect) are
 * typed as OidcAdapterExtensions. Consumers that only depend on the port
 * interface remain substrate-agnostic; consumers that need the OIDC-specific
 * redirect helpers cast to OidcAdapterExtensions locally.
 */

import type { AuthError, IdentityPort, Session, Upactor } from '@prefig/upact';
import { createSession, SubstrateUnavailableError } from '@prefig/upact';
import { createOidcClientBacked } from './client.js';
import type { OidcClient } from './client.js';
import { mapClaimsToUpactor } from './claims-mapper.js';
import { DEFAULT_SCOPES, validateScopes } from './scope-policy.js';
import { signState, unsignState } from './state-cookies.js';
import { signSession, unsignSession, sessionCookieOptions } from './session-cookies.js';
import type { CookieJar, OidcConfig, OidcCredential, OidcSessionData } from './types.js';

/** Out-of-port methods specific to the OIDC adapter. */
export interface OidcAdapterExtensions {
	/**
	 * Builds the authorization URL for the IDP redirect (init phase).
	 * Sets the state cookie. The consumer redirects to this URL.
	 */
	buildAuthRedirect(options?: { returnTo?: string; prompt?: 'login' | 'consent' | 'none' }): Promise<URL>;
	/**
	 * Builds the IDP end-session URL (logout redirect).
	 * Clears the session cookie. The consumer redirects to this URL.
	 */
	buildLogoutRedirect(postLogoutRedirectUri?: string): Promise<URL>;
}

/**
 * Creates an upact IdentityPort backed by any OIDC-compliant IDP.
 *
 * @param config - IDP coordinates and cookie configuration.
 * @param cookies - Per-request cookie jar (SvelteKit event.cookies or equivalent).
 * @param _client - Optional OidcClient override for testing.
 */
export function createOidcAdapter(
	config: OidcConfig,
	cookies: CookieJar,
	_client?: OidcClient,
): IdentityPort & OidcAdapterExtensions {
	const scopes = config.scopes ?? DEFAULT_SCOPES;
	validateScopes(scopes); // throws immediately on config error

	const sessionName = config.sessionCookieName ?? '__upact_oidc';
	const stateName = config.stateCookieName ?? '__upact_oidc_state';
	const client = _client ?? createOidcClientBacked(config);
	const isSecure = config.redirectUri.startsWith('https://');

	// ——— helpers ————————————————————————————————————————————————————————————

	async function readSession(): Promise<OidcSessionData | null> {
		const cookie = cookies.get(sessionName);
		if (!cookie) return null;
		return unsignSession(cookie, config.cookieKey);
	}

	async function writeSession(data: OidcSessionData): Promise<void> {
		const signed = await signSession(data, config.cookieKey);
		cookies.set(sessionName, signed, sessionCookieOptions(isSecure));
	}

	function normaliseOidcError(err: unknown): AuthError {
		const msg = err instanceof Error ? err.message.toLowerCase() : '';
		if (msg.includes('invalid_grant') || msg.includes('access_denied') || msg.includes('interaction_required')) {
			return { code: 'credential_rejected', message: 'OIDC grant rejected' };
		}
		if (msg.includes('invalid_token') || msg.includes('invalid_client') || msg.includes('invalid_request')) {
			return { code: 'credential_invalid', message: 'OIDC credential invalid' };
		}
		if (msg.includes('server_error') || msg.includes('network') || msg.includes('fetch') || msg.includes('econnrefused')) {
			return { code: 'substrate_unavailable', message: 'IDP unavailable' };
		}
		if (msg.includes('slow_down') || msg.includes('rate') || msg.includes('429')) {
			return { code: 'rate_limited', message: 'IDP rate-limited' };
		}
		if (msg.includes('not found') || msg.includes('discovery')) {
			return { code: 'identity_unavailable', message: 'IDP discovery failed' };
		}
		return { code: 'auth_failed', message: 'OIDC authentication failed' };
	}

	// ——— IdentityPort ————————————————————————————————————————————————————————

	async function authenticate(credential: unknown): Promise<Session | AuthError> {
		if (!isOidcCredential(credential)) {
			return { code: 'credential_invalid', message: 'unrecognised credential shape' };
		}

		const stateCookie = cookies.get(stateName);
		if (!stateCookie) {
			return { code: 'credential_invalid', message: 'missing OIDC state cookie — possible replay or timeout' };
		}
		const pendingState = await unsignState(stateCookie, config.cookieKey);
		// Delete immediately — single-use
		cookies.delete(stateName, { path: '/' });
		if (!pendingState) {
			return { code: 'credential_invalid', message: 'OIDC state cookie tampered or expired' };
		}

		try {
			const tokenSet = await client.exchangeCode(
				credential.request,
				pendingState.state,
				pendingState.codeVerifier,
				pendingState.nonce,
			);
			const sessionData: OidcSessionData = {
				accessToken: tokenSet.accessToken,
				refreshToken: tokenSet.refreshToken,
				idToken: tokenSet.idToken,
				expiresAt: tokenSet.expiresAt,
				sub: tokenSet.claims.sub,
				issuer: tokenSet.claims.iss,
			};
			await writeSession(sessionData);
			return createSession(sessionData);
		} catch (err) {
			return normaliseOidcError(err);
		}
	}

	async function currentUpactor(_request: Request): Promise<Upactor | null> {
		let sessionData: OidcSessionData | null;
		try {
			sessionData = await readSession();
		} catch (err) {
			throw new SubstrateUnavailableError(err instanceof Error ? err.message : 'session read failed');
		}
		if (!sessionData) return null;

		const nowSec = Math.floor(Date.now() / 1000);
		const expired = sessionData.expiresAt <= nowSec + 5; // 5s clock tolerance

		if (expired && sessionData.refreshToken) {
			try {
				const tokenSet = await client.refreshToken(sessionData.refreshToken, sessionData.sub);
				sessionData = {
					accessToken: tokenSet.accessToken,
					refreshToken: tokenSet.refreshToken,
					idToken: tokenSet.idToken,
					expiresAt: tokenSet.expiresAt,
					sub: tokenSet.claims.sub,
					issuer: tokenSet.claims.iss,
				};
				await writeSession(sessionData);
			} catch (err) {
				const msg = err instanceof Error ? err.message.toLowerCase() : '';
				if (msg.includes('invalid_grant') || msg.includes('econnrefused') || msg.includes('network')) {
					throw new SubstrateUnavailableError('IDP unreachable during transparent refresh');
				}
				// Refresh failed non-transiently — treat as logged out
				cookies.delete(sessionName, { path: '/' });
				return null;
			}
		} else if (expired) {
			// No refresh token — session expired
			cookies.delete(sessionName, { path: '/' });
			return null;
		}

		try {
			return await mapClaimsToUpactor({
				sub: sessionData.sub,
				iss: sessionData.issuer,
				aud: config.clientId,
				exp: sessionData.expiresAt,
				iat: 0,
			});
		} catch (err) {
			throw new SubstrateUnavailableError(err instanceof Error ? err.message : 'claims mapping failed');
		}
	}

	async function invalidate(_session: Session): Promise<void> {
		cookies.delete(sessionName, { path: '/' });
	}

	async function issueRenewal(identity: Upactor, _evidence: unknown): Promise<Upactor | null> {
		const sessionData = await readSession();
		if (!sessionData) return null;
		if (!sessionData.refreshToken) return null; // Decision 9: OPTIONAL

		try {
			const tokenSet = await client.refreshToken(sessionData.refreshToken, sessionData.sub);
			// Decision 3 Option A: identity-bound — sub mismatch → null
			if (tokenSet.claims.sub !== identity.id) {
				// The adapter's id is hash-derived, not the raw sub — compare via re-derivation.
				// We compare the stored sub (pre-hashing) against the session sub instead.
			}
			if (tokenSet.claims.sub !== sessionData.sub) {
				cookies.delete(sessionName, { path: '/' });
				return null;
			}
			const updated: OidcSessionData = {
				accessToken: tokenSet.accessToken,
				refreshToken: tokenSet.refreshToken,
				idToken: tokenSet.idToken,
				expiresAt: tokenSet.expiresAt,
				sub: tokenSet.claims.sub,
				issuer: tokenSet.claims.iss,
			};
			await writeSession(updated);
			return mapClaimsToUpactor(tokenSet.claims);
		} catch (err) {
			const msg = err instanceof Error ? err.message.toLowerCase() : '';
			if (msg.includes('invalid_grant')) {
				// Refresh token expired/revoked — session over
				cookies.delete(sessionName, { path: '/' });
				return null;
			}
			if (msg.includes('sub mismatch')) {
				cookies.delete(sessionName, { path: '/' });
				return null;
			}
			throw new SubstrateUnavailableError(err instanceof Error ? err.message : 'renewal failed');
		}
	}

	// ——— OidcAdapterExtensions ——————————————————————————————————————————————

	async function buildAuthRedirect(options: {
		returnTo?: string;
		prompt?: 'login' | 'consent' | 'none';
	} = {}): Promise<URL> {
		const state = client.randomState();
		const codeVerifier = client.randomCodeVerifier();
		const codeChallenge = await client.calculateCodeChallenge(codeVerifier);
		const nonce = client.randomNonce();

		const pending = { state, codeVerifier, nonce, returnTo: options.returnTo };
		const signed = await signState(pending, config.cookieKey);
		cookies.set(stateName, signed, {
			httpOnly: true,
			secure: isSecure,
			sameSite: 'Lax',
			path: '/',
			maxAge: 10 * 60,
		});

		return client.buildAuthorizationUrl(
			{ state, codeChallenge, nonce, prompt: options.prompt },
			scopes,
		);
	}

	async function buildLogoutRedirect(postLogoutRedirectUri?: string): Promise<URL> {
		const sessionData = await readSession();
		cookies.delete(sessionName, { path: '/' });
		const idTokenHint = sessionData?.idToken ?? '';
		return client.buildEndSessionUrl(idTokenHint, postLogoutRedirectUri);
	}

	return { authenticate, currentUpactor, invalidate, issueRenewal, buildAuthRedirect, buildLogoutRedirect };
}

function isOidcCredential(value: unknown): value is OidcCredential {
	if (typeof value !== 'object' || value === null) return false;
	const candidate = value as { kind?: unknown; request?: unknown };
	return candidate.kind === 'oidc-callback' && candidate.request instanceof Request;
}
