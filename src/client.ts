// SPDX-License-Identifier: Apache-2.0
/**
 * OidcClient interface + default openid-client v6 backed implementation.
 *
 * The interface is separated from the adapter so unit tests can swap in a
 * mock without touching openid-client internals.
 */

import * as oidc from 'openid-client';
import type { IDTokenClaims, OidcConfig } from './types.js';

export interface TokenSet {
	accessToken: string;
	refreshToken?: string;
	idToken: string;
	expiresAt: number; // unix seconds
	claims: IDTokenClaims;
}

export interface AuthorizationParams {
	state: string;
	codeChallenge: string;
	nonce: string;
	prompt?: 'login' | 'consent' | 'none';
}

/** Minimal interface wrapping openid-client operations needed by the adapter. */
export interface OidcClient {
	/** Returns the discovered configuration (triggers discovery if not cached). */
	getConfig(): Promise<oidc.Configuration>;
	/** Builds the authorization URL for the redirect. */
	buildAuthorizationUrl(params: AuthorizationParams, scopes: string[]): Promise<URL>;
	/** Exchanges an authorization code for tokens and validates the ID token. */
	exchangeCode(request: Request, expectedState: string, codeVerifier: string, expectedNonce: string): Promise<TokenSet>;
	/** Refreshes an access token using a refresh token. */
	refreshToken(refreshToken: string, expectedSub: string): Promise<TokenSet>;
	/** Builds the end-session URL for IDP-side logout. */
	buildEndSessionUrl(idTokenHint: string, postLogoutRedirectUri?: string): Promise<URL>;
	/** Generates a cryptographically random state string. */
	randomState(): string;
	/** Generates a PKCE code verifier. */
	randomCodeVerifier(): string;
	/** Calculates the PKCE S256 code challenge from a verifier. */
	calculateCodeChallenge(verifier: string): Promise<string>;
	/** Generates a random nonce. */
	randomNonce(): string;
}

/** Discovery cache: caches server metadata by issuer URL, refreshed after 1 hour. */
const discoveryCache = new Map<string, { metadata: ReturnType<oidc.Configuration['serverMetadata']>; fetchedAt: number }>();
const DISCOVERY_TTL_MS = 60 * 60 * 1000;

async function discoverServerMetadata(
	issuer: string,
	allowInsecure: boolean,
): Promise<ReturnType<oidc.Configuration['serverMetadata']>> {
	const now = Date.now();
	const cached = discoveryCache.get(issuer);
	if (cached && now - cached.fetchedAt < DISCOVERY_TTL_MS) {
		return cached.metadata;
	}
	const options = allowInsecure ? { execute: [oidc.allowInsecureRequests] } : undefined;
	const probeConfig = await oidc.discovery(new URL(issuer), 'upact-oidc-probe', undefined, undefined, options);
	const metadata = probeConfig.serverMetadata();
	discoveryCache.set(issuer, { metadata, fetchedAt: now });
	return metadata;
}

/**
 * Default OidcClient backed by openid-client v6.
 *
 * The config object captures clientId, clientSecret, and redirectUri in
 * closure. No substrate credentials appear on the returned interface.
 */
export function createOidcClientBacked(oidcConfig: OidcConfig): OidcClient {
	const { issuer, clientId, clientSecret, redirectUri, allowInsecureRequests: allowInsecure = false } = oidcConfig;

	async function getConfig(): Promise<oidc.Configuration> {
		const serverMeta = await discoverServerMetadata(issuer, allowInsecure);
		const config = new oidc.Configuration(serverMeta, clientId, { client_secret: clientSecret });
		if (allowInsecure) oidc.allowInsecureRequests(config);
		return config;
	}

	return {
		getConfig,

		async buildAuthorizationUrl(params: AuthorizationParams, scopes: string[]): Promise<URL> {
			const config = await getConfig();
			return oidc.buildAuthorizationUrl(config, {
				redirect_uri: redirectUri,
				scope: scopes.join(' '),
				state: params.state,
				code_challenge: params.codeChallenge,
				code_challenge_method: 'S256',
				nonce: params.nonce,
				...(params.prompt ? { prompt: params.prompt } : {}),
			});
		},

		async exchangeCode(
			request: Request,
			expectedState: string,
			codeVerifier: string,
			expectedNonce: string,
		): Promise<TokenSet> {
			const config = await getConfig();
			const tokenSet = await oidc.authorizationCodeGrant(config, request, {
				pkceCodeVerifier: codeVerifier,
				expectedState,
				expectedNonce,
				idTokenExpected: true,
			});
			const claims = tokenSet.claims() as IDTokenClaims;
			return {
				accessToken: tokenSet.access_token!,
				refreshToken: tokenSet.refresh_token,
				idToken: tokenSet.id_token!,
				expiresAt: claims.exp,
				claims,
			};
		},

		async refreshToken(refreshTokenValue: string, expectedSub: string): Promise<TokenSet> {
			const config = await getConfig();
			const tokenSet = await oidc.refreshTokenGrant(config, refreshTokenValue);
			const claims = tokenSet.claims() as IDTokenClaims;
			if (claims.sub !== expectedSub) {
				throw new Error(`Sub mismatch on refresh: expected ${expectedSub}, got ${claims.sub}`);
			}
			return {
				accessToken: tokenSet.access_token!,
				refreshToken: tokenSet.refresh_token ?? refreshTokenValue,
				idToken: tokenSet.id_token!,
				expiresAt: claims.exp,
				claims,
			};
		},

		async buildEndSessionUrl(idTokenHint: string, postLogoutRedirectUri?: string): Promise<URL> {
			const config = await getConfig();
			return oidc.buildEndSessionUrl(config, {
				id_token_hint: idTokenHint,
				...(postLogoutRedirectUri ? { post_logout_redirect_uri: postLogoutRedirectUri } : {}),
			});
		},

		randomState(): string {
			return oidc.randomState();
		},

		randomCodeVerifier(): string {
			return oidc.randomPKCECodeVerifier();
		},

		async calculateCodeChallenge(verifier: string): Promise<string> {
			return oidc.calculatePKCECodeChallenge(verifier);
		},

		randomNonce(): string {
			return oidc.randomNonce();
		},
	};
}
