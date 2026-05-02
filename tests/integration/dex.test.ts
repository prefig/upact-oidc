// SPDX-License-Identifier: Apache-2.0
/**
 * Integration tests against the local Dex IDP.
 *
 * Requires Dex running at http://localhost:5556/dex:
 *   docker compose -f ../upact-oidc-poc/docker-compose.yml up -d
 *
 * Gate: DEX_AVAILABLE=1 vitest run tests/integration
 *
 * These tests use ROPC (Resource Owner Password Credentials) to obtain real
 * tokens from Dex without a browser redirect. ROPC is test-only; the real
 * adapter always uses authorization-code + PKCE. The privacy and lifecycle
 * assertions verified here are the same assertions that matter in production.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { createOidcClientBacked } from '../../src/client.js';
import { mapClaimsToUpactor } from '../../src/claims-mapper.js';
import { createOidcAdapter } from '../../src/adapter.js';
import { signSession } from '../../src/session-cookies.js';
import { makeCookieJar } from '../fixtures/mock-client.js';
import type { IDTokenClaims, OidcSessionData } from '../../src/types.js';

const DEX_AVAILABLE = process.env.DEX_AVAILABLE === '1';

const DEX_CONFIG = {
	issuer: 'http://localhost:5556/dex',
	clientId: 'upact-poc',
	clientSecret: 'upact-poc-secret',
	redirectUri: 'http://localhost:3000/auth/callback',
	cookieKey: '0'.repeat(64),
	scopes: ['openid', 'offline_access', 'profile'],
	allowInsecureRequests: true, // localhost Dex only — never use in production
};

function decodeJwtClaims(token: string): IDTokenClaims {
	const payload = token.split('.')[1];
	const padded = payload
		.replace(/-/g, '+')
		.replace(/_/g, '/')
		.padEnd(payload.length + ((4 - (payload.length % 4)) % 4), '=');
	return JSON.parse(atob(padded)) as IDTokenClaims;
}

async function fetchTokensViaROPC() {
	const params = new URLSearchParams({
		grant_type: 'password',
		username: 'alice@example.com',
		password: 'password',
		scope: DEX_CONFIG.scopes.join(' '),
	});
	const creds = btoa(`${DEX_CONFIG.clientId}:${DEX_CONFIG.clientSecret}`);
	const resp = await fetch(`${DEX_CONFIG.issuer}/token`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded',
			Authorization: `Basic ${creds}`,
		},
		body: params.toString(),
	});
	if (!resp.ok) throw new Error(`Dex ROPC failed: ${resp.status} — ${await resp.text()}`);
	const data = await resp.json() as { access_token: string; refresh_token: string; id_token: string };
	return {
		accessToken: data.access_token,
		refreshToken: data.refresh_token,
		idToken: data.id_token,
		claims: decodeJwtClaims(data.id_token),
	};
}

// ——— claims mapping ——————————————————————————————————————————————————————————

describe('Dex integration — mapClaimsToUpactor', () => {
	let claims: IDTokenClaims;

	beforeAll(async () => {
		if (!DEX_AVAILABLE) return;
		const tokens = await fetchTokensViaROPC();
		claims = tokens.claims;
	});

	it.skipIf(!DEX_AVAILABLE)('maps real Dex claims to Upactor with lifecycle and provenance', async () => {
		const upactor = await mapClaimsToUpactor(claims);
		expect(upactor.id).toHaveLength(32);
		expect(upactor.lifecycle?.renewable).toBe('reauth');
		expect(upactor.lifecycle?.expires_at).toBeInstanceOf(Date);
		expect(upactor.provenance?.substrate).toBe('oidc');
		expect(upactor.provenance?.instance).toBe(DEX_CONFIG.issuer);
	}, 10000);

	it.skipIf(!DEX_AVAILABLE)('display_hint is username, not email address', async () => {
		const upactor = await mapClaimsToUpactor(claims);
		// Dex returns preferred_username: 'alice' (not alice@example.com)
		expect(upactor.display_hint).toBe('alice');
	}, 10000);

	it.skipIf(!DEX_AVAILABLE)('id is deterministic: same claims produce the same id', async () => {
		const a = await mapClaimsToUpactor(claims);
		const b = await mapClaimsToUpactor(claims);
		expect(a.id).toBe(b.id);
	}, 10000);

	it.skipIf(!DEX_AVAILABLE)('Upactor JSON does not contain the raw sub', async () => {
		const upactor = await mapClaimsToUpactor(claims);
		const json = JSON.stringify(upactor);
		expect(json).not.toContain(claims.sub);
	}, 10000);

	it.skipIf(!DEX_AVAILABLE)('Upactor JSON does not contain email', async () => {
		const upactor = await mapClaimsToUpactor(claims);
		const json = JSON.stringify(upactor);
		expect(json).not.toContain('@');
	}, 10000);
});

// ——— OidcClient refresh via openid-client v6 ————————————————————————————————

describe('Dex integration — OidcClient.refreshToken', () => {
	const client = createOidcClientBacked(DEX_CONFIG);

	it.skipIf(!DEX_AVAILABLE)('refreshes via openid-client v6 refreshTokenGrant', async () => {
		const { claims, refreshToken } = await fetchTokensViaROPC();
		const tokenSet = await client.refreshToken(refreshToken, claims.sub);
		expect(tokenSet.accessToken).toBeDefined();
		expect(tokenSet.idToken).toBeDefined();
		expect(tokenSet.claims.sub).toBe(claims.sub);
		expect(tokenSet.claims.iss).toBe(DEX_CONFIG.issuer);
		expect(tokenSet.expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
	}, 15000);

	it.skipIf(!DEX_AVAILABLE)('refreshed TokenSet maps to a privacy-stripped Upactor', async () => {
		const { claims, refreshToken } = await fetchTokensViaROPC();
		const tokenSet = await client.refreshToken(refreshToken, claims.sub);
		const upactor = await mapClaimsToUpactor(tokenSet.claims);
		const json = JSON.stringify(upactor);
		expect(upactor.id).toHaveLength(32);
		expect(upactor.provenance?.substrate).toBe('oidc');
		expect(json).not.toContain(tokenSet.claims.sub);
	}, 15000);
});

// ——— currentUpactor session round-trip ——————————————————————————————————————

describe('Dex integration — currentUpactor', () => {
	let tokens: Awaited<ReturnType<typeof fetchTokensViaROPC>>;

	beforeAll(async () => {
		if (!DEX_AVAILABLE) return;
		tokens = await fetchTokensViaROPC();
	});

	it.skipIf(!DEX_AVAILABLE)('reads a real session cookie and returns Upactor', async () => {
		const sessionData: OidcSessionData = {
			accessToken: tokens.accessToken,
			refreshToken: tokens.refreshToken,
			idToken: tokens.idToken,
			expiresAt: tokens.claims.exp,
			sub: tokens.claims.sub,
			issuer: tokens.claims.iss,
		};
		const cookies = makeCookieJar();
		cookies.store.set('__upact_oidc', await signSession(sessionData, DEX_CONFIG.cookieKey));

		const adapter = createOidcAdapter(DEX_CONFIG, cookies);
		const upactor = await adapter.currentUpactor(new Request('http://localhost:3000/'));
		expect(upactor).not.toBeNull();
		expect(upactor?.id).toHaveLength(32);
		expect(upactor?.provenance?.substrate).toBe('oidc');
		expect(upactor?.lifecycle?.renewable).toBe('reauth');
	}, 15000);

	it.skipIf(!DEX_AVAILABLE)('Upactor from currentUpactor does not expose raw sub', async () => {
		const sessionData: OidcSessionData = {
			accessToken: tokens.accessToken,
			idToken: tokens.idToken,
			expiresAt: tokens.claims.exp,
			sub: tokens.claims.sub,
			issuer: tokens.claims.iss,
		};
		const cookies = makeCookieJar();
		cookies.store.set('__upact_oidc', await signSession(sessionData, DEX_CONFIG.cookieKey));

		const adapter = createOidcAdapter(DEX_CONFIG, cookies);
		const upactor = await adapter.currentUpactor(new Request('http://localhost:3000/'));
		const json = JSON.stringify(upactor);
		expect(json).not.toContain(tokens.claims.sub);
		expect(json).not.toContain('@');
	}, 15000);
});

// ——— transparent refresh on expired session —————————————————————————————————

describe('Dex integration — currentUpactor transparent refresh', () => {
	it.skipIf(!DEX_AVAILABLE)('transparently refreshes an expired session using real Dex refresh token', async () => {
		// Fetch fresh tokens so the refresh token is not already consumed
		const fresh = await fetchTokensViaROPC();
		const sessionData: OidcSessionData = {
			accessToken: fresh.accessToken,
			refreshToken: fresh.refreshToken,
			idToken: fresh.idToken,
			expiresAt: Math.floor(Date.now() / 1000) - 100, // force expired
			sub: fresh.claims.sub,
			issuer: fresh.claims.iss,
		};
		const cookies = makeCookieJar();
		cookies.store.set('__upact_oidc', await signSession(sessionData, DEX_CONFIG.cookieKey));

		const adapter = createOidcAdapter(DEX_CONFIG, cookies);
		const upactor = await adapter.currentUpactor(new Request('http://localhost:3000/'));
		expect(upactor).not.toBeNull();
		expect(upactor?.provenance?.substrate).toBe('oidc');
		// Session cookie must have been rotated
		expect(cookies.set).toHaveBeenCalledWith('__upact_oidc', expect.any(String), expect.any(Object));
	}, 20000);
});

// ——— issueRenewal ————————————————————————————————————————————————————————————

describe('Dex integration — issueRenewal', () => {
	it.skipIf(!DEX_AVAILABLE)('issues renewal via real Dex refresh token', async () => {
		const fresh = await fetchTokensViaROPC();
		const sessionData: OidcSessionData = {
			accessToken: fresh.accessToken,
			refreshToken: fresh.refreshToken,
			idToken: fresh.idToken,
			expiresAt: fresh.claims.exp,
			sub: fresh.claims.sub,
			issuer: fresh.claims.iss,
		};
		const cookies = makeCookieJar();
		cookies.store.set('__upact_oidc', await signSession(sessionData, DEX_CONFIG.cookieKey));

		const adapter = createOidcAdapter(DEX_CONFIG, cookies);
		// identity.id is not used for sub comparison in issueRenewal (stored sub vs refreshed sub)
		const stale = { id: 'placeholder', capabilities: new Set() };
		const renewed = await adapter.issueRenewal(stale, undefined);
		expect(renewed).not.toBeNull();
		expect(renewed?.provenance?.substrate).toBe('oidc');
		expect(renewed?.lifecycle?.renewable).toBe('reauth');
	}, 20000);
});
