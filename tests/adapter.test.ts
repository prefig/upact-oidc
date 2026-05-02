import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createOidcAdapter } from '../src/adapter.js';
import { signState } from '../src/state-cookies.js';
import { signSession } from '../src/session-cookies.js';
import { makeMockClient, makeCookieJar, makeTokenSet, makeIdTokenClaims, TEST_CONFIG } from './fixtures/mock-client.js';
import type { AuthError } from '@prefig/upact';

function isAuthError(v: unknown): v is AuthError {
	return typeof v === 'object' && v !== null && 'code' in v && 'message' in v;
}

function makeCallbackRequest() {
	return new Request('http://localhost:3000/auth/callback?code=auth-code&state=random-state');
}

async function makeValidStateCookie() {
	return signState(
		{ state: 'random-state', codeVerifier: 'code-verifier', nonce: 'random-nonce', returnTo: '/' },
		TEST_CONFIG.cookieKey,
	);
}

async function makeValidSessionCookie(overrides = {}) {
	const claims = makeIdTokenClaims(overrides);
	return signSession(
		{
			accessToken: 'access-token-sentinel',
			refreshToken: 'refresh-token-sentinel',
			idToken: 'id-token-sentinel',
			expiresAt: claims.exp,
			sub: claims.sub,
			issuer: claims.iss,
		},
		TEST_CONFIG.cookieKey,
	);
}

describe('createOidcAdapter — construction', () => {
	it('throws at construction for forbidden scopes', () => {
		const cookies = makeCookieJar();
		expect(() =>
			createOidcAdapter({ ...TEST_CONFIG, scopes: ['openid', 'email'] }, cookies),
		).toThrow(/forbidden/i);
	});

	it('accepts valid scope list', () => {
		const cookies = makeCookieJar();
		expect(() =>
			createOidcAdapter({ ...TEST_CONFIG, scopes: ['openid', 'profile'] }, cookies),
		).not.toThrow();
	});
});

describe('createOidcAdapter — buildAuthRedirect', () => {
	it('returns an authorization URL and sets the state cookie', async () => {
		const cookies = makeCookieJar();
		const client = makeMockClient();
		const adapter = createOidcAdapter(TEST_CONFIG, cookies, client);

		const url = await adapter.buildAuthRedirect();
		expect(url).toBeInstanceOf(URL);
		expect(client.randomState).toHaveBeenCalled();
		expect(client.calculateCodeChallenge).toHaveBeenCalled();
		expect(cookies.set).toHaveBeenCalledWith(
			'__upact_oidc_state',
			expect.any(String),
			expect.objectContaining({ httpOnly: true }),
		);
	});

	it('passes prompt option through', async () => {
		const cookies = makeCookieJar();
		const client = makeMockClient();
		const adapter = createOidcAdapter(TEST_CONFIG, cookies, client);
		await adapter.buildAuthRedirect({ prompt: 'login' });
		expect(client.buildAuthorizationUrl).toHaveBeenCalledWith(
			expect.objectContaining({ prompt: 'login' }),
			expect.any(Array),
		);
	});
});

describe('createOidcAdapter — authenticate', () => {
	it('rejects non-oidc-callback credentials', async () => {
		const cookies = makeCookieJar();
		const adapter = createOidcAdapter(TEST_CONFIG, cookies, makeMockClient());
		const result = await adapter.authenticate({ kind: 'password', email: 'a@b.com' });
		expect(isAuthError(result)).toBe(true);
		expect((result as AuthError).code).toBe('credential_invalid');
	});

	it('returns credential_invalid when state cookie is missing', async () => {
		const cookies = makeCookieJar();
		const adapter = createOidcAdapter(TEST_CONFIG, cookies, makeMockClient());
		const result = await adapter.authenticate({ kind: 'oidc-callback', request: makeCallbackRequest() });
		expect(isAuthError(result)).toBe(true);
		expect((result as AuthError).code).toBe('credential_invalid');
	});

	it('returns credential_invalid when state cookie is tampered', async () => {
		const cookies = makeCookieJar();
		cookies.store.set('__upact_oidc_state', 'tampered.value');
		const adapter = createOidcAdapter(TEST_CONFIG, cookies, makeMockClient());
		const result = await adapter.authenticate({ kind: 'oidc-callback', request: makeCallbackRequest() });
		expect(isAuthError(result)).toBe(true);
		expect((result as AuthError).code).toBe('credential_invalid');
	});

	it('exchanges code, sets session cookie, returns opaque Session', async () => {
		const cookies = makeCookieJar();
		cookies.store.set('__upact_oidc_state', await makeValidStateCookie());
		const client = makeMockClient();
		const adapter = createOidcAdapter(TEST_CONFIG, cookies, client);

		const result = await adapter.authenticate({ kind: 'oidc-callback', request: makeCallbackRequest() });
		expect(isAuthError(result)).toBe(false);
		// Session is opaque
		expect(JSON.stringify(result)).toBe('"[upact:session]"');
		// State cookie deleted
		expect(cookies.delete).toHaveBeenCalledWith('__upact_oidc_state', expect.anything());
		// Session cookie set
		expect(cookies.set).toHaveBeenCalledWith('__upact_oidc', expect.any(String), expect.any(Object));
	});

	it('deletes state cookie immediately even on exchange failure', async () => {
		const cookies = makeCookieJar();
		cookies.store.set('__upact_oidc_state', await makeValidStateCookie());
		const client = makeMockClient({
			exchangeCode: vi.fn().mockRejectedValue(new Error('invalid_grant')),
		});
		const adapter = createOidcAdapter(TEST_CONFIG, cookies, client);
		await adapter.authenticate({ kind: 'oidc-callback', request: makeCallbackRequest() });
		expect(cookies.delete).toHaveBeenCalledWith('__upact_oidc_state', expect.anything());
	});

	it.each([
		['invalid_grant error', 'invalid_grant', 'credential_rejected'],
		['server_error', 'server_error: IDP down', 'substrate_unavailable'],
		['rate limit', 'slow_down: rate limited', 'rate_limited'],
	])('maps exchange error "%s" to AuthErrorCode %s', async (_, errMsg, expectedCode) => {
		const cookies = makeCookieJar();
		cookies.store.set('__upact_oidc_state', await makeValidStateCookie());
		const client = makeMockClient({
			exchangeCode: vi.fn().mockRejectedValue(new Error(errMsg)),
		});
		const adapter = createOidcAdapter(TEST_CONFIG, cookies, client);
		const result = await adapter.authenticate({ kind: 'oidc-callback', request: makeCallbackRequest() });
		expect(isAuthError(result)).toBe(true);
		expect((result as AuthError).code).toBe(expectedCode);
	});

	it('returned Session does not leak tokens', async () => {
		const cookies = makeCookieJar();
		cookies.store.set('__upact_oidc_state', await makeValidStateCookie());
		const adapter = createOidcAdapter(TEST_CONFIG, cookies, makeMockClient());
		const session = await adapter.authenticate({ kind: 'oidc-callback', request: makeCallbackRequest() });
		const json = JSON.stringify(session);
		expect(json).not.toContain('access-token-sentinel');
		expect(json).not.toContain('refresh-token-sentinel');
		expect(json).not.toContain('id-token-sentinel');
	});
});

describe('createOidcAdapter — currentUpactor', () => {
	it('returns null when no session cookie', async () => {
		const cookies = makeCookieJar();
		const adapter = createOidcAdapter(TEST_CONFIG, cookies, makeMockClient());
		const result = await adapter.currentUpactor(new Request('http://localhost/'));
		expect(result).toBeNull();
	});

	it('returns Upactor with lifecycle and provenance for a valid session', async () => {
		const cookies = makeCookieJar();
		cookies.store.set('__upact_oidc', await makeValidSessionCookie());
		const adapter = createOidcAdapter(TEST_CONFIG, cookies, makeMockClient());
		const upactor = await adapter.currentUpactor(new Request('http://localhost/'));
		expect(upactor).not.toBeNull();
		expect(upactor?.lifecycle?.renewable).toBe('reauth');
		expect(upactor?.provenance?.substrate).toBe('oidc');
	});

	it('transparently refreshes an expired session when refresh token present', async () => {
		const expiredClaims = makeIdTokenClaims({ exp: Math.floor(Date.now() / 1000) - 100 });
		const sessionCookie = await signSession(
			{
				accessToken: 'old-access',
				refreshToken: 'refresh-token-sentinel',
				idToken: 'old-id',
				expiresAt: expiredClaims.exp,
				sub: expiredClaims.sub,
				issuer: expiredClaims.iss,
			},
			TEST_CONFIG.cookieKey,
		);
		const cookies = makeCookieJar();
		cookies.store.set('__upact_oidc', sessionCookie);

		const freshClaims = makeIdTokenClaims();
		const client = makeMockClient({
			refreshToken: vi.fn().mockResolvedValue(makeTokenSet({ claims: freshClaims })),
		});
		const adapter = createOidcAdapter(TEST_CONFIG, cookies, client);
		const upactor = await adapter.currentUpactor(new Request('http://localhost/'));
		expect(upactor).not.toBeNull();
		expect(client.refreshToken).toHaveBeenCalledOnce();
		expect(cookies.set).toHaveBeenCalled(); // session cookie updated
	});

	it('returns null and deletes session for expired session with no refresh token', async () => {
		const expiredClaims = makeIdTokenClaims({ exp: Math.floor(Date.now() / 1000) - 100 });
		const sessionCookie = await signSession(
			{
				accessToken: 'old-access',
				idToken: 'old-id',
				expiresAt: expiredClaims.exp,
				sub: expiredClaims.sub,
				issuer: expiredClaims.iss,
			},
			TEST_CONFIG.cookieKey,
		);
		const cookies = makeCookieJar();
		cookies.store.set('__upact_oidc', sessionCookie);
		const adapter = createOidcAdapter(TEST_CONFIG, cookies, makeMockClient());
		const result = await adapter.currentUpactor(new Request('http://localhost/'));
		expect(result).toBeNull();
		expect(cookies.delete).toHaveBeenCalledWith('__upact_oidc', expect.anything());
	});

	it('does not leak tokens from the returned Upactor', async () => {
		const cookies = makeCookieJar();
		cookies.store.set('__upact_oidc', await makeValidSessionCookie());
		const adapter = createOidcAdapter(TEST_CONFIG, cookies, makeMockClient());
		const upactor = await adapter.currentUpactor(new Request('http://localhost/'));
		const json = JSON.stringify(upactor);
		expect(json).not.toContain('access-token-sentinel');
		expect(json).not.toContain('refresh-token-sentinel');
		expect(json).not.toContain('alice-sub');
	});
});

describe('createOidcAdapter — invalidate', () => {
	it('deletes the session cookie', async () => {
		const cookies = makeCookieJar();
		cookies.store.set('__upact_oidc', await makeValidSessionCookie());
		const adapter = createOidcAdapter(TEST_CONFIG, cookies, makeMockClient());
		const session = {} as never; // Session is opaque
		await adapter.invalidate(session);
		expect(cookies.delete).toHaveBeenCalledWith('__upact_oidc', expect.anything());
	});
});

describe('createOidcAdapter — issueRenewal', () => {
	it('returns null when no session cookie', async () => {
		const cookies = makeCookieJar();
		const adapter = createOidcAdapter(TEST_CONFIG, cookies, makeMockClient());
		const identity = { id: 'x', capabilities: new Set() };
		const result = await adapter.issueRenewal(identity, undefined);
		expect(result).toBeNull();
	});

	it('returns null when session has no refresh token (Decision 9)', async () => {
		const cookies = makeCookieJar();
		const claims = makeIdTokenClaims();
		const sessionCookie = await signSession(
			{ accessToken: 'a', idToken: 'i', expiresAt: claims.exp, sub: claims.sub, issuer: claims.iss },
			TEST_CONFIG.cookieKey,
		);
		cookies.store.set('__upact_oidc', sessionCookie);
		const adapter = createOidcAdapter(TEST_CONFIG, cookies, makeMockClient());
		const identity = { id: 'x', capabilities: new Set() };
		const result = await adapter.issueRenewal(identity, undefined);
		expect(result).toBeNull();
	});

	it('refreshes and returns renewed Upactor on success', async () => {
		const cookies = makeCookieJar();
		cookies.store.set('__upact_oidc', await makeValidSessionCookie());
		const freshClaims = makeIdTokenClaims({ sub: 'alice-sub' });
		const client = makeMockClient({
			refreshToken: vi.fn().mockResolvedValue(makeTokenSet({ claims: freshClaims })),
		});
		const adapter = createOidcAdapter(TEST_CONFIG, cookies, client);
		const stale = { id: 'anything', capabilities: new Set() };
		const renewed = await adapter.issueRenewal(stale, undefined);
		expect(renewed).not.toBeNull();
		expect(renewed?.lifecycle?.renewable).toBe('reauth');
		expect(client.refreshToken).toHaveBeenCalledOnce();
	});

	it('returns null and clears session on invalid_grant (refresh token expired)', async () => {
		const cookies = makeCookieJar();
		cookies.store.set('__upact_oidc', await makeValidSessionCookie());
		const client = makeMockClient({
			refreshToken: vi.fn().mockRejectedValue(new Error('invalid_grant')),
		});
		const adapter = createOidcAdapter(TEST_CONFIG, cookies, client);
		const stale = { id: 'x', capabilities: new Set() };
		const result = await adapter.issueRenewal(stale, undefined);
		expect(result).toBeNull();
		expect(cookies.delete).toHaveBeenCalledWith('__upact_oidc', expect.anything());
	});

	it('returns null on sub mismatch (Decision 3 Option A — identity-bound)', async () => {
		const cookies = makeCookieJar();
		cookies.store.set('__upact_oidc', await makeValidSessionCookie());
		const client = makeMockClient({
			refreshToken: vi.fn().mockRejectedValue(new Error('sub mismatch on refresh')),
		});
		const adapter = createOidcAdapter(TEST_CONFIG, cookies, client);
		const stale = { id: 'x', capabilities: new Set() };
		const result = await adapter.issueRenewal(stale, undefined);
		expect(result).toBeNull();
	});
});
