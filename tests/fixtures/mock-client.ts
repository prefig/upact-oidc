import { vi } from 'vitest';
import type { OidcClient, TokenSet } from '../../src/client.js';
import type { IDTokenClaims } from '../../src/types.js';

export function makeIdTokenClaims(overrides: Partial<IDTokenClaims> = {}): IDTokenClaims {
	return {
		sub: 'alice-sub',
		iss: 'http://localhost:5556/dex',
		aud: 'upact-poc',
		exp: Math.floor(Date.now() / 1000) + 3600,
		iat: Math.floor(Date.now() / 1000),
		preferred_username: 'alice',
		...overrides,
	};
}

export function makeTokenSet(overrides: Partial<TokenSet> = {}): TokenSet {
	const claims = makeIdTokenClaims();
	return {
		accessToken: 'access-token-sentinel',
		refreshToken: 'refresh-token-sentinel',
		idToken: 'id-token-sentinel',
		expiresAt: claims.exp,
		claims,
		...overrides,
	};
}

export function makeMockClient(overrides: Partial<OidcClient> = {}): OidcClient {
	return {
		getConfig: vi.fn().mockResolvedValue({}),
		buildAuthorizationUrl: vi.fn().mockResolvedValue(new URL('http://localhost:5556/dex/auth?state=s')),
		exchangeCode: vi.fn().mockResolvedValue(makeTokenSet()),
		refreshToken: vi.fn().mockResolvedValue(makeTokenSet()),
		buildEndSessionUrl: vi.fn().mockResolvedValue(new URL('http://localhost:5556/dex/end_session')),
		randomState: vi.fn().mockReturnValue('random-state'),
		randomCodeVerifier: vi.fn().mockReturnValue('code-verifier'),
		calculateCodeChallenge: vi.fn().mockResolvedValue('code-challenge'),
		randomNonce: vi.fn().mockReturnValue('random-nonce'),
		...overrides,
	};
}

export function makeCookieJar(): {
	get: ReturnType<typeof vi.fn>;
	set: ReturnType<typeof vi.fn>;
	delete: ReturnType<typeof vi.fn>;
	store: Map<string, string>;
} {
	const store = new Map<string, string>();
	return {
		store,
		get: vi.fn((name: string) => store.get(name)),
		set: vi.fn((name: string, value: string) => { store.set(name, value); }),
		delete: vi.fn((name: string) => { store.delete(name); }),
	};
}

export const TEST_CONFIG = {
	issuer: 'http://localhost:5556/dex',
	clientId: 'upact-poc',
	clientSecret: 'upact-poc-secret',
	redirectUri: 'http://localhost:3000/auth/callback',
	cookieKey: '0'.repeat(64),
};
