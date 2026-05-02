import { describe, it, expect } from 'vitest';
import { mapClaimsToUpactor } from '../src/claims-mapper.js';
import type { IDTokenClaims } from '../src/types.js';

const BASE_CLAIMS: IDTokenClaims = {
	sub: 'alice-sub-value',
	iss: 'http://localhost:5556/dex',
	aud: 'upact-poc',
	exp: 1800000000,
	iat: 1700000000,
};

describe('mapClaimsToUpactor', () => {
	it('derives id as sha256(sub@issuer) hex, 32 chars', async () => {
		const upactor = await mapClaimsToUpactor(BASE_CLAIMS);
		expect(typeof upactor.id).toBe('string');
		expect(upactor.id).toHaveLength(32);
		expect(upactor.id).toMatch(/^[0-9a-f]+$/);
	});

	it('produces the same id for the same sub+issuer', async () => {
		const a = await mapClaimsToUpactor(BASE_CLAIMS);
		const b = await mapClaimsToUpactor(BASE_CLAIMS);
		expect(a.id).toBe(b.id);
	});

	it('produces different ids for different sub values', async () => {
		const a = await mapClaimsToUpactor(BASE_CLAIMS);
		const b = await mapClaimsToUpactor({ ...BASE_CLAIMS, sub: 'bob-different-sub' });
		expect(a.id).not.toBe(b.id);
	});

	it('produces different ids for different issuers', async () => {
		const a = await mapClaimsToUpactor(BASE_CLAIMS);
		const b = await mapClaimsToUpactor({ ...BASE_CLAIMS, iss: 'http://other-idp:5556/dex' });
		expect(a.id).not.toBe(b.id);
	});

	it('sets capabilities to empty set', async () => {
		const upactor = await mapClaimsToUpactor(BASE_CLAIMS);
		expect(upactor.capabilities.size).toBe(0);
	});

	it('sets provenance with substrate oidc and issuer instance', async () => {
		const upactor = await mapClaimsToUpactor(BASE_CLAIMS);
		expect(upactor.provenance).toEqual({
			substrate: 'oidc',
			instance: 'http://localhost:5556/dex',
		});
	});

	it('sets lifecycle with expires_at from exp claim and renewable reauth', async () => {
		const upactor = await mapClaimsToUpactor(BASE_CLAIMS);
		expect(upactor.lifecycle?.renewable).toBe('reauth');
		expect(upactor.lifecycle?.expires_at).toBeInstanceOf(Date);
		expect(upactor.lifecycle?.expires_at?.getTime()).toBe(BASE_CLAIMS.exp * 1000);
	});

	describe('display_hint', () => {
		it('is absent when no name/preferred_username claim', async () => {
			const upactor = await mapClaimsToUpactor(BASE_CLAIMS);
			expect(upactor.display_hint).toBeUndefined();
		});

		it('uses preferred_username when present', async () => {
			const upactor = await mapClaimsToUpactor({
				...BASE_CLAIMS,
				preferred_username: 'alice',
			});
			expect(upactor.display_hint).toBe('alice');
		});

		it('falls back to name when preferred_username absent', async () => {
			const upactor = await mapClaimsToUpactor({ ...BASE_CLAIMS, name: 'Alice Liddell' });
			expect(upactor.display_hint).toBe('Alice Liddell');
		});

		it('prefers preferred_username over name', async () => {
			const upactor = await mapClaimsToUpactor({
				...BASE_CLAIMS,
				preferred_username: 'alice',
				name: 'Alice Liddell',
			});
			expect(upactor.display_hint).toBe('alice');
		});

		it('rejects email-shaped preferred_username', async () => {
			const upactor = await mapClaimsToUpactor({
				...BASE_CLAIMS,
				preferred_username: 'alice@example.com',
			});
			expect(upactor.display_hint).toBeUndefined();
		});

		it('rejects email-shaped name', async () => {
			const upactor = await mapClaimsToUpactor({
				...BASE_CLAIMS,
				name: 'alice@example.com',
			});
			expect(upactor.display_hint).toBeUndefined();
		});

		it('trims whitespace from display hint', async () => {
			const upactor = await mapClaimsToUpactor({
				...BASE_CLAIMS,
				preferred_username: '  alice  ',
			});
			expect(upactor.display_hint).toBe('alice');
		});

		it('treats empty preferred_username as absent', async () => {
			const upactor = await mapClaimsToUpactor({
				...BASE_CLAIMS,
				preferred_username: '   ',
			});
			expect(upactor.display_hint).toBeUndefined();
		});
	});

	describe('privacy stripping', () => {
		it('does not include sub on the returned Upactor', async () => {
			const upactor = await mapClaimsToUpactor(BASE_CLAIMS);
			expect(JSON.stringify(upactor)).not.toContain('alice-sub-value');
		});

		it('does not include iss string on the returned Upactor id', async () => {
			const upactor = await mapClaimsToUpactor(BASE_CLAIMS);
			expect(upactor.id).not.toContain('localhost');
		});

		it('does not include email even when present in claims (ignored by allow-list)', async () => {
			const claims = { ...BASE_CLAIMS, email: 'alice@example.com' } as IDTokenClaims & { email: string };
			const upactor = await mapClaimsToUpactor(claims);
			expect(JSON.stringify(upactor)).not.toContain('alice@example.com');
		});
	});
});
