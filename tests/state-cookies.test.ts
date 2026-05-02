import { describe, it, expect, vi } from 'vitest';
import { signState, unsignState } from '../src/state-cookies.js';
import type { PendingState } from '../src/types.js';

// 32-byte key as 64 hex chars (test-only)
const TEST_KEY = '0'.repeat(64);

const SAMPLE_STATE: PendingState = {
	state: 'random-state-abc123',
	codeVerifier: 'pkce-verifier-xyz',
	nonce: 'nonce-value',
	returnTo: '/dashboard',
};

describe('signState / unsignState', () => {
	it('round-trips the state value', async () => {
		const cookie = await signState(SAMPLE_STATE, TEST_KEY);
		const recovered = await unsignState(cookie, TEST_KEY);
		expect(recovered).toEqual(SAMPLE_STATE);
	});

	it('returns null for a tampered payload', async () => {
		const cookie = await signState(SAMPLE_STATE, TEST_KEY);
		const parts = cookie.split('.');
		parts[0] = parts[0]!.slice(0, -4) + 'AAAA';
		const tampered = parts.join('.');
		const result = await unsignState(tampered, TEST_KEY);
		expect(result).toBeNull();
	});

	it('returns null for a tampered signature', async () => {
		const cookie = await signState(SAMPLE_STATE, TEST_KEY);
		const parts = cookie.split('.');
		parts[1] = parts[1]!.slice(0, -4) + 'AAAA';
		const tampered = parts.join('.');
		const result = await unsignState(tampered, TEST_KEY);
		expect(result).toBeNull();
	});

	it('returns null for a different signing key', async () => {
		const cookie = await signState(SAMPLE_STATE, TEST_KEY);
		const wrongKey = 'f'.repeat(64);
		const result = await unsignState(cookie, wrongKey);
		expect(result).toBeNull();
	});

	it('returns null for a cookie with no dot separator', async () => {
		const result = await unsignState('nodotanywhere', TEST_KEY);
		expect(result).toBeNull();
	});

	it('returns null for an expired cookie', async () => {
		const cookie = await signState(SAMPLE_STATE, TEST_KEY);
		// Advance time by 11 minutes
		vi.setSystemTime(Date.now() + 11 * 60 * 1000);
		const result = await unsignState(cookie, TEST_KEY);
		vi.useRealTimers();
		expect(result).toBeNull();
	});

	it('works without a returnTo field', async () => {
		const state: PendingState = { state: 's', codeVerifier: 'v', nonce: 'n' };
		const cookie = await signState(state, TEST_KEY);
		const recovered = await unsignState(cookie, TEST_KEY);
		expect(recovered).toEqual(state);
		expect(recovered?.returnTo).toBeUndefined();
	});

	it('cookie value does not contain state or codeVerifier in plaintext', async () => {
		const cookie = await signState(SAMPLE_STATE, TEST_KEY);
		// The base64url encoding of the JSON will contain the values, but not as plain strings
		// We just ensure the raw sensitive values don't appear unencoded
		expect(cookie).not.toContain('pkce-verifier-xyz');
		expect(cookie).not.toContain('random-state-abc123');
	});
});
