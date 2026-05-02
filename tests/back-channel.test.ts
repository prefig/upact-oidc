import { describe, it, expect } from 'vitest';
import { inspect } from 'node:util';
import { createOidcAdapter } from '../src/adapter.js';
import { makeCookieJar, makeMockClient, TEST_CONFIG } from './fixtures/mock-client.js';

/**
 * Decision 11 / SPEC §7.5 — 16-vector closure-conformance test.
 *
 * The adapter MUST NOT expose substrate tokens or the cookie jar via any
 * common reflection path. Sentinel values planted on the cookie jar mock
 * MUST be unreachable through the adapter instance.
 */

describe('createOidcAdapter — back-channel closure conformance (16 vectors)', () => {
	function makeAdapter() {
		const cookies = makeCookieJar();
		const client = makeMockClient();
		// Plant sentinel values on the client mock to detect leakage
		(client as Record<string, unknown>).__sentinel = 'SENTINEL_TOKEN_VALUE';
		(cookies as Record<string, unknown>).__sentinel = 'SENTINEL_COOKIE_VALUE';
		const adapter = createOidcAdapter(TEST_CONFIG, cookies, client);
		return { adapter, sentinels: ['SENTINEL_TOKEN_VALUE', 'SENTINEL_COOKIE_VALUE', TEST_CONFIG.cookieKey, TEST_CONFIG.clientSecret] };
	}

	it('JSON.stringify does not leak sentinels', () => {
		const { adapter, sentinels } = makeAdapter();
		const json = JSON.stringify(adapter);
		for (const s of sentinels) expect(json).not.toContain(s);
	});

	it('Object.keys does not surface substrate state', () => {
		const { adapter, sentinels } = makeAdapter();
		const keys = JSON.stringify(Object.keys(adapter));
		for (const s of sentinels) expect(keys).not.toContain(s);
	});

	it('Object.getOwnPropertyNames does not surface substrate state', () => {
		const { adapter, sentinels } = makeAdapter();
		const names = JSON.stringify(Object.getOwnPropertyNames(adapter));
		for (const s of sentinels) expect(names).not.toContain(s);
	});

	it('Reflect.ownKeys does not surface substrate state', () => {
		const { adapter, sentinels } = makeAdapter();
		const keys = JSON.stringify(Reflect.ownKeys(adapter).map(String));
		for (const s of sentinels) expect(keys).not.toContain(s);
	});

	it('Object.getOwnPropertySymbols does not surface substrate state', () => {
		const { adapter, sentinels } = makeAdapter();
		const syms = JSON.stringify(Object.getOwnPropertySymbols(adapter).map(String));
		for (const s of sentinels) expect(syms).not.toContain(s);
	});

	it('for-in loop does not surface substrate state', () => {
		const { adapter, sentinels } = makeAdapter();
		const found: string[] = [];
		for (const key in adapter) found.push(key);
		const result = JSON.stringify(found);
		for (const s of sentinels) expect(result).not.toContain(s);
	});

	it('structuredClone throws DataCloneError (functions are not clonable — no data leak possible)', () => {
		const { adapter } = makeAdapter();
		// An object with function properties cannot be structuredCloned.
		// DataCloneError itself is the proof that no substrate data escapes via this vector.
		expect(() => structuredClone(adapter)).toThrow();
	});

	it('util.inspect does not surface sentinels', () => {
		const { adapter, sentinels } = makeAdapter();
		const inspected = inspect(adapter, { depth: 5 });
		for (const s of sentinels) expect(inspected).not.toContain(s);
	});

	it('(adapter as any).client is undefined', () => {
		const { adapter } = makeAdapter();
		expect((adapter as Record<string, unknown>).client).toBeUndefined();
	});

	it('(adapter as any).cookies is undefined', () => {
		const { adapter } = makeAdapter();
		expect((adapter as Record<string, unknown>).cookies).toBeUndefined();
	});

	it('(adapter as any).cookieKey is undefined', () => {
		const { adapter } = makeAdapter();
		expect((adapter as Record<string, unknown>).cookieKey).toBeUndefined();
	});

	it('(adapter as any).clientSecret is undefined', () => {
		const { adapter } = makeAdapter();
		expect((adapter as Record<string, unknown>).clientSecret).toBeUndefined();
	});

	it('Object spread does not surface substrate state', () => {
		const { adapter, sentinels } = makeAdapter();
		const spread = JSON.stringify({ ...adapter });
		for (const s of sentinels) expect(spread).not.toContain(s);
	});

	it('wrapped JSON.stringify with replacer does not surface substrate state', () => {
		const { adapter, sentinels } = makeAdapter();
		const json = JSON.stringify(adapter, (_, v) => (typeof v === 'function' ? '[fn]' : v));
		for (const s of sentinels) expect(json).not.toContain(s);
	});

	it('Object.entries does not surface substrate state', () => {
		const { adapter, sentinels } = makeAdapter();
		const entries = JSON.stringify(Object.entries(adapter));
		for (const s of sentinels) expect(entries).not.toContain(s);
	});

	it('(adapter as any)._config is undefined', () => {
		const { adapter } = makeAdapter();
		expect((adapter as Record<string, unknown>)._config).toBeUndefined();
	});
});
