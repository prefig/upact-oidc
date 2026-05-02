import { describe, it, expect } from 'vitest';
import { validateScopes, DEFAULT_SCOPES } from '../src/scope-policy.js';

describe('validateScopes', () => {
	it('accepts the default scopes', () => {
		expect(() => validateScopes(DEFAULT_SCOPES)).not.toThrow();
	});

	it('accepts openid + offline_access + profile', () => {
		expect(() => validateScopes(['openid', 'offline_access', 'profile'])).not.toThrow();
	});

	it.each(['email', 'phone', 'address', 'groups'])(
		'throws on forbidden scope: %s',
		(scope) => {
			expect(() => validateScopes(['openid', scope])).toThrow(/forbidden/i);
			expect(() => validateScopes(['openid', scope])).toThrow(scope);
			expect(() => validateScopes(['openid', scope])).toThrow(/SPEC §7/);
		},
	);

	it('throws when openid is missing', () => {
		expect(() => validateScopes(['offline_access'])).toThrow(/openid.*required/i);
	});

	it('throws on unknown scope', () => {
		expect(() => validateScopes(['openid', 'custom_scope'])).toThrow(/allow-list/i);
	});

	it('DEFAULT_SCOPES are openid and offline_access', () => {
		expect(DEFAULT_SCOPES).toContain('openid');
		expect(DEFAULT_SCOPES).toContain('offline_access');
		expect(DEFAULT_SCOPES).toHaveLength(2);
	});
});
