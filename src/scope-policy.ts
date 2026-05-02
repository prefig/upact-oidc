// SPDX-License-Identifier: Apache-2.0
/**
 * OIDC scope discipline — runtime guard (SPEC.md §10 / Decision G1).
 *
 * Privacy-load-bearing: forbidden scopes leak fields (email, phone, address,
 * group membership) that upact §7 MUST NOT surfaces at the port. Enforcement
 * is a runtime check, not just convention.
 */

/** Scopes that MUST NOT be requested — they cross the §7 privacy boundary. */
const FORBIDDEN_SCOPES = new Set(['email', 'phone', 'address', 'groups']);

/** Scopes the adapter allows (any other scope is a config error). */
const ALLOWED_SCOPES = new Set(['openid', 'offline_access', 'profile']);

/** Default scopes when none are specified in OidcConfig. */
export const DEFAULT_SCOPES: string[] = ['openid', 'offline_access'];

/**
 * Validates that the requested scopes do not include forbidden values and
 * only include recognised values. Throws a descriptive error if invalid.
 *
 * Called at adapter construction time, before any network request.
 */
export function validateScopes(scopes: string[]): void {
	for (const scope of scopes) {
		if (FORBIDDEN_SCOPES.has(scope)) {
			throw new Error(
				`upact scope policy violation (SPEC §7): scope '${scope}' is forbidden. ` +
					`Forbidden scopes leak privacy-minima fields (email, phone, address, group membership) ` +
					`that upact MUST NOT surface at the port. ` +
					`Allowed scopes: ${[...ALLOWED_SCOPES].join(', ')}.`,
			);
		}
		if (!ALLOWED_SCOPES.has(scope)) {
			throw new Error(
				`upact scope policy: scope '${scope}' is not in the allow-list. ` +
					`Allowed scopes: ${[...ALLOWED_SCOPES].join(', ')}.`,
			);
		}
	}
	if (!scopes.includes('openid')) {
		throw new Error(`upact scope policy: 'openid' is required.`);
	}
}
