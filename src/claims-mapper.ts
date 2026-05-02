// SPDX-License-Identifier: Apache-2.0
/**
 * Claims mapper — pure function, allow-list-based.
 *
 * Reads only: sub, iss, exp, preferred_username, name.
 * Explicitly does NOT read: email, phone, address, groups, or any other claim.
 * Privacy-stripping is enforced by construction (allow-list), not by deletion.
 */

import type { Upactor } from '@prefig/upact';
import { capabilitiesFromIDP } from './capabilities.js';
import type { IDTokenClaims } from './types.js';

// SPEC §4.2: display_hint MUST NOT be an email address.
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * Map OIDC ID token claims to an upact Upactor.
 *
 * id = SHA-256(sub + '@' + iss), first 32 hex characters.
 * This is deterministic per identity, not reversible from id alone, and
 * not derivable from email (sub and iss are opaque to the application).
 */
export async function mapClaimsToUpactor(claims: IDTokenClaims): Promise<Upactor> {
	const id = await deriveId(claims.sub, claims.iss);
	const displayHint = readDisplayHint(claims);

	return {
		id,
		...(displayHint !== undefined ? { display_hint: displayHint } : {}),
		capabilities: capabilitiesFromIDP(),
		lifecycle: {
			expires_at: new Date(claims.exp * 1000),
			renewable: 'reauth',
		},
		provenance: {
			substrate: 'oidc',
			instance: claims.iss,
		},
	};
}

async function deriveId(sub: string, issuer: string): Promise<string> {
	const raw = `${sub}@${issuer}`;
	const encoded = new TextEncoder().encode(raw);
	const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
	const hashArray = Array.from(new Uint8Array(hashBuffer));
	return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 32);
}

function readDisplayHint(claims: IDTokenClaims): string | undefined {
	for (const raw of [claims.preferred_username, claims.name]) {
		if (typeof raw !== 'string') continue;
		const trimmed = raw.trim();
		if (trimmed.length > 0 && !EMAIL_PATTERN.test(trimmed)) return trimmed;
	}
	return undefined;
}
