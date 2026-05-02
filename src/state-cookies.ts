// SPDX-License-Identifier: Apache-2.0
/**
 * Signed-cookie helpers for OAuth state management during the redirect round-trip.
 *
 * Cookies carry PendingState (state, codeVerifier, nonce, returnTo) from the
 * init phase to the callback phase. They are signed with HMAC-SHA256,
 * HttpOnly, Secure, SameSite=Lax, path-scoped to /auth/callback, 10-min TTL.
 *
 * Tampered or expired cookies return null — the adapter treats this as an
 * invalid/replayed callback (credential_invalid).
 */

import type { PendingState } from './types.js';

const COOKIE_TTL_SECONDS = 10 * 60; // 10 minutes

interface SignedPayload {
	data: PendingState;
	expiresAt: number; // unix seconds
}

/** Derive a CryptoKey from a hex-encoded 32-byte key string. */
async function importKey(hexKey: string): Promise<CryptoKey> {
	const bytes = new Uint8Array(hexKey.match(/.{2}/g)!.map((b) => parseInt(b, 16)));
	return crypto.subtle.importKey('raw', bytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

/** Sign a payload: base64url(json) + '.' + base64url(hmac). */
export async function signState(state: PendingState, hexKey: string): Promise<string> {
	const payload: SignedPayload = { data: state, expiresAt: Math.floor(Date.now() / 1000) + COOKIE_TTL_SECONDS };
	const json = JSON.stringify(payload);
	const encoded = btoa(json).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
	const key = await importKey(hexKey);
	const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(encoded));
	const sigEncoded = btoa(String.fromCharCode(...new Uint8Array(sig)))
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=/g, '');
	return `${encoded}.${sigEncoded}`;
}

/** Verify and decode a signed state cookie. Returns null if tampered or expired. */
export async function unsignState(cookie: string, hexKey: string): Promise<PendingState | null> {
	const dot = cookie.lastIndexOf('.');
	if (dot === -1) return null;
	const encoded = cookie.slice(0, dot);
	const sigEncoded = cookie.slice(dot + 1);

	const key = await importKey(hexKey);
	// Re-pad base64url → base64
	const sigPadded = sigEncoded.replace(/-/g, '+').replace(/_/g, '/').padEnd(
		sigEncoded.length + ((4 - (sigEncoded.length % 4)) % 4),
		'=',
	);
	let sigBytes: Uint8Array<ArrayBuffer>;
	try {
		sigBytes = Uint8Array.from(atob(sigPadded), (c) => c.charCodeAt(0));
	} catch {
		return null;
	}

	const valid = await crypto.subtle.verify('HMAC', key, sigBytes, new TextEncoder().encode(encoded));
	if (!valid) return null;

	const jsonPadded = encoded.replace(/-/g, '+').replace(/_/g, '/').padEnd(
		encoded.length + ((4 - (encoded.length % 4)) % 4),
		'=',
	);
	let payload: SignedPayload;
	try {
		payload = JSON.parse(atob(jsonPadded)) as SignedPayload;
	} catch {
		return null;
	}

	if (payload.expiresAt < Math.floor(Date.now() / 1000)) return null;
	return payload.data;
}
