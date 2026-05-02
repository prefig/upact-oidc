// SPDX-License-Identifier: Apache-2.0
/**
 * Session cookie helpers — HMAC-signed JSON containing OidcSessionData.
 *
 * The session cookie is HttpOnly, Secure, SameSite=Lax, long-lived (matches
 * the IDP's refresh token expiry; we use 30 days as a safe upper bound).
 * The access_token and refresh_token are sensitive; they are signed but not
 * encrypted. Keep HTTPS enforced at the infrastructure layer.
 */

import type { CookieSetOptions, OidcSessionData } from './types.js';

const SESSION_MAX_AGE = 30 * 24 * 60 * 60; // 30 days in seconds

async function importKey(hexKey: string): Promise<CryptoKey> {
	const bytes = new Uint8Array(hexKey.match(/.{2}/g)!.map((b) => parseInt(b, 16)));
	return crypto.subtle.importKey('raw', bytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

function b64url(buf: Uint8Array): string {
	return btoa(String.fromCharCode(...buf))
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=/g, '');
}

function fromb64url(s: string): Uint8Array<ArrayBuffer> {
	const padded = s.replace(/-/g, '+').replace(/_/g, '/').padEnd(s.length + ((4 - (s.length % 4)) % 4), '=');
	return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

export async function signSession(data: OidcSessionData, hexKey: string): Promise<string> {
	const json = JSON.stringify(data);
	const encoded = b64url(new TextEncoder().encode(json));
	const key = await importKey(hexKey);
	const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(encoded));
	return `${encoded}.${b64url(new Uint8Array(sig))}`;
}

export async function unsignSession(cookie: string, hexKey: string): Promise<OidcSessionData | null> {
	const dot = cookie.lastIndexOf('.');
	if (dot === -1) return null;
	const encoded = cookie.slice(0, dot);
	const sigEncoded = cookie.slice(dot + 1);

	const key = await importKey(hexKey);
	const sigBytes = fromb64url(sigEncoded);
	const valid = await crypto.subtle.verify('HMAC', key, sigBytes, new TextEncoder().encode(encoded));
	if (!valid) return null;

	try {
		const json = new TextDecoder().decode(fromb64url(encoded));
		return JSON.parse(json) as OidcSessionData;
	} catch {
		return null;
	}
}

export function sessionCookieOptions(secure: boolean): CookieSetOptions {
	return {
		httpOnly: true,
		secure,
		sameSite: 'Lax' as const,
		path: '/',
		maxAge: SESSION_MAX_AGE,
	};
}
