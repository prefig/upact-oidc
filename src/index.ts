// SPDX-License-Identifier: Apache-2.0
/**
 * @prefig/upact-oidc — Generic OIDC adapter for upact.
 *
 * Delegates substrate machinery to a substrate-side IDP
 * (Authentik, Keycloak, ZITADEL, Dex). One adapter, many IDPs.
 */

export { createOidcAdapter } from './adapter.js';
export type { OidcAdapterExtensions } from './adapter.js';
export { validateScopes, DEFAULT_SCOPES } from './scope-policy.js';
export type {
	OidcConfig,
	CookieJar,
	CookieSetOptions,
	OidcCredential,
	OidcSessionData,
	PendingState,
} from './types.js';

export type {
	Upactor,
	IdentityLifecycle,
	Capability,
	Session,
	AuthError,
	AuthErrorCode,
	IdentityPort,
} from '@prefig/upact';
export { SubstrateUnavailableError } from '@prefig/upact';
