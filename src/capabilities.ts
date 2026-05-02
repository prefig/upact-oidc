// SPDX-License-Identifier: Apache-2.0
import type { Capability } from '@prefig/upact';

/**
 * Returns the capability set for an OIDC IDP.
 *
 * v0.1: always [] (audit Option 2 — no concrete consumer gates on an OIDC
 * capability). Future: conditional on IDP discovery metadata advertising
 * specific endpoints (e.g. email endpoint → 'email' capability).
 */
export function capabilitiesFromIDP(): ReadonlySet<Capability> {
	return Object.freeze(new Set<Capability>());
}
