/**
 * Domain types for the certificate chain and license claims.
 */

import type { EntitlementValue } from "./entitlements.js";

/**
 * Master (implicit, caller-supplied) -> Submaster -> Project -> Daily.
 */
export interface CertChain {
  readonly submaster: string;
  readonly project: string;
  readonly daily: string;
}

export const PERPETUAL = "perpetual";
export const EXPIRING = "expiring";

/**
 * A chain-verified, not-yet-grace-validated license. Produced by
 * verifyActivationAt, consumed by validateAt. All timestamps are unix
 * seconds (not milliseconds), matching the JWT `iat`/`exp` claims directly.
 */
export interface License {
  readonly key: string;
  /**
   * The legacy-system key string this license was resolved from, when it
   * was minted via a legacy-key migration alias rather than activated by
   * its own native key. "" for a natively-keyed license. Internal only —
   * used to recognize a cached token on a later activate() call passing
   * the same legacy key, since `key` above will be the newly minted
   * native key instead. See the JWT's "alias" claim.
   */
  readonly alias: string;
  readonly activationId: string;
  readonly projectId: string;
  readonly machineId: string;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly gracePeriodSecs: number;
  readonly licenseType: string;
  readonly metadata: Readonly<Record<string, string>>;
  /**
   * The decoded `ent` claim, or `undefined` when the token carried no such
   * claim at all — a different thing from an empty object, and the
   * distinction `PublicLicense.hasEntitlements` reports. See
   * entitlements.ts.
   */
  readonly entitlements: Readonly<Record<string, EntitlementValue>> | undefined;
}
