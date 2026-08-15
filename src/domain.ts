/**
 * Domain types for the certificate chain and license claims.
 */

/**
 * Master (implicit, caller-supplied) -> Submaster -> Project -> Daily.
 */
export interface CertChain {
  readonly submaster: string;
  readonly project: string;
  readonly daily: string;
}

export const PERPETUAL_FIXED = "perpetual_fixed";
export const PERPETUAL = "perpetual";
export const EXPIRING = "expiring";

/**
 * A chain-verified, not-yet-grace-validated license. Produced by
 * verifyActivationAt, consumed by validateAt. All timestamps are unix
 * seconds (not milliseconds), matching the JWT `iat`/`exp` claims directly.
 */
export interface License {
  readonly key: string;
  readonly activationId: string;
  readonly projectId: string;
  readonly machineId: string;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly gracePeriodSecs: number;
  readonly licenseType: string;
  readonly metadata: Readonly<Record<string, string>>;
}

export function isPerpetualFixed(license: License): boolean {
  return license.licenseType === PERPETUAL_FIXED;
}
