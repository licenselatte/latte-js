/**
 * The verified, validated, "safe to use" view of a license, and the
 * pipeline that produces it.
 *
 * Split out of index.ts (which re-exports everything here unchanged) so
 * that http.ts can depend on checkLicenseAt/PublicLicense without a
 * circular import through the package entry point.
 */

import type { CertChain } from "./domain.js";
import { inGracePeriod, validateAt } from "./validate.js";
import { verifyActivationAt } from "./verify.js";

/**
 * The verified, validated, "safe to use" view of a license.
 */
export interface PublicLicense {
  readonly key: string;
  readonly activationId: string;
  readonly projectId: string;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly gracePeriodSecs: number;
  readonly inGracePeriod: boolean;
  readonly licenseType: string;
  readonly metadata: Readonly<Record<string, string>>;
}

/**
 * Runs the full pipeline against a cached token: chain verification, then
 * grace-period validation, then the inGracePeriod computation. This is the
 * primary entry point plugin developers embed — see README.md for usage.
 *
 * `now` (unix seconds) is a required, explicit parameter rather than an
 * internal `Date.now()` read — this is deliberate: it's what makes this
 * package's test suite fully reproducible against the shared fixtures in
 * testdata/. Pass `Date.now() / 1000` for real-time use.
 */
export async function checkLicenseAt(
  masterPub: Uint8Array,
  token: string,
  chain: CertChain,
  machineId: string,
  now: number,
): Promise<PublicLicense> {
  const license = await verifyActivationAt(masterPub, token, chain, now);
  validateAt(license, machineId, now);
  const inGrace = inGracePeriod(license, now);

  return {
    key: license.key,
    activationId: license.activationId,
    projectId: license.projectId,
    issuedAt: license.issuedAt,
    expiresAt: license.expiresAt,
    gracePeriodSecs: license.gracePeriodSecs,
    inGracePeriod: inGrace,
    licenseType: license.licenseType,
    metadata: license.metadata,
  };
}
