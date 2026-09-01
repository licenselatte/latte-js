/**
 * The verified, validated, "safe to use" view of a license, and the
 * pipeline that produces it.
 *
 * Split out of index.ts (which re-exports everything here unchanged) so
 * that http.ts can depend on checkLicenseAt/PublicLicense without a
 * circular import through the package entry point.
 */

import type { CertChain, License } from "./domain.js";
import type { EntitlementValue } from "./entitlements.js";
import { can, limit } from "./entitlements.js";
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

  /**
   * The typed feature map the seller signed into this licence: a flat
   * object whose values are booleans and integers and nothing else. Read it
   * with {@link PublicLicense.can} and {@link PublicLicense.limit} rather
   * than indexing it directly, unless you want to enumerate what was
   * granted.
   *
   * Always an object — empty when the token carried no `ent` claim. Use
   * {@link PublicLicense.hasEntitlements} to tell those two cases apart.
   * See entitlements.ts for the full contract.
   */
  readonly entitlements: Readonly<Record<string, EntitlementValue>>;

  /**
   * Whether the activation token carried an `ent` claim at all — including
   * an empty one, which is why this is not an `Object.keys(...).length`
   * check.
   *
   * It exists for one job: letting an application fall back to its
   * pre-entitlements behaviour for the one release it takes an installed
   * base to renew. Absence denies, so without this probe, shipping `can()`
   * before setting values in the dashboard switches the feature off for
   * every customer holding an older cached token.
   */
  readonly hasEntitlements: boolean;

  /**
   * Whether the boolean entitlement named by `key` is present and true.
   *
   * A key that is absent, or that holds a number rather than a boolean,
   * answers `false`. There is no coercion across kinds: `can` on an integer
   * entitlement is false even when that integer is non-zero.
   */
  can(key: string): boolean;

  /**
   * The integer entitlement named by `key`, or `undefined` when it is
   * absent.
   *
   * The unlimited sentinel is returned as-is: compare against `UNLIMITED`
   * rather than testing for a negative number. `limit` on a boolean
   * entitlement is `undefined`, not 1 or 0.
   */
  limit(key: string): number | undefined;
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

  return toPublicLicense(license, inGracePeriod(license, now));
}

/**
 * Projects a chain-verified {@link License} onto its public shape.
 *
 * Shared with the cached-token path in http.ts rather than inlined at each
 * call site: the two used to be duplicate object literals, and a field added
 * to one and not the other is a difference nothing would catch.
 */
export function toPublicLicense(license: License, inGrace: boolean): PublicLicense {
  const entitlements = license.entitlements;

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
    // Always an object, so callers can enumerate unconditionally; the
    // absent-versus-empty distinction lives in hasEntitlements alone.
    entitlements: entitlements ?? {},
    hasEntitlements: entitlements !== undefined,
    can: (key: string) => can(entitlements, key),
    limit: (key: string) => limit(entitlements, key),
  };
}
