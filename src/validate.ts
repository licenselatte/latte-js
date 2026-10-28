/**
 * Grace-period / offline validation.
 *
 * Boundary semantics are strict (`>`, never `>=`), and the 365-day
 * "too old" ceiling is independent of and unrelated to the grace period.
 */

import type { License } from "./domain.js";
import {
  GraceExpiredError,
  HardExpiredError,
  InvalidFieldsError,
  LicenseTooOldError,
  MachineIdMismatchError,
} from "./errors.js";

const MAX_AGE_SECS = 365 * 24 * 60 * 60;
const MAX_RENEWAL_TIME_SECS = 60 * 60;

/**
 * Validates `license` against `machineId` as of `now` (unix seconds).
 * Throws a ValidateError subclass on rejection.
 */
export function validateAt(license: License, machineId: string, now: number): void {
  if (license.issuedAt === 0) {
    throw new InvalidFieldsError("issued_at is zero");
  }
  if (license.expiresAt === 0) {
    throw new InvalidFieldsError("expires_at is zero");
  }
  if (license.gracePeriodSecs <= 0) {
    throw new InvalidFieldsError("grace_period is zero or negative");
  }
  if (license.machineId !== machineId) {
    throw new MachineIdMismatchError();
  }
  if (license.expiresAt < license.issuedAt) {
    throw new InvalidFieldsError("expires_at is before issued_at");
  }

  const offlineDeadline = license.issuedAt + license.gracePeriodSecs;

  if (now > license.expiresAt) {
    throw new HardExpiredError();
  }
  if (now > offlineDeadline) {
    throw new GraceExpiredError();
  }
  if (now - license.issuedAt > MAX_AGE_SECS) {
    throw new LicenseTooOldError();
  }
}

/**
 * inGracePeriod: true when the licence is still valid on cached data, the
 * SDK has tried to renew it and could not reach the server, and the offline
 * grace window has not run out.
 *
 * `renewalFailed` is the SDK's in-memory record of that failed attempt; with
 * it false the answer is always false. Past the 60-minute marker (strict, `>`)
 * and short of the grace deadline measured from issuedAt, a failed renewal
 * makes it true. Despite the name, this is **not** "is the license in its
 * grace period" — see isValid below for the actual grace-window membership
 * check. It is advisory: gate features on the check verdict, never on this.
 */
export function inGracePeriod(license: License, now: number, renewalFailed: boolean): boolean {
  const sinceActivation = now - license.issuedAt;
  return (
    renewalFailed &&
    sinceActivation > MAX_RENEWAL_TIME_SECS &&
    sinceActivation < license.gracePeriodSecs
  );
}

/**
 * isValid: now - issuedAt <= gracePeriod, inclusive at the boundary. A
 * third, distinct freshness check from validateAt's grace-deadline branch
 * (which is strict, `>`) and from inGracePeriod above (which also needs a
 * failed renewal) — kept as a separate function rather than collapsed
 * into either of the other two.
 */
export function isValid(license: License, now: number): boolean {
  return now - license.issuedAt <= license.gracePeriodSecs;
}
