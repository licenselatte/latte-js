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
 * inGracePeriod: true once more than 60 minutes have passed since issuedAt
 * without a renewal, while still inside the grace window measured from
 * that same issuedAt. Despite the name, this is **not** "is the license in
 * its grace period" — it's a softer, earlier "please reconnect soon"
 * signal; see isValid below for the actual grace-window membership check.
 */
export function inGracePeriod(license: License, now: number): boolean {
  const sinceActivation = now - license.issuedAt;
  return sinceActivation > MAX_RENEWAL_TIME_SECS && sinceActivation < license.gracePeriodSecs;
}

/**
 * isValid: now - issuedAt <= gracePeriod, inclusive at the boundary. A
 * third, distinct freshness check from validateAt's grace-deadline branch
 * (which is strict, `>`) and from inGracePeriod above (which is a softer,
 * earlier warning) — kept as a separate function rather than collapsed
 * into either of the other two.
 */
export function isValid(license: License, now: number): boolean {
  return now - license.issuedAt <= license.gracePeriodSecs;
}
