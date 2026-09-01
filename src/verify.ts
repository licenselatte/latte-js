/**
 * Certificate chain verification: Master -> Submaster -> Project -> Daily
 * -> activation token.
 *
 * Includes cross-checks between chain links — see the comment on the
 * iat/exp cross-check below before "fixing" it; its current behavior is
 * intentional, not a bug.
 */

import type { CertChain, License } from "./domain.js";
import { decodeEntitlements } from "./entitlements.js";
import {
  ChainInconsistentError,
  InvalidClaimError,
  MissingClaimError,
} from "./errors.js";
import { parseAndVerify } from "./jwt.js";

const ISSUER = "licenselatte";
const MAX_GRACE_PERIOD_SECS = 90 * 24 * 60 * 60;

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error("not valid hex");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function pubKeyFromCert(claims: Record<string, unknown>, field: string): Uint8Array {
  const hexStr = claims[field];
  if (typeof hexStr !== "string") {
    throw new MissingClaimError(field);
  }
  let raw: Uint8Array;
  try {
    raw = hexToBytes(hexStr);
  } catch (e) {
    throw new InvalidClaimError(field, `not valid hex: ${(e as Error).message}`);
  }
  if (raw.length !== 32) {
    throw new InvalidClaimError(field, `must be 32 bytes, got ${raw.length}`);
  }
  return raw;
}

function numberClaim(claims: Record<string, unknown>, key: string): number | undefined {
  const v = claims[key];
  return typeof v === "number" ? v : undefined;
}

function stringClaim(claims: Record<string, unknown>, key: string): string {
  const v = claims[key];
  return typeof v === "string" ? v : "";
}

/**
 * Verifies the full chain and the activation token, evaluating time-based
 * claims as of `now` (unix seconds).
 *
 * Production callers should pass `Date.now() / 1000`; tests pass a
 * fixture's pinned `now` so results are reproducible (see
 * latte-testvectors/README.md).
 */
export async function verifyActivationAt(
  masterPub: Uint8Array,
  token: string,
  chain: CertChain,
  now: number,
): Promise<License> {
  // Step 1: submaster cert, signed by master.
  const sub = await parseAndVerify(chain.submaster, masterPub, ISSUER, now);
  const submasterPub = pubKeyFromCert(sub.claims, "spk");

  // Step 2: project cert, signed by submaster.
  const proj = await parseAndVerify(chain.project, submasterPub, ISSUER, now);
  const projectPub = pubKeyFromCert(proj.claims, "ppk");

  // Step 3: daily cert, signed by project key.
  const daily = await parseAndVerify(chain.daily, projectPub, ISSUER, now);
  const dailyPub = pubKeyFromCert(daily.claims, "dpk");

  // Step 4: activation JWT, signed by the daily key. An effectively-infinite
  // leeway applies here — its own iat/exp/nbf are not authoritative; the
  // grace-period math in validate.ts is.
  const activation = await parseAndVerify(token, dailyPub, ISSUER, now, null);
  const claims = activation.claims;

  const key = stringClaim(claims, "sub");
  const alias = stringClaim(claims, "alias");
  const activationId = stringClaim(claims, "aid");
  const projectId = stringClaim(claims, "pid");
  const machineId = stringClaim(claims, "mid");
  const licenseType = stringClaim(claims, "ltype");

  const grc = numberClaim(claims, "grc") ?? 0;
  const gracePeriodSecs = Math.max(grc, 0);
  const issuedAt = numberClaim(claims, "iat") ?? 0;
  const expiresAt = numberClaim(claims, "exp") ?? 0;

  const entitlements = decodeEntitlements(claims);

  const metadata: Record<string, string> = {};
  const pmd = claims["pmd"];
  if (typeof pmd === "object" && pmd !== null && !Array.isArray(pmd)) {
    for (const [k, v] of Object.entries(pmd as Record<string, unknown>)) {
      if (typeof v === "string") {
        metadata[k] = v;
      }
    }
  }

  // Cross-check: project cert's own pid (if present) must agree with the
  // activation JWT's pid.
  const pidInCert = proj.claims["pid"];
  if (typeof pidInCert === "string" && pidInCert !== "" && pidInCert !== projectId) {
    throw new ChainInconsistentError(
      `project_id mismatch between activation JWT (${projectId}) and project cert (${pidInCert})`,
    );
  }

  // Daily cert's iat/exp are required (not just optional claims).
  const dailyIat = numberClaim(daily.claims, "iat");
  if (dailyIat === undefined) {
    throw new MissingClaimError("iat");
  }
  const dailyExp = numberClaim(daily.claims, "exp");
  if (dailyExp === undefined) {
    throw new MissingClaimError("exp");
  }

  // Cross-check: activation iat must not precede the daily cert's own iat
  // (an activation can't have been issued before its signer existed).
  if (issuedAt < dailyIat) {
    throw new ChainInconsistentError("activation JWT iat is before daily cert iat");
  }

  // Cross-check intended to ensure the activation doesn't outlive the daily
  // cert that signed it. This compares the activation's IssuedAt against
  // the daily cert's exp, not the activation's own ExpiresAt as the intent
  // (and the error message) might suggest. This is intentional, existing
  // behavior — do not change it to compare `exp` without explicit sign-off,
  // since it changes accept/reject outcomes.
  if (issuedAt > dailyExp) {
    throw new ChainInconsistentError("activation JWT iat is after daily cert exp");
  }

  // Grace period ceiling: no lower bound is enforced anywhere.
  if (gracePeriodSecs > MAX_GRACE_PERIOD_SECS) {
    throw new ChainInconsistentError(`grace period too long: ${gracePeriodSecs}s`);
  }

  return {
    key,
    alias,
    activationId,
    projectId,
    machineId,
    issuedAt,
    expiresAt,
    gracePeriodSecs,
    licenseType,
    metadata,
    entitlements,
  };
}
