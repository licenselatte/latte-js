/**
 * Certificate chain verification: Master -> Submaster -> Project -> Daily
 * -> activation token.
 *
 * Includes cross-checks between chain links. The daily cert's own exp is
 * not checked against `now`; its window bounds the activation's iat instead.
 */

import type { CertChain, License } from "./domain.js";
import { decodeEntitlements } from "./entitlements.js";
import {
  ChainInconsistentError,
  InvalidClaimError,
  InvalidSignatureError,
  MissingClaimError,
} from "./errors.js";
import { parseAndVerify, type ParsedJwt } from "./jwt.js";

const ISSUER = "licenselatte";
const MAX_GRACE_PERIOD_SECS = 90 * 24 * 60 * 60;
// 2099-01-01T00:00:00Z: the expiresAt of a licence that never ends, the
// same value a perpetual token in the grc format carries as its exp.
const PERPETUAL_EXPIRES_AT = 4_070_908_800;

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
 * Verifies the submaster cert against the first of `masterPub` it is signed
 * by. Only a signature mismatch moves on to the next key: any other failure
 * (malformed, wrong issuer, expired) is the same under every key, or only
 * reachable under the right one, so it is thrown as is. If no key matches,
 * the result is InvalidSignatureError.
 */
async function parseSubmasterCert(
  cert: string,
  masterPub: Uint8Array | readonly Uint8Array[],
  now: number,
): Promise<ParsedJwt> {
  const anchors = masterPub instanceof Uint8Array ? [masterPub] : masterPub;
  for (const pub of anchors) {
    try {
      return await parseAndVerify(cert, pub, ISSUER, now);
    } catch (e) {
      if (!(e instanceof InvalidSignatureError)) {
        throw e;
      }
    }
  }
  throw new InvalidSignatureError();
}

/**
 * Verifies the full chain and the activation token, evaluating time-based
 * claims as of `now` (unix seconds).
 *
 * `masterPub` is one master public key or several; the chain is accepted if
 * its submaster cert is signed by any of them. Pass `MASTER_PUBLIC_KEYS` to
 * trust the same keys `Sdk` does.
 *
 * Production callers should pass `Date.now() / 1000`; tests pass a
 * fixture's pinned `now` so results are reproducible (see
 * latte-testvectors/README.md).
 */
export async function verifyActivationAt(
  masterPub: Uint8Array | readonly Uint8Array[],
  token: string,
  chain: CertChain,
  now: number,
): Promise<License> {
  // Step 1: submaster cert, signed by a master key.
  const sub = await parseSubmasterCert(chain.submaster, masterPub, now);
  const submasterPub = pubKeyFromCert(sub.claims, "spk");

  // Step 2: project cert, signed by submaster.
  const proj = await parseAndVerify(chain.project, submasterPub, ISSUER, now);
  const projectPub = pubKeyFromCert(proj.claims, "ppk");

  // Step 3: daily cert, signed by project key. Its exp is not checked
  // against `now`: it expires the morning after it is issued, and the token
  // it signed has to verify offline for its whole grace period. Its window
  // bounds the token's iat instead, below.
  const daily = await parseAndVerify(chain.daily, projectPub, ISSUER, now, 0, false);
  const dailyPub = pubKeyFromCert(daily.claims, "dpk");

  // Step 4: activation JWT, signed by the daily key. Its iat/exp/nbf are
  // not checked against `now` here: a past `exp` is a grace_expired or
  // hard_expired rejection from validate.ts, never a verify failure.
  const activation = await parseAndVerify(token, dailyPub, ISSUER, now, null);
  const claims = activation.claims;

  const key = stringClaim(claims, "sub");
  const alias = stringClaim(claims, "alias");
  const activationId = stringClaim(claims, "aid");
  const projectId = stringClaim(claims, "pid");
  const machineId = stringClaim(claims, "mid");
  const licenseType = stringClaim(claims, "ltype");

  const issuedAt = numberClaim(claims, "iat") ?? 0;
  const exp = numberClaim(claims, "exp") ?? 0;

  // Two token formats, told apart by `grc` and nothing else. With `grc`,
  // `exp` is the licence's end and the offline deadline is iat + grc.
  // Without it, `exp` is the offline deadline itself and `lex` is the
  // licence's end, absent for a licence that never ends. Either way the
  // offline deadline is issuedAt + gracePeriodSecs, so validateAt needs no
  // knowledge of the format.
  let expiresAt: number;
  let gracePeriodSecs: number;
  if ("grc" in claims) {
    expiresAt = exp;
    gracePeriodSecs = Math.max(numberClaim(claims, "grc") ?? 0, 0);
  } else {
    expiresAt = "lex" in claims ? (numberClaim(claims, "lex") ?? 0) : PERPETUAL_EXPIRES_AT;
    gracePeriodSecs = Math.max(exp - issuedAt, 0);
  }

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

  // Cross-check: activation iat must not be after the daily cert's exp, so a
  // daily key cannot sign tokens dated after its own day.
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
