/**
 * Minimal EdDSA/Ed25519 JWT compact-serialization handling.
 *
 * The certificate chain uses exactly one JWA algorithm ("EdDSA", RFC 8037,
 * pure Ed25519 — never prehashed HashEdDSA), one serialization (compact),
 * and a fixed set of claims per JWT "kind". There is no reason to depend on
 * a general JWT library for four call sites with one fixed algorithm; the
 * only cryptographic primitive used is @noble/ed25519's signature
 * verification (audited, no native deps, not hand-rolled).
 *
 * Verification is async because @noble/ed25519 v2 delegates SHA-512 to the
 * WebCrypto API (available in both Node and browsers/Electron) rather than
 * bundling its own hash implementation.
 */

import * as ed from "@noble/ed25519";
import {
  ExpiredError,
  MalformedTokenError,
  NotYetValidError,
  WrongIssuerError,
  InvalidSignatureError,
} from "./errors.js";

export interface ParsedJwt {
  readonly claims: Record<string, unknown>;
}

function base64UrlDecode(s: string): Uint8Array {
  const padded = s + "=".repeat((4 - (s.length % 4)) % 4);
  const b64 = padded.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function decodeJsonObject(bytes: Uint8Array, what: string): Record<string, unknown> {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (e) {
    throw new MalformedTokenError(`${what}: invalid utf-8 (${(e as Error).message})`);
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (e) {
    throw new MalformedTokenError(`${what}: invalid json (${(e as Error).message})`);
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new MalformedTokenError(`${what} is not a JSON object`);
  }
  return value as Record<string, unknown>;
}

/**
 * Parses and Ed25519-verifies a compact JWT against pubKey, then validates
 * `iss` and, with the given leeway (zero by default), `iat`/`exp`/`nbf` if
 * present.
 *
 * Zero leeway applies to submaster/project/daily certs: no clock-skew
 * tolerance at all. Pass `leewaySecs: null` for the activation-token parse
 * — expiry for that JWT is instead entirely the responsibility of the
 * grace-period math in validate.ts.
 */
export async function parseAndVerify(
  token: string,
  pubKey: Uint8Array,
  expectedIssuer: string,
  now: number,
  leewaySecs: number | null = 0,
): Promise<ParsedJwt> {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new MalformedTokenError(`expected 3 dot-separated parts, got ${parts.length}`);
  }
  const [headerB64, payloadB64, sigB64] = parts as [string, string, string];

  let headerBytes: Uint8Array;
  try {
    headerBytes = base64UrlDecode(headerB64);
  } catch (e) {
    throw new MalformedTokenError(`header base64: ${(e as Error).message}`);
  }
  const header = decodeJsonObject(headerBytes, "header");
  if (header["alg"] !== "EdDSA") {
    throw new MalformedTokenError(`unexpected alg: ${JSON.stringify(header["alg"])}`);
  }

  let payloadBytes: Uint8Array;
  try {
    payloadBytes = base64UrlDecode(payloadB64);
  } catch (e) {
    throw new MalformedTokenError(`payload base64: ${(e as Error).message}`);
  }
  const claims = decodeJsonObject(payloadBytes, "payload");

  let sigBytes: Uint8Array;
  try {
    sigBytes = base64UrlDecode(sigB64);
  } catch (e) {
    throw new MalformedTokenError(`signature base64: ${(e as Error).message}`);
  }
  if (sigBytes.length !== 64) {
    throw new MalformedTokenError(`signature is not 64 bytes, got ${sigBytes.length}`);
  }

  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  let ok: boolean;
  try {
    ok = await ed.verifyAsync(sigBytes, signingInput, pubKey);
  } catch {
    ok = false;
  }
  if (!ok) {
    throw new InvalidSignatureError();
  }

  if (claims["iss"] !== expectedIssuer) {
    throw new WrongIssuerError();
  }

  if (leewaySecs !== null) {
    checkTimeClaims(claims, now, leewaySecs);
  }

  return { claims };
}

function checkTimeClaims(
  claims: Record<string, unknown>,
  now: number,
  leewaySecs: number,
): void {
  const iat = claims["iat"];
  if (typeof iat === "number" && iat > now + leewaySecs) {
    throw new NotYetValidError();
  }
  const nbf = claims["nbf"];
  if (typeof nbf === "number" && nbf > now + leewaySecs) {
    throw new NotYetValidError();
  }
  const exp = claims["exp"];
  if (typeof exp === "number" && exp < now - leewaySecs) {
    throw new ExpiredError();
  }
}
