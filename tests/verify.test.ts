/**
 * Isolated chain-verification and signature-verification tests: build a
 * minimal cert chain in-process (independent of the shared fixtures /
 * generator) and exercise valid chains, tampered signatures, wrong keys,
 * broken intermediate links, and the documented cross-checks.
 */

import * as ed from "@noble/ed25519";
import { beforeEach, describe, expect, it } from "vitest";
import type { CertChain } from "../src/domain.js";
import {
  ChainInconsistentError,
  InvalidSignatureError,
  MalformedTokenError,
  MissingClaimError,
  NotYetValidError,
  VerifyError,
} from "../src/errors.js";
import { verifyActivationAt } from "../src/verify.js";

const ISSUER = "licenselatte";

function b64url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function signJwt(priv: Uint8Array, claims: Record<string, unknown>): Promise<string> {
  const header = b64url(new TextEncoder().encode('{"alg":"EdDSA","typ":"JWT"}'));
  const payload = b64url(new TextEncoder().encode(JSON.stringify(claims)));
  const signingInput = new TextEncoder().encode(`${header}.${payload}`);
  const sig = await ed.signAsync(signingInput, priv);
  return `${header}.${payload}.${b64url(sig)}`;
}

interface Chain {
  master: Uint8Array;
  masterPub: Uint8Array;
  project: Uint8Array;
  projectPub: Uint8Array;
  daily: Uint8Array;
  dailyPub: Uint8Array;
  chain: CertChain;
}

async function buildChain(now: number): Promise<Chain> {
  const master = ed.utils.randomPrivateKey();
  const masterPub = await ed.getPublicKeyAsync(master);
  const submaster = ed.utils.randomPrivateKey();
  const submasterPub = await ed.getPublicKeyAsync(submaster);
  const project = ed.utils.randomPrivateKey();
  const projectPub = await ed.getPublicKeyAsync(project);
  const daily = ed.utils.randomPrivateKey();
  const dailyPub = await ed.getPublicKeyAsync(daily);

  const submasterCert = await signJwt(master, {
    iss: ISSUER,
    iat: now - 1_000_000,
    exp: now + 1_000_000,
    spk: hex(submasterPub),
  });
  const projectCert = await signJwt(submaster, {
    iss: ISSUER,
    iat: now - 500_000,
    exp: now + 500_000,
    ppk: hex(projectPub),
    pid: "proj_1",
  });
  const dailyCert = await signJwt(project, {
    iss: ISSUER,
    iat: now - 86_400,
    exp: now + 86_400,
    dpk: hex(dailyPub),
  });

  return {
    master,
    masterPub,
    project,
    projectPub,
    daily,
    dailyPub,
    chain: { submaster: submasterCert, project: projectCert, daily: dailyCert },
  };
}

function activationClaims(now: number): Record<string, unknown> {
  return {
    iss: ISSUER,
    sub: "KEY",
    aid: "ACT1",
    pid: "proj_1",
    mid: "machine-1",
    ltype: "expiring",
    iat: now,
    exp: now + 1_000_000,
    grc: 7 * 86_400,
  };
}

describe("verifyActivationAt", () => {
  const now = 10_000_000;
  let c: Chain;

  beforeEach(async () => {
    c = await buildChain(now);
  });

  it("accepts a valid chain and signature", async () => {
    const token = await signJwt(c.daily, activationClaims(now));
    const lic = await verifyActivationAt(c.masterPub, token, c.chain, now);
    expect(lic.key).toBe("KEY");
    expect(lic.projectId).toBe("proj_1");
  });

  it("rejects a tampered signature", async () => {
    const token = (await signJwt(c.daily, activationClaims(now))) + "x";
    await expect(verifyActivationAt(c.masterPub, token, c.chain, now)).rejects.toSatisfy(
      (e: unknown) => e instanceof VerifyError,
    );
  });

  it("rejects the wrong master key", async () => {
    const token = await signJwt(c.daily, activationClaims(now));
    const wrongMaster = await ed.getPublicKeyAsync(ed.utils.randomPrivateKey());
    await expect(verifyActivationAt(wrongMaster, token, c.chain, now)).rejects.toThrow(
      InvalidSignatureError,
    );
  });

  it("rejects a broken intermediate link", async () => {
    const rogue = ed.utils.randomPrivateKey();
    const rogueProjectCert = await signJwt(rogue, {
      iss: ISSUER,
      iat: now - 500_000,
      exp: now + 500_000,
      ppk: hex(c.projectPub),
      pid: "proj_1",
    });
    const chain: CertChain = { ...c.chain, project: rogueProjectCert };
    const token = await signJwt(c.daily, activationClaims(now));
    await expect(verifyActivationAt(c.masterPub, token, chain, now)).rejects.toThrow(
      InvalidSignatureError,
    );
  });

  it("enforces the project_id cross-check", async () => {
    const claims = { ...activationClaims(now), pid: "some-other-project" };
    const token = await signJwt(c.daily, claims);
    await expect(verifyActivationAt(c.masterPub, token, c.chain, now)).rejects.toThrow(
      ChainInconsistentError,
    );
  });

  it("rejects a daily cert missing exp", async () => {
    const dailyCert = await signJwt(c.project, {
      iss: ISSUER,
      iat: now - 86_400,
      dpk: hex(c.dailyPub),
    });
    const chain: CertChain = { ...c.chain, daily: dailyCert };
    const token = await signJwt(c.daily, activationClaims(now));
    await expect(verifyActivationAt(c.masterPub, token, chain, now)).rejects.toThrow(
      MissingClaimError,
    );
  });

  it("rejects cert iat in the future with zero leeway", async () => {
    const token = await signJwt(c.daily, activationClaims(now));
    const skewedNow = now - 86_400 - 10; // before daily cert's own iat
    await expect(
      verifyActivationAt(c.masterPub, token, c.chain, skewedNow),
    ).rejects.toThrow(NotYetValidError);
  });

  it("tolerates a future activation iat via infinite leeway", async () => {
    const claims = { ...activationClaims(now), iat: now + 3600 };
    const token = await signJwt(c.daily, claims);
    const lic = await verifyActivationAt(c.masterPub, token, c.chain, now);
    expect(lic.key).toBe("KEY");
  });

  it("rejects a grace period exceeding the 90-day ceiling", async () => {
    const claims = { ...activationClaims(now), grc: 91 * 86_400 };
    const token = await signJwt(c.daily, claims);
    await expect(verifyActivationAt(c.masterPub, token, c.chain, now)).rejects.toThrow(
      ChainInconsistentError,
    );
  });

  it("rejects a malformed token", async () => {
    await expect(
      verifyActivationAt(c.masterPub, "not-a-jwt", c.chain, now),
    ).rejects.toThrow(MalformedTokenError);
  });
});
