/**
 * Runs every shared fixture in testdata/ against this package's
 * verify/validate pipeline. See ../../latte-testvectors/README.md for the
 * fixture schema and the expect_reason taxonomy this test asserts against.
 */

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { inGracePeriod, validateAt } from "../src/validate.js";
import { verifyActivationAt } from "../src/verify.js";
import type { CertChain } from "../src/domain.js";
import {
  GraceExpiredError,
  HardExpiredError,
  LicenseTooOldError,
  MachineIdMismatchError,
  ValidateError,
  VerifyError,
} from "../src/errors.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const TESTDATA_DIR = join(__dirname, "..", "testdata/vectors");

interface Fixture {
  name: string;
  now: string;
  master_public_key_hex: string;
  machine_id: string;
  token: string;
  chain: { submaster: string; project: string; daily: string };
  expect: "accept" | "reject";
  expect_stage: "none" | "verify" | "validate";
  expect_reason: string;
  expect_in_grace_period: boolean;
}

function loadFixtures(): Fixture[] {
  return readdirSync(TESTDATA_DIR)
    .filter((f) => f.endsWith(".json") && f !== "manifest.json")
    .map((f) => JSON.parse(readFileSync(join(TESTDATA_DIR, f), "utf-8")) as Fixture);
}

function parseRfc3339(s: string): number {
  const ms = Date.parse(s);
  if (Number.isNaN(ms)) {
    throw new Error(`bad timestamp: ${s}`);
  }
  return ms / 1000;
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function reasonFor(e: ValidateError): string {
  if (e instanceof HardExpiredError) return "hard_expired";
  if (e instanceof GraceExpiredError) return "grace_expired";
  if (e instanceof LicenseTooOldError) return "license_too_old";
  if (e instanceof MachineIdMismatchError) return "machine_id_mismatch";
  return "other";
}

const fixtures = loadFixtures();

describe("shared cross-language fixtures", () => {
  it("has the full fixture set", () => {
    expect(fixtures.length).toBeGreaterThan(15);
  });

  for (const f of fixtures) {
    it(f.name, async () => {
      const now = parseRfc3339(f.now);
      const masterPub = hexToBytes(f.master_public_key_hex);
      const chain: CertChain = {
        submaster: f.chain.submaster,
        project: f.chain.project,
        daily: f.chain.daily,
      };

      let license;
      try {
        license = await verifyActivationAt(masterPub, f.token, chain, now);
      } catch (e) {
        if (!(e instanceof VerifyError)) throw e;
        expect(f.expect, `unexpected verify-stage rejection: ${e}`).toBe("reject");
        expect(f.expect_stage).toBe("verify");
        return;
      }
      expect(
        !(f.expect === "reject" && f.expect_stage === "verify"),
        "expected verify-stage rejection but chain verification succeeded",
      ).toBe(true);

      try {
        validateAt(license, f.machine_id, now);
      } catch (e) {
        if (!(e instanceof ValidateError)) throw e;
        expect(f.expect, `unexpected validate-stage rejection: ${e}`).toBe("reject");
        expect(f.expect_stage).toBe("validate");
        expect(reasonFor(e)).toBe(f.expect_reason);
        return;
      }

      expect(
        f.expect,
        "expected rejection but verify+validate both succeeded",
      ).toBe("accept");

      const inGrace = inGracePeriod(license, now);
      expect(inGrace).toBe(f.expect_in_grace_period);
    });
  }
});
