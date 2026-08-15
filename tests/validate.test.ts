/**
 * Isolated grace-period math tests: boundary conditions (exactly at the
 * threshold, one second before, one second after) and the independent
 * checks that make up validateAt. No signing involved — pure arithmetic
 * over synthetic License objects.
 */

import { describe, expect, it } from "vitest";
import { EXPIRING, PERPETUAL_FIXED, type License } from "../src/domain.js";
import {
  GraceExpiredError,
  HardExpiredError,
  InvalidFieldsError,
  LicenseTooOldError,
  MachineIdMismatchError,
} from "../src/errors.js";
import { inGracePeriod, isValid, validateAt } from "../src/validate.js";

const DAY = 24 * 60 * 60;
const NOW_ANCHOR = 10_000_000;

function makeLicense(overrides: Partial<License> = {}): License {
  return {
    key: "K",
    activationId: "A",
    projectId: "P",
    machineId: "M",
    issuedAt: NOW_ANCHOR - 7 * DAY,
    expiresAt: NOW_ANCHOR + 365 * DAY,
    gracePeriodSecs: 7 * DAY,
    licenseType: EXPIRING,
    metadata: {},
    ...overrides,
  };
}

describe("validateAt grace-period boundaries", () => {
  it("accepts exactly at the grace deadline", () => {
    const lic = makeLicense();
    const deadline = lic.issuedAt + lic.gracePeriodSecs;
    expect(() => validateAt(lic, "M", deadline)).not.toThrow();
  });

  it("accepts one second before the grace deadline", () => {
    const lic = makeLicense();
    const deadline = lic.issuedAt + lic.gracePeriodSecs - 1;
    expect(() => validateAt(lic, "M", deadline)).not.toThrow();
  });

  it("rejects one second after the grace deadline", () => {
    const lic = makeLicense();
    const deadline = lic.issuedAt + lic.gracePeriodSecs + 1;
    expect(() => validateAt(lic, "M", deadline)).toThrow(GraceExpiredError);
  });

  it("hard expiry wins even within a nominal grace window", () => {
    const lic = makeLicense({ expiresAt: NOW_ANCHOR - 7 * DAY + 3600 });
    expect(() => validateAt(lic, "M", lic.expiresAt + 1)).toThrow(HardExpiredError);
  });

  it("license-too-old fires independent of grace and expiry", () => {
    const lic = makeLicense({
      gracePeriodSecs: 1000 * DAY,
      expiresAt: NOW_ANCHOR + 2000 * DAY,
    });
    const checkAt = lic.issuedAt + 366 * DAY;
    expect(() => validateAt(lic, "M", checkAt)).toThrow(LicenseTooOldError);
  });

  it("rejects a machine ID mismatch", () => {
    const lic = makeLicense();
    expect(() => validateAt(lic, "someone-else", NOW_ANCHOR)).toThrow(
      MachineIdMismatchError,
    );
  });

  it("perpetual_fixed still requires a positive grace period", () => {
    const lic = makeLicense({ licenseType: PERPETUAL_FIXED, gracePeriodSecs: 0 });
    expect(() => validateAt(lic, "M", NOW_ANCHOR)).toThrow(InvalidFieldsError);
  });

  it("perpetual_fixed skips the grace deadline but not hard expiry", () => {
    const lic = makeLicense({ licenseType: PERPETUAL_FIXED });
    const checkAt = lic.issuedAt + lic.gracePeriodSecs + 1;
    expect(() => validateAt(lic, "M", checkAt)).not.toThrow();
  });

  it("perpetual_fixed still hard-expires", () => {
    const lic = makeLicense({ licenseType: PERPETUAL_FIXED, expiresAt: NOW_ANCHOR - 1 });
    expect(() => validateAt(lic, "M", NOW_ANCHOR)).toThrow(HardExpiredError);
  });

  it.each([
    ["issuedAt", 0],
    ["expiresAt", 0],
    ["gracePeriodSecs", 0],
  ])("rejects invalid field %s=%s", (field, value) => {
    const lic = makeLicense({ [field]: value } as Partial<License>);
    expect(() => validateAt(lic, "M", NOW_ANCHOR)).toThrow(InvalidFieldsError);
  });

  it("rejects expiresAt before issuedAt", () => {
    const lic = makeLicense({ expiresAt: NOW_ANCHOR - 8 * DAY });
    expect(() => validateAt(lic, "M", NOW_ANCHOR)).toThrow(InvalidFieldsError);
  });
});

describe("inGracePeriod / isValid", () => {
  it("is false before the 60-minute marker", () => {
    const lic = makeLicense({ issuedAt: NOW_ANCHOR - 30 * 60 });
    expect(inGracePeriod(lic, NOW_ANCHOR)).toBe(false);
  });

  it("is true between 60 minutes and the grace deadline", () => {
    const lic = makeLicense({ issuedAt: NOW_ANCHOR - 2 * 60 * 60 });
    expect(inGracePeriod(lic, NOW_ANCHOR)).toBe(true);
  });

  it("isValid matches validateAt at the boundary", () => {
    const lic = makeLicense();
    const deadline = lic.issuedAt + lic.gracePeriodSecs;
    expect(isValid(lic, deadline)).toBe(true);
    expect(isValid(lic, deadline + 1)).toBe(false);
  });
});
