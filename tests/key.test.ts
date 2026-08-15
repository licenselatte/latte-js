import { describe, expect, it } from "vitest";
import { parseAppId, baseUrlFor } from "../src/appid.js";
import {
  InvalidChecksumError,
  UnknownEnvironmentError,
} from "../src/errors.js";
import { calculateChecksum, sanitizeKey, validateKey } from "../src/key.js";

describe("sanitizeKey", () => {
  it("folds ambiguous characters", () => {
    expect(sanitizeKey("ab-cd IL o")).toBe("ABCD110");
  });
});

describe("checksum", () => {
  it("round-trips", () => {
    const data = "AHAK85389VQYXYB6S4BW66SKE53TWVT";
    const sum = calculateChecksum(data, 4);
    expect(validateKey(data + sum, 4)).toBe(true);
    expect(validateKey(data + "XXXX", 4)).toBe(false);
  });

  it("survives out-of-alphabet input without throwing", () => {
    expect(() => validateKey("!!!!not-valid-alphabet!!!!", 4)).not.toThrow();
  });
});

describe("parseAppId", () => {
  const data28 = "AHAK85389VQYXYB6S4BW66SKE53T"; // 28 chars
  const checksum = calculateChecksum(data28, 4);

  it("accepts a well-formed live AppID", () => {
    const parsed = parseAppId(`pk_live_${data28}${checksum}`);
    expect(parsed.env).toBe("live");
    expect(baseUrlFor(parsed.env)).toBe("https://api.licenselatte.com");
  });

  it("supports the undocumented local environment", () => {
    const parsed = parseAppId(`pk_local_${data28}${checksum}`);
    expect(baseUrlFor(parsed.env)).toBe("http://localhost:8080");
  });

  it("rejects a bad checksum", () => {
    expect(() => parseAppId(`pk_live_${data28}XXXX`)).toThrow(InvalidChecksumError);
  });

  it("rejects an unknown environment", () => {
    expect(() => parseAppId(`pk_staging_${data28}${checksum}`)).toThrow(
      UnknownEnvironmentError,
    );
  });
});
