/**
 * Runs testdata/anchors.json and testdata/cache_files.json. See
 * ../../latte-testvectors/README.md, sections "Anchors" and "Cache files".
 */

import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import type { CertChain } from "../src/domain.js";
import { ValidateError, VerifyError } from "../src/errors.js";
import { resolveStorage } from "../src/storage.js";
import { validateAt } from "../src/validate.js";
import { verifyActivationAt } from "../src/verify.js";

const TESTDATA = join(dirname(fileURLToPath(import.meta.url)), "..", "testdata");

interface AnchorCase {
  name: string;
  now: string;
  master_public_keys_hex: string[];
  machine_id: string;
  token: string;
  chain: CertChain;
  expect: "accept" | "reject";
  expect_stage: "none" | "verify" | "validate";
}

interface CacheFiles {
  now: string;
  master_public_keys_hex: string[];
  cases: { name: string; contents: string }[];
}

function readJSON<T>(name: string): T {
  return JSON.parse(readFileSync(join(TESTDATA, name), "utf-8")) as T;
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return out;
}

const seconds = (s: string): number => Date.parse(s) / 1000;

describe("anchors.json", () => {
  for (const c of readJSON<{ cases: AnchorCase[] }>("anchors.json").cases) {
    it(c.name, async () => {
      const now = seconds(c.now);
      let stage: "none" | "verify" | "validate" = "none";
      try {
        const license = await verifyActivationAt(
          c.master_public_keys_hex.map(hexToBytes),
          c.token,
          c.chain,
          now,
        );
        try {
          validateAt(license, c.machine_id, now);
        } catch (e) {
          if (!(e instanceof ValidateError)) throw e;
          stage = "validate";
        }
      } catch (e) {
        if (!(e instanceof VerifyError)) throw e;
        stage = "verify";
      }
      expect(stage === "none" ? "accept" : "reject").toBe(c.expect);
      expect(stage).toBe(c.expect_stage);
    });
  }
});

describe("cache_files.json", () => {
  const v = readJSON<CacheFiles>("cache_files.json");
  const masterPubs = v.master_public_keys_hex.map(hexToBytes);
  const dir = mkdtempSync(join(tmpdir(), "latte-cache-files-"));

  for (const c of v.cases) {
    it(c.name, async () => {
      const path = join(dir, `${c.name}.json`);
      writeFileSync(path, c.contents);
      const storage = await resolveStorage("pk_test_cachefiles", { path });
      const cached = await storage!.load();
      if (cached === null) return;
      await expect(
        verifyActivationAt(masterPubs, cached.token, cached.chain, seconds(v.now)),
      ).rejects.toBeInstanceOf(VerifyError);
    });
  }
});
