import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MachineIdError } from "../src/errors.js";
import { Sdk } from "../src/http.js";
import {
  BROWSER_MACHINE_ID_KEY,
  parseIoregOutput,
  parseRegQueryOutput,
  protectMachineId,
  resolveMachineId,
} from "../src/machineid.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

interface MachineIdCase {
  raw_machine_id: string;
  app_id: string;
  expect_machine_id: string;
}

const vectors = JSON.parse(
  readFileSync(join(__dirname, "..", "testdata", "machine_id.json"), "utf8"),
) as { cases: MachineIdCase[] };

const APP_ID = "pk_test_AHAK85389VQYXYB6S4BW66SKE53TWVTS";
const HEX64 = /^[0-9a-f]{64}$/;

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("protectMachineId", () => {
  it("has vectors to run", () => {
    expect(vectors.cases.length).toBeGreaterThan(0);
  });

  it.each(vectors.cases)("derives $expect_machine_id", async (c) => {
    expect(await protectMachineId(c.raw_machine_id, c.app_id)).toBe(c.expect_machine_id);
  });
});

describe("parseIoregOutput", () => {
  it("extracts IOPlatformUUID", () => {
    const out = [
      "+-o MacBookPro18,3  <class IOPlatformExpertDevice, id 0x100000202, registered, matched, active, busy 0 (0 ms), retain 34>",
      "    {",
      '      "IOPlatformSerialNumber" = "C02ABCDEFGH"',
      '      "IOPlatformUUID" = "4C4C4544-0042-3510-8051-B4C04F4B4E32"',
      '      "model" = <"MacBookPro18,3">',
      "    }",
      "",
    ].join("\n");
    expect(parseIoregOutput(out)).toBe("4C4C4544-0042-3510-8051-B4C04F4B4E32");
  });

  it("returns empty when the key is missing", () => {
    expect(parseIoregOutput('      "IOPlatformSerialNumber" = "C02ABCDEFGH"\n')).toBe("");
  });
});

describe("parseRegQueryOutput", () => {
  it("extracts MachineGuid from CRLF output", () => {
    const out =
      "\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\r\n" +
      "    MachineGuid    REG_SZ    a1b2c3d4-e5f6-4711-8899-aabbccddeeff\r\n\r\n";
    expect(parseRegQueryOutput(out)).toBe("a1b2c3d4-e5f6-4711-8899-aabbccddeeff");
  });

  it("returns empty when the value is missing", () => {
    const out = "ERROR: The system was unable to find the specified registry key or value.\r\n";
    expect(parseRegQueryOutput(out)).toBe("");
  });
});

function stubLocalStorage(store: Map<string, string>): void {
  vi.stubGlobal("window", {
    localStorage: {
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => void store.set(k, v),
      removeItem: (k: string) => void store.delete(k),
    },
  });
}

describe("resolveMachineId", () => {
  it("hashes a configured raw ID and ignores the platform", async () => {
    stubLocalStorage(new Map());
    expect(await resolveMachineId(APP_ID, "raw")).toBe(await protectMachineId("raw", APP_ID));
  });

  it("persists a random raw ID in the browser and reuses it", async () => {
    const store = new Map<string, string>();
    stubLocalStorage(store);

    const first = await resolveMachineId(APP_ID);
    const raw = store.get(BROWSER_MACHINE_ID_KEY);
    expect(raw).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    expect(first).toBe(await protectMachineId(raw as string, APP_ID));
    expect(await resolveMachineId(APP_ID)).toBe(first);
    expect(store.size).toBe(1);
  });

  it("starts a new machine once site data is cleared", async () => {
    const store = new Map<string, string>();
    stubLocalStorage(store);

    const first = await resolveMachineId(APP_ID);
    store.clear();
    expect(await resolveMachineId(APP_ID)).not.toBe(first);
  });

  it("throws MachineIdError when the browser ID cannot be persisted", async () => {
    vi.stubGlobal("window", {
      localStorage: {
        getItem: () => null,
        setItem: () => {
          throw new Error("quota exceeded");
        },
        removeItem: () => undefined,
      },
    });
    await expect(resolveMachineId(APP_ID)).rejects.toThrow(MachineIdError);
  });

  it("reads this host's platform ID in Node", async () => {
    expect(await resolveMachineId(APP_ID)).toMatch(HEX64);
  });
});

describe("Sdk.machineId", () => {
  it("returns the derived ID, computed once", async () => {
    const store = new Map<string, string>();
    stubLocalStorage(store);
    const sdk = new Sdk({ appId: APP_ID, cache: false });

    const id = await sdk.machineId();
    store.clear();
    expect(await sdk.machineId()).toBe(id);
    expect(id).toMatch(HEX64);
  });
});
