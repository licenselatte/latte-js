import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CertChain } from "../src/domain.js";
import { resolveStorage } from "../src/storage.js";

function chain(): CertChain {
  return { submaster: "s", project: "p", daily: "d" };
}

describe("Node backend", () => {
  let dir: string;

  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "latte-storage-test-"));
  });

  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  it("round-trips through save and load", async () => {
    const filePath = path.join(dir, "cache.json");
    const storage = await resolveStorage("proj", { path: filePath });
    expect(storage).not.toBeNull();

    await storage?.save("the-token", chain());
    const loaded = await storage?.load();

    expect(loaded?.token).toBe("the-token");
    expect(loaded?.chain).toEqual(chain());
  });

  it("writes the documented snake_case JSON shape", async () => {
    const filePath = path.join(dir, "cache.json");
    const storage = await resolveStorage("proj", { path: filePath });
    await storage?.save("the-token", chain());

    const raw = JSON.parse(await fs.readFile(filePath, "utf8")) as Record<string, unknown>;
    expect(Object.keys(raw).sort()).toEqual(
      ["daily", "project", "submaster", "timestamp", "token"].sort(),
    );
  });

  it("returns null for a missing file", async () => {
    const storage = await resolveStorage("proj", { path: path.join(dir, "missing.json") });
    expect(await storage?.load()).toBeNull();
  });

  it("returns null for corrupt JSON", async () => {
    const filePath = path.join(dir, "cache.json");
    await fs.writeFile(filePath, "not json");
    const storage = await resolveStorage("proj", { path: filePath });
    expect(await storage?.load()).toBeNull();
  });

  it("creates missing parent directories", async () => {
    const filePath = path.join(dir, "nested", "deeper", "cache.json");
    const storage = await resolveStorage("proj", { path: filePath });
    await storage?.save("the-token", chain());
    expect(await storage?.load()).not.toBeNull();
  });

  it("overwrites an existing file without leaving a temp file behind", async () => {
    const filePath = path.join(dir, "cache.json");
    const storage = await resolveStorage("proj", { path: filePath });
    await storage?.save("first", chain());
    await storage?.save("second", chain());

    expect((await storage?.load())?.token).toBe("second");
    await expect(fs.access(`${filePath}.tmp`)).rejects.toThrow();
  });

  it("clear removes the file", async () => {
    const filePath = path.join(dir, "cache.json");
    const storage = await resolveStorage("proj", { path: filePath });
    await storage?.save("the-token", chain());

    await storage?.clear();
    expect(await storage?.load()).toBeNull();
  });

  it("clear on a missing file is not an error", async () => {
    const storage = await resolveStorage("proj", { path: path.join(dir, "missing.json") });
    await expect(storage?.clear()).resolves.toBeUndefined();
  });

  it("resolves a default path under the OS config directory when no override is given", async () => {
    const storage = await resolveStorage("some-project-key", undefined);
    // Just confirm a Node-backed storage was resolved at all (this test
    // process has no window/localStorage) — the exact default path is an
    // OS-specific implementation detail, not asserted here.
    expect(storage).not.toBeNull();
  });
});

describe("resolveStorage", () => {
  it("returns null when caching is disabled", async () => {
    expect(await resolveStorage("proj", false)).toBeNull();
  });

  it("prefers the browser backend when window.localStorage is present", async () => {
    const store = new Map<string, string>();
    vi.stubGlobal("window", {
      localStorage: {
        getItem: (k: string) => store.get(k) ?? null,
        setItem: (k: string, v: string) => void store.set(k, v),
        removeItem: (k: string) => void store.delete(k),
      },
    });

    try {
      const storage = await resolveStorage("proj", true);
      await storage?.save("the-token", chain());
      expect(store.has("licenselatte:proj")).toBe(true);
      expect((await storage?.load())?.token).toBe("the-token");
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("browser backend round-trips and clears", async () => {
    const store = new Map<string, string>();
    vi.stubGlobal("window", {
      localStorage: {
        getItem: (k: string) => store.get(k) ?? null,
        setItem: (k: string, v: string) => void store.set(k, v),
        removeItem: (k: string) => void store.delete(k),
      },
    });

    try {
      const storage = await resolveStorage("proj", true);
      await storage?.save("the-token", chain());
      await storage?.clear();
      expect(await storage?.load()).toBeNull();
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("browser backend returns null for a corrupt stored value", async () => {
    const store = new Map<string, string>([["licenselatte:proj", "not json"]]);
    vi.stubGlobal("window", {
      localStorage: {
        getItem: (k: string) => store.get(k) ?? null,
        setItem: (k: string, v: string) => void store.set(k, v),
        removeItem: (k: string) => void store.delete(k),
      },
    });

    try {
      const storage = await resolveStorage("proj", true);
      expect(await storage?.load()).toBeNull();
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("ignores a Node-only path override when the browser backend is selected", async () => {
    const store = new Map<string, string>();
    vi.stubGlobal("window", {
      localStorage: {
        getItem: (k: string) => store.get(k) ?? null,
        setItem: (k: string, v: string) => void store.set(k, v),
        removeItem: (k: string) => void store.delete(k),
      },
    });

    try {
      const storage = await resolveStorage("proj", { path: "/should/be/ignored.json" });
      await storage?.save("the-token", chain());
      expect(store.has("licenselatte:proj")).toBe(true);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
