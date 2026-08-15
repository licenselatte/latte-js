/**
 * Tests for Sdk.activate/Sdk.renew/Sdk.check against a stubbed global
 * `fetch`, covering:
 *   - the exact wire request shape for activate/renew
 *   - status-code -> sentinel error mapping
 *   - transport-level failure -> NetworkError
 *   - malformed/empty response bodies -> ServerError
 *   - bad license-key format short-circuiting before any network call
 *   - the cache: falling through when it's unreadable/unverifiable, not
 *     writing a token that failed verification, and clearing it when the
 *     server says the activation no longer exists
 *
 * What this file deliberately does *not* test: a full activate() success
 * path returning a real PublicLicense, or check()'s success/expired
 * branches. Sdk verifies against the hardcoded production master public
 * key; the matching private key lives only on LicenseLatte's real backend,
 * so nothing in this repo can produce a token this package would actually
 * accept. The crypto pipeline itself (checkLicenseAt and everything it
 * calls) is already exhaustively covered by tests/fixtures.test.ts against
 * real (test) key material — this file only needs to prove the
 * network/cache plumbing correctly feeds a syntactically-valid response
 * into that pipeline, which the "server-returned token fails verification"
 * test below confirms end to end (it just can't also assert *acceptance*,
 * for the reason above). tests/storage.test.ts separately covers the cache
 * backends' format/atomicity in isolation, with no key material involved
 * at all.
 */

import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CertChain } from "../src/domain.js";
import {
  InvalidKeyError,
  InvalidProjectKeyError,
  LicenseExpiredError,
  LicenseNotFoundError,
  NetworkError,
  NotActivatedError,
  SeatLimitError,
  ServerError,
} from "../src/errors.js";
import { Sdk } from "../src/http.js";
import { resolveStorage } from "../src/storage.js";

// A valid AppID (pk_test_{28-char data}{4-char checksum}) and a matching
// license key ({6-char short_id}{22 random}{2-char checksum}), computed
// against the checksum algorithm in src/key.ts.
const TEST_APP_ID = "pk_test_AHAK85389VQYXYB6S4BW66SKE53TWVTS";
const TEST_LICENSE_KEY = "AHAK85BCDEFGHJKMNPQRSTVWXYZ00Z";
const TEST_MACHINE_ID = "test-machine-id";
const BASE_URL = "https://mock.invalid";

let dir: string;

beforeEach(async () => {
  dir = await fs.mkdtemp(path.join(os.tmpdir(), "latte-http-test-"));
});

afterEach(async () => {
  vi.unstubAllGlobals();
  await fs.rm(dir, { recursive: true, force: true });
});

function cachePath(): string {
  return path.join(dir, "cache.json");
}

function makeSdk(overrideCachePath = cachePath()): Sdk {
  return new Sdk({ appId: TEST_APP_ID, baseUrl: BASE_URL, cache: { path: overrideCachePath } });
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

async function seedCache(filePath: string, token: string, chain: CertChain): Promise<void> {
  const storage = await resolveStorage("unused", { path: filePath });
  await storage?.save(token, chain);
}

const GARBAGE_CHAIN: CertChain = { submaster: "s", project: "p", daily: "d" };

describe("Sdk.activate", () => {
  it("sends the documented request shape", async () => {
    const fetchMock = vi.fn(async (url: string | URL, init?: RequestInit) => {
      expect(url).toBe(`${BASE_URL}/v1/activate`);
      expect(JSON.parse(init?.body as string)).toEqual({
        project_key: TEST_APP_ID,
        license_key: TEST_LICENSE_KEY,
        machine_id: TEST_MACHINE_ID,
      });
      return jsonResponse({
        token: "not-a-real-jwt",
        activation_id: "11111111-1111-1111-1111-111111111111",
        chain: { submaster: "s", project: "p", daily: "d" },
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    const sdk = makeSdk();
    await expect(sdk.activate(TEST_LICENSE_KEY, TEST_MACHINE_ID)).rejects.toThrow(ServerError);
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("surfaces a server-returned token that fails verification as ServerError", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonResponse({
          token: "not-a-real-jwt",
          activation_id: "11111111-1111-1111-1111-111111111111",
          chain: { submaster: "s", project: "p", daily: "d" },
        }),
      ),
    );

    const sdk = makeSdk();
    await expect(sdk.activate(TEST_LICENSE_KEY, TEST_MACHINE_ID)).rejects.toThrow(
      /^server returned invalid token:/,
    );
  });

  it.each([
    [404, LicenseNotFoundError],
    [403, LicenseExpiredError],
    [409, SeatLimitError],
    [401, InvalidProjectKeyError],
  ])("maps status %i to the documented sentinel", async (status, expected) => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse({ error: "nope" }, status)),
    );

    const sdk = makeSdk();
    await expect(sdk.activate(TEST_LICENSE_KEY, TEST_MACHINE_ID)).rejects.toThrow(expected);
  });

  it("maps an unmapped status code to ServerError with the server message", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse({ error: "something broke" }, 500)),
    );

    const sdk = makeSdk();
    await expect(sdk.activate(TEST_LICENSE_KEY, TEST_MACHINE_ID)).rejects.toThrow(
      "something broke",
    );
  });

  it("treats an empty token in a 200 response as a ServerError", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonResponse({
          token: "",
          activation_id: "11111111-1111-1111-1111-111111111111",
          chain: { submaster: "s", project: "p", daily: "d" },
        }),
      ),
    );

    const sdk = makeSdk();
    await expect(sdk.activate(TEST_LICENSE_KEY, TEST_MACHINE_ID)).rejects.toThrow(
      "server returned empty token",
    );
  });

  it("maps a transport-level failure to NetworkError", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new TypeError("fetch failed");
      }),
    );

    const sdk = makeSdk();
    await expect(sdk.activate(TEST_LICENSE_KEY, TEST_MACHINE_ID)).rejects.toThrow(NetworkError);
  });

  it("rejects a bad license-key format without ever calling fetch", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const sdk = makeSdk();
    await expect(sdk.activate("too-short", TEST_MACHINE_ID)).rejects.toThrow(InvalidKeyError);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects a license key whose short_id doesn't match this project's app key", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const sdk = makeSdk();
    // Right length and checksum, but a short_id belonging to a different
    // project.
    const wrongProjectKey = "ZZZZZZBCDEFGHJKMNPQRSTVWXYZ00Z";
    await expect(sdk.activate(wrongProjectKey, TEST_MACHINE_ID)).rejects.toThrow(InvalidKeyError);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("Sdk.renew", () => {
  it("sends the documented request shape without project_key", async () => {
    const activationId = "11111111-1111-1111-1111-111111111111";
    const fetchMock = vi.fn(async (url: string | URL, init?: RequestInit) => {
      expect(url).toBe(`${BASE_URL}/v1/renew`);
      expect(JSON.parse(init?.body as string)).toEqual({
        activation_id: activationId,
        license_key: TEST_LICENSE_KEY,
        machine_id: TEST_MACHINE_ID,
      });
      return jsonResponse({
        token: "not-a-real-jwt",
        activation_id: activationId,
        chain: { submaster: "s", project: "p", daily: "d" },
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    const sdk = makeSdk();
    await expect(sdk.renew(activationId, TEST_LICENSE_KEY, TEST_MACHINE_ID)).rejects.toThrow(
      ServerError,
    );
    expect(fetchMock).toHaveBeenCalledOnce();
  });
});

describe("cache", () => {
  it("check reports NotActivatedError when nothing is cached", async () => {
    const sdk = makeSdk();
    await expect(sdk.check(TEST_MACHINE_ID)).rejects.toThrow(NotActivatedError);
  });

  it("check reports NotActivatedError for a cache that fails verification", async () => {
    const filePath = cachePath();
    await seedCache(filePath, "not-a-real-jwt", GARBAGE_CHAIN);

    const sdk = makeSdk(filePath);
    await expect(sdk.check(TEST_MACHINE_ID)).rejects.toThrow(NotActivatedError);
  });

  it("activate falls through to the network when the cache is unverifiable", async () => {
    const filePath = cachePath();
    await seedCache(filePath, "not-a-real-jwt", GARBAGE_CHAIN);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse({ error: "nope" }, 404)),
    );

    const sdk = makeSdk(filePath);
    // LicenseNotFound only happens on the network path — reaching it
    // proves the unverifiable cache entry didn't short-circuit into a
    // false "success" or a cache-specific error.
    await expect(sdk.activate(TEST_LICENSE_KEY, TEST_MACHINE_ID)).rejects.toThrow(
      LicenseNotFoundError,
    );
  });

  it("activate does not cache a server response that fails verification", async () => {
    const filePath = cachePath();
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonResponse({
          token: "not-a-real-jwt",
          activation_id: "11111111-1111-1111-1111-111111111111",
          chain: { submaster: "s", project: "p", daily: "d" },
        }),
      ),
    );

    const sdk = makeSdk(filePath);
    await expect(sdk.activate(TEST_LICENSE_KEY, TEST_MACHINE_ID)).rejects.toThrow(ServerError);

    const storage = await resolveStorage("unused", { path: filePath });
    expect(await storage?.load()).toBeNull();
  });

  it("activate clears an existing cache entry on license-not-found", async () => {
    const filePath = cachePath();
    await seedCache(filePath, "not-a-real-jwt", GARBAGE_CHAIN);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse({ error: "nope" }, 404)),
    );

    const sdk = makeSdk(filePath);
    await expect(sdk.activate(TEST_LICENSE_KEY, TEST_MACHINE_ID)).rejects.toThrow(
      LicenseNotFoundError,
    );

    const storage = await resolveStorage("unused", { path: filePath });
    expect(await storage?.load()).toBeNull();
  });

  it("renew clears an existing cache entry on license-expired", async () => {
    const filePath = cachePath();
    await seedCache(filePath, "not-a-real-jwt", GARBAGE_CHAIN);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse({ error: "nope" }, 403)),
    );

    const sdk = makeSdk(filePath);
    const activationId = "11111111-1111-1111-1111-111111111111";
    await expect(
      sdk.renew(activationId, TEST_LICENSE_KEY, TEST_MACHINE_ID),
    ).rejects.toThrow(LicenseExpiredError);

    const storage = await resolveStorage("unused", { path: filePath });
    expect(await storage?.load()).toBeNull();
  });

  it("activate leaves an existing cache entry alone on an unrelated server error", async () => {
    const filePath = cachePath();
    await seedCache(filePath, "not-a-real-jwt", GARBAGE_CHAIN);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse({ error: "broke" }, 500)),
    );

    const sdk = makeSdk(filePath);
    await expect(sdk.activate(TEST_LICENSE_KEY, TEST_MACHINE_ID)).rejects.toThrow(ServerError);

    // A 500 doesn't mean the activation is gone, just that something else
    // went wrong — an existing cache entry (unverifiable or not)
    // shouldn't be touched over it.
    const storage = await resolveStorage("unused", { path: filePath });
    expect(await storage?.load()).not.toBeNull();
  });

  it("cache: false disables caching for both activate and check", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse({ error: "nope" }, 404)),
    );
    const sdk = new Sdk({ appId: TEST_APP_ID, baseUrl: BASE_URL, cache: false });

    await expect(sdk.check(TEST_MACHINE_ID)).rejects.toThrow(NotActivatedError);
    await expect(sdk.activate(TEST_LICENSE_KEY, TEST_MACHINE_ID)).rejects.toThrow(
      LicenseNotFoundError,
    );
  });
});
