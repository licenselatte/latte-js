/**
 * Tests for the admin client against a mock fetch: every method's verb, path,
 * auth header, body and query, 204/202 handling, and error mapping.
 */

import { describe, expect, it } from "vitest";
import { AdminApiError, AdminClient } from "../src/admin.js";

interface Seen {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string | undefined;
}

function mock(status: number, body: unknown = undefined) {
  const seen: Seen[] = [];
  const fetchFn = (async (url: string, init: RequestInit) => {
    seen.push({
      url,
      method: init.method ?? "GET",
      headers: init.headers as Record<string, string>,
      body: init.body as string | undefined,
    });
    const text = body === undefined ? "" : JSON.stringify(body);
    return new Response(status === 204 ? null : text, { status });
  }) as unknown as typeof fetch;
  const client = new AdminClient("llk_test_secret", {
    baseUrl: "https://api.test/v1/",
    fetch: fetchFn,
  });
  return { client, seen };
}

const lic = {
  id: "i",
  project_id: "p",
  policy_id: "pol",
  license_key: "AB-CD",
  status: "suspended",
  expires_at: null,
  metadata: {},
  client_metadata: {},
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
  future_field: { x: true },
};

function expectCall(s: Seen | undefined, method: string, url: string) {
  expect(s?.method).toBe(method);
  expect(s?.url).toBe(`https://api.test/v1${url}`);
  expect(s?.headers.Authorization).toBe("Bearer llk_test_secret");
}

describe("AdminClient", () => {
  it("requires an API key", () => {
    expect(() => new AdminClient("")).toThrow(TypeError);
  });

  it("issues a license and keeps unknown fields", async () => {
    const { client, seen } = mock(201, lic);
    const l = await client.issueLicense({
      policy_id: "pol",
      customer_email: "b@example.com",
      metadata: { order: "1" },
    });
    expectCall(seen[0], "POST", "/licenses");
    expect(seen[0]?.headers["Content-Type"]).toBe("application/json");
    expect(JSON.parse(seen[0]?.body ?? "")).toEqual({
      policy_id: "pol",
      customer_email: "b@example.com",
      metadata: { order: "1" },
    });
    expect(l.license_key).toBe("AB-CD");
    expect(l.future_field).toEqual({ x: true });
  });

  it("lists licenses with query params, and none when empty", async () => {
    const { client, seen } = mock(200, { licenses: [lic], total: 7 });
    const out = await client.listLicenses({
      limit: 10,
      offset: 20,
      customer_email: "a+b@example.com",
      status: "active",
    });
    expectCall(
      seen[0],
      "GET",
      "/licenses?limit=10&offset=20&customer_email=a%2Bb%40example.com&status=active",
    );
    expect(seen[0]?.body).toBeUndefined();
    expect(out.total).toBe(7);
    await client.listLicenses();
    expectCall(seen[1], "GET", "/licenses");
  });

  it("escapes the license key in the path", async () => {
    const { client, seen } = mock(200, lic);
    await client.getLicense("AB/CD EF");
    expectCall(seen[0], "GET", "/licenses/AB%2FCD%20EF");
  });

  it("updates with wholesale maps, a Date expiry, or a null expiry", async () => {
    const { client, seen } = mock(200, lic);
    await client.updateLicense("K", {
      metadata: { a: 1 },
      client_metadata: {},
      expires_at: new Date("2027-01-02T03:04:05Z"),
    });
    expectCall(seen[0], "PATCH", "/licenses/K");
    expect(JSON.parse(seen[0]?.body ?? "")).toEqual({
      metadata: { a: 1 },
      client_metadata: {},
      expires_at: "2027-01-02T03:04:05.000Z",
    });
    await client.updateLicense("K", { expires_at: null });
    expect(seen[1]?.body).toBe('{"expires_at":null}');
    await client.updateLicense("K", {});
    expect(seen[2]?.body).toBe("{}");
  });

  it("revokes and releases on 204", async () => {
    const { client, seen } = mock(204);
    await expect(client.revokeLicense("K")).resolves.toBeUndefined();
    expectCall(seen[0], "DELETE", "/licenses/K");
    await expect(client.releaseActivation("K", "act-1")).resolves.toBeUndefined();
    expectCall(seen[1], "DELETE", "/licenses/K/activations/act-1");
    expect(seen[1]?.body).toBeUndefined();
    expect(seen[1]?.headers["Content-Type"]).toBeUndefined();
  });

  it("suspends and reinstates", async () => {
    const { client, seen } = mock(200, lic);
    expect((await client.suspendLicense("K")).id).toBe("i");
    expectCall(seen[0], "POST", "/licenses/K/suspend");
    await client.reinstateLicense("K");
    expectCall(seen[1], "POST", "/licenses/K/reinstate");
  });

  it("resends on 202", async () => {
    const { client, seen } = mock(202, { status: "queued" });
    await expect(client.resendLicenseEmail("K")).resolves.toBeUndefined();
    expectCall(seen[0], "POST", "/licenses/K/resend");
  });

  it("lists activations", async () => {
    const act = {
      id: "a1",
      status: "active",
      machine_id_hash: "h",
      activated_at: "2026-01-01T00:00:00Z",
      last_renewed_at: null,
      deactivated_at: null,
      seat_held_until: null,
      sdk: { language: "go" },
      metadata: {},
      extra: 1,
    };
    const { client, seen } = mock(200, { activations: [act] });
    const acts = await client.listActivations("K");
    expectCall(seen[0], "GET", "/licenses/K/activations");
    expect(acts[0]?.extra).toBe(1);
    expect(acts[0]?.last_renewed_at).toBeNull();
  });

  it("lists policies", async () => {
    const { client, seen } = mock(200, { policies: [{ id: "p1", name: "Pro" }] });
    const ps = await client.listPolicies();
    expectCall(seen[0], "GET", "/policies");
    expect(ps[0]?.id).toBe("p1");
  });

  it.each([400, 401, 403, 404, 409, 429])("maps status %i to AdminApiError", async (status) => {
    const { client } = mock(status, {
      error: "nope",
      code: "plan_license_limit_reached",
    });
    const err = await client.getLicense("K").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AdminApiError);
    expect(err).toMatchObject({
      status,
      message: "nope",
      code: "plan_license_limit_reached",
    });
  });

  it("falls back to the status text when the error body is not JSON", async () => {
    const fetchFn = (async () =>
      new Response("<html>", { status: 502, statusText: "Bad Gateway" })) as unknown as typeof fetch;
    const client = new AdminClient("k", { fetch: fetchFn });
    await expect(client.revokeLicense("K")).rejects.toMatchObject({
      status: 502,
      message: "Bad Gateway",
    });
  });

  it("does not retry a failed write", async () => {
    const { client, seen } = mock(429, { error: "slow down" });
    await expect(client.issueLicense({ policy_id: "p" })).rejects.toBeInstanceOf(AdminApiError);
    expect(seen).toHaveLength(1);
  });

  it("uses the default base URL and the global fetch", async () => {
    const urls: string[] = [];
    const orig = globalThis.fetch;
    globalThis.fetch = (async (url: string) => {
      urls.push(url);
      return new Response(JSON.stringify({ policies: [] }), { status: 200 });
    }) as unknown as typeof fetch;
    try {
      await new AdminClient("k").listPolicies();
    } finally {
      globalThis.fetch = orig;
    }
    expect(urls).toEqual(["https://api.licenselatte.com/v1/policies"]);
  });
});
