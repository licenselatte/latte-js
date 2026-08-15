/**
 * Sdk: activates and renews licenses over the network, with an optional
 * cache (localStorage in a browser, a JSON file in Node/Electron main) so
 * repeat launches don't need a network call.
 *
 * The network calls run on the global `fetch` (Node 18+, browsers,
 * Electron) — no dependency needed. Caching auto-detects its backend (see
 * storage.ts) and needs no dependency either. Neither is behind a build
 * flag the way it would be in a compiled language; `Config.cache = false`
 * skips storage entirely (a sandboxed environment with no
 * filesystem/localStorage, for instance). There's no equivalent toggle for
 * the network calls, since without them Sdk has nothing left to do — use
 * verify.verifyActivationAt/validate.validateAt directly if you want to
 * supply your own HTTP client instead.
 *
 * activate/renew always go over the network on a cache miss; there's no
 * background renewal here — call renew yourself on whatever schedule fits
 * your application.
 */

import { baseUrlFor, parseAppId } from "./appid.js";
import type { CertChain } from "./domain.js";
import {
  HardExpiredError,
  InvalidKeyError,
  InvalidProjectKeyError,
  LicenseExpiredError,
  LicenseNotFoundError,
  NetworkError,
  NotActivatedError,
  SeatLimitError,
  ServerError,
  ValidateError,
  VerifyError,
} from "./errors.js";
import { sanitizeKey, validateKey } from "./key.js";
import { checkLicenseAt, type PublicLicense } from "./license.js";
import { resolveStorage, type CacheConfig, type Storage } from "./storage.js";

// The Ed25519 public key used to verify every certificate chain. This is a
// public key, not a secret — it's meant to be embedded in every SDK.
const MASTER_PUBLIC_KEY_HEX = "6773cdfdfb7fc44f13f097449b715e7147a2d73f525d9f09a8d25229e458a2fb";

const DEFAULT_TIMEOUT_MS = 30_000;

const INVALIDATING_ERRORS = [LicenseNotFoundError, LicenseExpiredError, InvalidProjectKeyError];

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

const MASTER_PUBLIC_KEY = hexToBytes(MASTER_PUBLIC_KEY_HEX);

/** Configuration for Sdk. */
export interface Config {
  /** `pk_{env}_{32-char key}`, shown in the LicenseLatte dashboard. */
  readonly appId: string;
  /** Request timeout for activate/renew, in milliseconds. Defaults to 30s. */
  readonly timeoutMs?: number;
  /**
   * Override the API base URL that `appId`'s environment would otherwise
   * select. Useful for routing through a corporate proxy/self-hosted
   * relay, or for pointing tests at a mock server. Omit to use the
   * environment default.
   */
  readonly baseUrl?: string;
  /**
   * Cache config. `true` (the default) auto-detects a backend —
   * `window.localStorage` in a browser, a JSON file under the OS config
   * directory in Node/Electron main. `false` disables caching entirely.
   * `{ path }` forces the Node/Electron-main file backend at an exact
   * path; ignored (harmlessly) if the browser backend is what's selected.
   */
  readonly cache?: CacheConfig;
}

interface TokenResponse {
  readonly token?: string;
  readonly chain?: Partial<CertChain>;
}

interface ErrorResponse {
  readonly error?: string;
}

/**
 * Activates and renews licenses over the network, with an optional local
 * cache so a valid activation survives across restarts without a network
 * round trip.
 */
export class Sdk {
  private readonly baseUrl: string;
  private readonly appId: string;
  private readonly appKey: string;
  private readonly timeoutMs: number;
  private readonly storage: Promise<Storage | null>;

  constructor(config: Config) {
    const parsed = parseAppId(config.appId); // throws an AppIdError subclass

    this.baseUrl = config.baseUrl ?? baseUrlFor(parsed.env);
    this.appId = config.appId;
    this.appKey = parsed.key;
    this.timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.storage = resolveStorage(parsed.key, config.cache ?? true);
  }

  /**
   * Activates `licenseKey` for `machineId`.
   *
   * The key is sanitized then format/checksum-validated against this
   * SDK's own project key first — a mismatch throws InvalidKeyError and
   * never reaches the network or the cache.
   *
   * With caching available, a cached activation for this exact
   * (sanitized) key is tried first; if it's still valid, it's returned
   * without a network call. Any other outcome — no cache, a cache for a
   * different key, or a cached token that fails verification/validation —
   * falls through to a network call, and a successful result is written
   * back to the cache. A server response that fails local
   * verification/validation throws ServerError, not one of the sentinel
   * errors (those are reserved for the server's HTTP status code itself).
   */
  async activate(licenseKey: string, machineId: string): Promise<PublicLicense> {
    const sanitized = sanitizeKey(licenseKey);
    this.validateLicenseKey(sanitized);

    const cached = await this.cachedLicense(machineId);
    if (cached !== null && cached.key === sanitized) {
      return cached;
    }

    const { token, chain } = await this.postAndHandleInvalidation("/v1/activate", {
      project_key: this.appId,
      license_key: sanitized,
      machine_id: machineId,
    });
    const lic = await this.verifyAndValidate(token, chain, machineId);
    await this.saveToCache(token, chain);
    return lic;
  }

  /**
   * Renews an existing activation.
   *
   * Unlike activate, this does not re-check the license-key format
   * against the project key — it trusts the caller already holds a valid
   * activationId (from a prior activate call's
   * PublicLicense.activationId). Also unlike activate's request, the wire
   * request here carries no project_key field. On success, and with
   * caching available, the renewed token replaces whatever was previously
   * cached.
   */
  async renew(
    activationId: string,
    licenseKey: string,
    machineId: string,
  ): Promise<PublicLicense> {
    const { token, chain } = await this.postAndHandleInvalidation("/v1/renew", {
      activation_id: activationId,
      license_key: licenseKey,
      machine_id: machineId,
    });
    const lic = await this.verifyAndValidate(token, chain, machineId);
    await this.saveToCache(token, chain);
    return lic;
  }

  /**
   * Reads the cached activation for `machineId` without making a network
   * call.
   *
   * Throws LicenseExpiredError if there's a cached token but it's past
   * its hard expiry, and NotActivatedError for every other reason there's
   * no currently-usable cached license: caching unavailable, nothing
   * cached, a cache that fails signature verification (corrupt, tampered,
   * or simply not something this key can verify), or one that's valid but
   * rejected for a different reason (out of its grace window, too old, or
   * for a different machine ID) — those don't get their own error because
   * the caller's correct response to all of them is the same: activate
   * again.
   */
  async check(machineId: string): Promise<PublicLicense> {
    const storage = await this.storage;
    const cached = await storage?.load();
    if (cached === undefined || cached === null) {
      throw new NotActivatedError();
    }

    try {
      return await checkLicenseAt(
        MASTER_PUBLIC_KEY,
        cached.token,
        cached.chain,
        machineId,
        Date.now() / 1000,
      );
    } catch (e) {
      if (e instanceof HardExpiredError) {
        throw new LicenseExpiredError();
      }
      if (e instanceof VerifyError || e instanceof ValidateError) {
        throw new NotActivatedError();
      }
      throw e;
    }
  }

  /**
   * 30 chars after sanitizing (6-char short_id + 22 random + 2 checksum);
   * the short_id must equal the first 6 chars of this project's AppID key
   * segment, and the trailing 2 chars must be a valid checksum over the
   * 22 before them.
   */
  private validateLicenseKey(sanitized: string): void {
    if (
      sanitized.length !== 30 ||
      sanitized.slice(0, 6) !== this.appKey.slice(0, 6) ||
      !validateKey(sanitized.slice(6), 2)
    ) {
      throw new InvalidKeyError();
    }
  }

  private async cachedLicense(machineId: string): Promise<PublicLicense | null> {
    const storage = await this.storage;
    const cached = await storage?.load();
    if (cached === undefined || cached === null) {
      return null;
    }
    try {
      return await checkLicenseAt(
        MASTER_PUBLIC_KEY,
        cached.token,
        cached.chain,
        machineId,
        Date.now() / 1000,
      );
    } catch {
      return null;
    }
  }

  private async saveToCache(token: string, chain: CertChain): Promise<void> {
    const storage = await this.storage;
    // Best-effort: a local write failure shouldn't turn a successful
    // network activation into an error (the backends already swallow
    // their own I/O errors; this just guards the "no backend" case).
    await storage?.save(token, chain);
  }

  private async clearCache(): Promise<void> {
    const storage = await this.storage;
    await storage?.clear();
  }

  private async verifyAndValidate(
    token: string,
    chain: CertChain,
    machineId: string,
  ): Promise<PublicLicense> {
    try {
      return await checkLicenseAt(MASTER_PUBLIC_KEY, token, chain, machineId, Date.now() / 1000);
    } catch (e) {
      if (e instanceof VerifyError || e instanceof ValidateError) {
        throw new ServerError(`server returned invalid token: ${e.message}`);
      }
      throw e;
    }
  }

  /**
   * Calls post, and on a response that unambiguously means "this
   * activation no longer exists" (not found / expired / wrong project
   * key), drops any cached token for this project too — otherwise a later
   * check/activate fast path would keep treating a server-revoked license
   * as still active until it independently expires.
   */
  private async postAndHandleInvalidation(
    path: string,
    body: Record<string, string>,
  ): Promise<{ token: string; chain: CertChain }> {
    try {
      return await this.post(path, body);
    } catch (e) {
      if (INVALIDATING_ERRORS.some((cls) => e instanceof cls)) {
        await this.clearCache();
      }
      throw e;
    }
  }

  /** Shared POST helper for activate/renew. */
  private async post(
    path: string,
    body: Record<string, string>,
  ): Promise<{ token: string; chain: CertChain }> {
    let resp: Response;
    try {
      resp = await fetch(this.baseUrl + path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (e) {
      throw new NetworkError(e instanceof Error ? e.message : String(e));
    }

    if (!resp.ok) {
      let msg = "";
      try {
        const errBody = (await resp.json()) as ErrorResponse;
        msg = errBody.error ?? "";
      } catch {
        // Non-JSON error body: fall through with an empty message.
      }
      switch (resp.status) {
        case 404:
          throw new LicenseNotFoundError();
        case 403:
          throw new LicenseExpiredError();
        case 409:
          throw new SeatLimitError();
        case 401:
          throw new InvalidProjectKeyError();
        default:
          throw new ServerError(msg || `HTTP ${resp.status}`);
      }
    }

    let data: TokenResponse;
    try {
      data = (await resp.json()) as TokenResponse;
    } catch (e) {
      throw new ServerError(`decode response: ${e instanceof Error ? e.message : String(e)}`);
    }

    const token = data.token ?? "";
    const chain = data.chain;
    if (!token) {
      throw new ServerError("server returned empty token");
    }
    if (!chain?.daily || !chain?.project || !chain?.submaster) {
      throw new ServerError("server returned empty chain");
    }

    return { token, chain: { submaster: chain.submaster, project: chain.project, daily: chain.daily } };
  }
}
