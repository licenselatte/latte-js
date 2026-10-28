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
 * activate/renew always go over the network on a cache miss. check renews a
 * cached token that is at least an hour old in the background, without
 * making the caller wait (see Sdk.check); renew is also there to call
 * yourself. deactivate, machines and renameMachine always go over the
 * network.
 */

import { baseUrlFor, parseAppId } from "./appid.js";
import type { CertChain } from "./domain.js";
import {
  DeactivationBlockedError,
  GraceExpiredError,
  HardExpiredError,
  InvalidKeyError,
  InvalidProjectKeyError,
  LicenseExpiredError,
  LicenseNotFoundError,
  LicenseTooOldError,
  NetworkError,
  NotActivatedError,
  SeatLimitError,
  ServerError,
  ValidateError,
  VerifyError,
} from "./errors.js";
import { normalizeKey, sanitizeKey } from "./key.js";
import { checkLicenseAt, toPublicLicense, type PublicLicense } from "./license.js";
import { defaultMachineName, resolveMachineId } from "./machineid.js";
import { resolveStorage, type CacheConfig, type Storage } from "./storage.js";
import { inGracePeriod, validateAt } from "./validate.js";
import { verifyActivationAt } from "./verify.js";
import { VERSION } from "./version.js";

// The Ed25519 master public keys a certificate chain may be rooted in. These
// are public keys, not secrets: they're meant to be embedded in every SDK. A
// chain is accepted if its submaster cert is signed by any one of them. Each
// root lives on its own YubiKey; the hex is the card's authentication key,
// the one it signs with.
const MASTER_PUBLIC_KEYS_HEX = [
  // Old root, YubiKey 32493801. Primary 49C1CA77D17984E0D25C0994D626409AD567D479.
  // Kept until the submaster cert it signed expires on 2026-12-11.
  "6773cdfdfb7fc44f13f097449b715e7147a2d73f525d9f09a8d25229e458a2fb",
  // root-a, YubiKey 40127477. Primary B89594D5DD7B9213E5FC7DC27FC9430452C9F38D,
  // auth subkey A53549AF5B5570F304D4342D702AEFFF07B512EF.
  "73358e45a5c77b7f7236d26f5a1756011b522d277bb19ac4869d2e88952705cd",
  // root-b, YubiKey 40127498. Primary A980BA5DD0B3831A4038D22C744D413D801A1AFA,
  // auth subkey B217F9743D6FD3EB21FF87D83752947C4AD9CC5E.
  "4f9369b8a4a0fd9be67cd403e4ed92e0d45609772659be4a066c1a9c4eff43fe",
  // root-c, YubiKey 40127484. Primary 7F3CC680FF472FCF9A351CAF8204C38EAF10DA14,
  // auth subkey 59282CA469B7E8168952E07476352E58361B3A92.
  "46d45bbc3280df763fcaf7a37055888eeefbb5781784c1f471f4f413d72b123f",
];

const DEFAULT_TIMEOUT_MS = 30_000;

// check starts a background renewal once the cached token is this old, and
// no more often than every MIN_RENEWAL_INTERVAL_MS.
const MIN_RENEWAL_AGE_SECS = 60 * 60;
const MIN_RENEWAL_INTERVAL_MS = 5 * 60 * 1000;

const INVALIDATING_ERRORS = [LicenseNotFoundError, LicenseExpiredError, InvalidProjectKeyError];

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * The master public keys `Sdk` verifies against, for passing to
 * checkLicenseAt/verifyActivationAt when you store tokens yourself.
 */
export const MASTER_PUBLIC_KEYS: readonly Uint8Array[] = Object.freeze(
  MASTER_PUBLIC_KEYS_HEX.map(hexToBytes),
);

// Identifies this SDK to the API on every request. Sent in the
// body rather than a header: in a browser the API's CORS policy allows only
// Content-Type, and User-Agent cannot be set from fetch at all.
const SDK_INFO = { language: "js", version: VERSION } as const;

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
  /**
   * A raw machine ID to use instead of the one the SDK reads itself. It is
   * never sent as-is: like the platform ID, it is HMAC'd with the app ID
   * first (see `Sdk.machineId`). Omit or leave empty to use the platform's
   * machine ID in Node, or a random ID persisted in `localStorage` in a
   * browser.
   *
   * Supply your own when the platform ID does not identify one install:
   * containers that share an image's `/etc/machine-id` or have none, cloned
   * VMs, a seat per user rather than per machine, and tests. Changing it on
   * an install that is already activated counts as a new machine.
   */
  readonly machineId?: string;
  /**
   * The name this machine is given when it activates, shown to the customer
   * in `Sdk.machines` and the customer portal and to you in the dashboard.
   * Omit it to send the OS hostname in Node/Electron main and no name in a
   * browser; `""` sends no name. A name set later with `Sdk.renameMachine`
   * is kept on re-activation.
   */
  readonly machineName?: string;
}

/** What `Sdk.deactivate` reports. */
export interface DeactivateResult {
  /**
   * `false` when the machine was already released, on an earlier call or by
   * the seller. Both outcomes are success.
   */
  readonly released: boolean;
  /**
   * When the freed seat can be used by another machine, set when the
   * seller's policy holds it until this machine's last token has expired.
   * `null` means the seat is free now.
   */
  readonly seatFreeAt: Date | null;
}

/**
 * One machine holding a seat on the licence, as `Sdk.machines` lists it. It
 * identifies a machine for a person to recognise and is never a handle for
 * acting on one.
 */
export interface Machine {
  /** The machine's name, absent when it has none. */
  readonly name?: string;
  /** The first 12 characters of the machine ID hash. */
  readonly fingerprint: string;
  readonly activatedAt: Date;
  /** The machine's last activation or renewal. */
  readonly lastSeenAt: Date;
  /**
   * Set on a released machine whose seat the seller's policy still holds,
   * and is when that seat frees.
   */
  readonly seatFreeAt?: Date;
  /** Marks the machine the SDK is running on. */
  readonly current: boolean;
}

interface TokenResponse {
  readonly token?: string;
  readonly chain?: Partial<CertChain>;
}

interface ErrorResponse {
  readonly error?: string;
  readonly reason?: string;
  readonly available_at?: string;
}

interface MachineResponse {
  readonly machine_name?: string;
  readonly machine_fingerprint: string;
  readonly activated_at: string;
  readonly last_seen_at: string;
  readonly seat_free_at?: string;
  readonly current: boolean;
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
  private readonly rawMachineId: string | undefined;
  private readonly machineName: string | undefined;
  private derivedMachineId: Promise<string> | undefined;
  private renewalsInFlight = 0;
  private lastRenewAttemptMs = 0;
  // Whether the last renewal attempt could not reach the server. In memory
  // only: never saved to the cache and never read by anything but check and
  // activate's cache hit, so a restart starts at false. renewalEpoch moves
  // whenever the activation changes, so an attempt that started under an
  // earlier one cannot write the flag.
  private renewalFailed = false;
  private renewalEpoch = 0;

  constructor(config: Config) {
    const parsed = parseAppId(config.appId); // throws an AppIdError subclass

    this.baseUrl = config.baseUrl ?? baseUrlFor(parsed.env);
    this.appId = config.appId;
    this.appKey = parsed.key;
    this.timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.storage = resolveStorage(parsed.key, config.cache ?? true);
    this.rawMachineId = config.machineId;
    this.machineName = config.machineName;
  }

  /**
   * The machine ID this SDK sends and checks tokens against: lowercase hex
   * HMAC-SHA256 keyed by the raw machine ID over `"licenselatte_" + appId`.
   * Computed on first use and reused after that. Pass it to checkLicenseAt
   * or validateAt when verifying a token you stored yourself.
   *
   * Throws MachineIdError when no `Config.machineId` was given and the
   * platform offers none.
   */
  machineId(): Promise<string> {
    this.derivedMachineId ??= resolveMachineId(this.appId, this.rawMachineId).catch((e: unknown) => {
      this.derivedMachineId = undefined;
      throw e;
    });
    return this.derivedMachineId;
  }

  /**
   * Activates `licenseKey` on this machine (see machineId).
   *
   * The key is normalized and given a minimal sanity check (non-empty,
   * not implausibly long) before ever reaching the network — a license
   * key may be native or a legacy-system alias (see the legacy-key-migration
   * feature in license-latte-api, internal/usecase/api/activate_license.go),
   * and only the server knows which, so anything beyond that minimal check
   * is deferred to it.
   *
   * With caching available, a cached activation for this exact key is
   * tried first; if it's still valid, it's returned without a network
   * call. A cache hit matches either the cached license's native key
   * (`sub` claim) against the sanitized input, or — for a license
   * resolved via a legacy-key alias, where `sub` is the newly minted
   * native key rather than the string the caller keeps passing — its
   * `alias` claim against the normalized input. Any other outcome — no
   * cache, a cache for a different key, or a cached token that fails
   * verification/validation — falls through to a network call, and a
   * successful result is written back to the cache. A server response
   * that fails local verification/validation throws ServerError, not one
   * of the sentinel errors (those are reserved for the server's HTTP
   * status code itself).
   */
  async activate(licenseKey: string): Promise<PublicLicense> {
    const sanitized = sanitizeKey(licenseKey);
    const normalized = normalizeKey(licenseKey);
    this.validateLicenseKey(normalized);
    const machineId = await this.machineId();

    const cached = await this.cachedLicense(machineId);
    if (
      cached !== null &&
      (cached.license.key === sanitized || (cached.alias !== "" && cached.alias === normalized))
    ) {
      return cached.license;
    }

    const { token, chain } = await this.postAndHandleInvalidation("/v1/activate", {
      project_key: this.appId,
      license_key: normalized,
      machine_id: machineId,
      machine_name: (this.machineName ?? (await defaultMachineName())) || undefined,
      sdk: SDK_INFO,
    });
    const lic = await this.verifyAndValidate(token, chain, machineId);
    await this.saveToCache(token, chain);
    this.resetRenewalFailed();
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
   * cached. A renewal the server rejects as not found, expired or for the
   * wrong project also drops the cached token.
   *
   * check runs the same renewal in the background; both count towards the
   * five-minute spacing between background attempts. An attempt that cannot
   * reach the server (NetworkError) is what turns `inGracePeriod` on for the
   * next check; any other outcome turns it off.
   */
  async renew(activationId: string, licenseKey: string): Promise<PublicLicense> {
    return this.renewAttempt(activationId, licenseKey);
  }

  /**
   * One renewal. `cachedToken` is set by the background renewal started from
   * check: the cache is then only replaced or dropped while it still holds
   * that token, so an attempt that outlives a deactivate or a new activation
   * cannot undo it.
   */
  private async renewAttempt(
    activationId: string,
    licenseKey: string,
    cachedToken?: string,
  ): Promise<PublicLicense> {
    this.renewalsInFlight++;
    this.lastRenewAttemptMs = Date.now();
    const epoch = this.renewalEpoch;
    let failed = false;
    try {
      const { token, chain } = await this.postAndHandleInvalidation(
        "/v1/renew",
        await this.credentials(activationId, licenseKey),
        cachedToken,
      );
      const lic = await this.verifyAndValidate(token, chain, await this.machineId());
      if (cachedToken === undefined || (await this.cacheHolds(cachedToken))) {
        await this.saveToCache(token, chain);
      }
      return lic;
    } catch (e) {
      failed =
        e instanceof NetworkError && (cachedToken === undefined || (await this.cacheHolds(cachedToken)));
      throw e;
    } finally {
      if (epoch === this.renewalEpoch) {
        this.renewalFailed = failed;
      }
      this.renewalsInFlight--;
    }
  }

  private resetRenewalFailed(): void {
    this.renewalEpoch++;
    this.renewalFailed = false;
  }

  /**
   * Starts a background renewal of `cachedToken` when `license` is at least
   * an hour old, the last attempt was at least five minutes ago and none is
   * running. Never waits for it: every failure is swallowed, and the cached
   * token stays usable until its grace deadline.
   *
   * The only thing keeping the process alive is the request itself, which
   * `timeoutMs` bounds; no timer is held.
   */
  private renewInBackground(
    license: Pick<PublicLicense, "issuedAt" | "activationId" | "key">,
    cachedToken: string,
  ): void {
    const now = Date.now();
    if (
      this.renewalsInFlight > 0 ||
      now / 1000 - license.issuedAt < MIN_RENEWAL_AGE_SECS ||
      now - this.lastRenewAttemptMs < MIN_RENEWAL_INTERVAL_MS
    ) {
      return;
    }
    this.renewAttempt(license.activationId, license.key, cachedToken).catch(() => {});
  }

  /**
   * Releases this machine's seat so the licence can be activated on another
   * machine. It needs the network: the server releases the seat first, and
   * only once it has answered 200 is the cached token deleted, after which
   * check throws NotActivatedError until the next activate. On any error
   * the cache is left alone and the call can be retried; a machine that is
   * lost or dead is released from the seller's customer portal instead.
   *
   * Takes the same activationId and licenseKey as renew. A release that
   * already happened is success, with `released: false`. When the seller's
   * deactivation policy refuses the release, throws
   * DeactivationBlockedError.
   */
  async deactivate(activationId: string, licenseKey: string): Promise<DeactivateResult> {
    const data = await this.request<{ released?: boolean; seat_free_at?: string | null }>(
      "/v1/deactivate",
      await this.credentials(activationId, licenseKey),
    );
    await this.clearCache();
    return {
      released: data.released === true,
      seatFreeAt: data.seat_free_at ? new Date(data.seat_free_at) : null,
    };
  }

  /**
   * Lists the machines holding a seat on this machine's licence. It needs
   * the network and an active activation on this machine (LicenseExpiredError
   * otherwise, from the server's 403).
   */
  async machines(activationId: string, licenseKey: string): Promise<Machine[]> {
    const data = await this.request<{ machines?: MachineResponse[] }>(
      "/v1/machines",
      await this.credentials(activationId, licenseKey),
    );
    return (data.machines ?? []).map((m) => ({
      ...(m.machine_name ? { name: m.machine_name } : {}),
      fingerprint: m.machine_fingerprint,
      activatedAt: new Date(m.activated_at),
      lastSeenAt: new Date(m.last_seen_at),
      ...(m.seat_free_at ? { seatFreeAt: new Date(m.seat_free_at) } : {}),
      current: m.current === true,
    }));
  }

  /**
   * Names this machine and returns the name as stored, trimmed. The server
   * refuses (ServerError, from its 400) a name that is empty, longer than 64
   * characters or holds control characters. Needs the network and an active
   * activation, like machines.
   */
  async renameMachine(activationId: string, licenseKey: string, name: string): Promise<string> {
    const data = await this.request<{ machine_name: string }>("/v1/machines/rename", {
      ...(await this.credentials(activationId, licenseKey)),
      machine_name: name,
    });
    return data.machine_name;
  }

  /**
   * Reads the cached activation for this machine without making a network
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
   *
   * It verifies the cached token offline and returns at once. A token at
   * least an hour old also starts a renewal in the background, at most one
   * at a time and no more often than every five minutes. If the server
   * rejects that renewal as not found, expired or for the wrong project (a
   * licence deactivated in the dashboard, say), the cached token is dropped
   * and the next check throws NotActivatedError. Any other failure, network
   * errors included, is ignored and the cached token stays valid until its
   * grace deadline.
   *
   * `inGracePeriod` on the result is true when the licence is still valid on
   * cached data, the SDK has tried to renew it and could not reach the
   * server, and the offline grace window has not run out. It reflects the
   * renewal attempts finished before this call, so check again after one.
   * It is advisory: gate features on this verdict, never on `inGracePeriod`.
   *
   * A cached token that is past its grace deadline (or its licence's end)
   * but whose signature chain still verifies is rejected as above, and is
   * renewed in the background the same way; once that succeeds, the next
   * check returns the license. A computer that was off longer than the grace
   * window thus recovers by itself.
   */
  async check(): Promise<PublicLicense> {
    const machineId = await this.machineId();
    const storage = await this.storage;
    const cached = await storage?.load();
    if (cached === undefined || cached === null) {
      throw new NotActivatedError();
    }

    try {
      const license = await checkLicenseAt(
        MASTER_PUBLIC_KEYS,
        cached.token,
        cached.chain,
        machineId,
        Date.now() / 1000,
        this.renewalFailed,
      );
      this.renewInBackground(license, cached.token);
      return license;
    } catch (e) {
      if (
        e instanceof GraceExpiredError ||
        e instanceof HardExpiredError ||
        e instanceof LicenseTooOldError
      ) {
        await this.renewLapsedInBackground(cached);
      }
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
   * Starts a background renewal for a cached token that check rejected for
   * its age: past its grace deadline, past the licence's end, or too old.
   * Those rejections come after the machine ID and the fields were accepted,
   * and the chain is verified again here, so the activation ID and key sent
   * come from a token signed for this machine. The server does not look at
   * the token's age.
   */
  private async renewLapsedInBackground(cached: { token: string; chain: CertChain }): Promise<void> {
    try {
      const license = await verifyActivationAt(
        MASTER_PUBLIC_KEYS,
        cached.token,
        cached.chain,
        Date.now() / 1000,
      );
      this.renewInBackground(license, cached.token);
    } catch {
      // An unverifiable token is not renewed.
    }
  }

  /**
   * A minimal local sanity check, not a format check: a license key may
   * be native or a legacy-system alias (see the legacy-key-migration
   * feature in license-latte-api, internal/usecase/api/activate_license.go),
   * and only the server knows which. This exists only to reject
   * obviously-not-a-key input (empty, or implausibly long) without a
   * network round trip.
   */
  private validateLicenseKey(normalized: string): void {
    if (normalized.length === 0 || normalized.length > 256) {
      throw new InvalidKeyError();
    }
  }

  /**
   * Verifies+validates the cached token, if any, returning both its
   * public-facing shape and its (internal-only) alias claim so the fast
   * path in activate() can match a legacy-key alias too.
   */
  private async cachedLicense(
    machineId: string,
  ): Promise<{ license: PublicLicense; alias: string } | null> {
    const storage = await this.storage;
    const cached = await storage?.load();
    if (cached === undefined || cached === null) {
      return null;
    }
    try {
      const now = Date.now() / 1000;
      const license = await verifyActivationAt(MASTER_PUBLIC_KEYS, cached.token, cached.chain, now);
      validateAt(license, machineId, now);
      return {
        license: toPublicLicense(license, inGracePeriod(license, now, this.renewalFailed)),
        alias: license.alias,
      };
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

  /** The body renew and the machine calls authenticate with. */
  private async credentials(
    activationId: string,
    licenseKey: string,
  ): Promise<Record<string, unknown>> {
    return {
      activation_id: activationId,
      license_key: licenseKey,
      machine_id: await this.machineId(),
      sdk: SDK_INFO,
    };
  }

  private async clearCache(): Promise<void> {
    this.resetRenewalFailed();
    const storage = await this.storage;
    await storage?.clear();
  }

  private async cacheHolds(token: string): Promise<boolean> {
    const storage = await this.storage;
    return (await storage?.load())?.token === token;
  }

  private async verifyAndValidate(
    token: string,
    chain: CertChain,
    machineId: string,
  ): Promise<PublicLicense> {
    try {
      return await checkLicenseAt(MASTER_PUBLIC_KEYS, token, chain, machineId, Date.now() / 1000);
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
   * as still active until it independently expires. With `onlyIfCached`,
   * the cache is dropped only while it still holds that token.
   */
  private async postAndHandleInvalidation(
    path: string,
    body: Record<string, unknown>,
    onlyIfCached?: string,
  ): Promise<{ token: string; chain: CertChain }> {
    try {
      return await this.post(path, body);
    } catch (e) {
      if (
        INVALIDATING_ERRORS.some((cls) => e instanceof cls) &&
        (onlyIfCached === undefined || (await this.cacheHolds(onlyIfCached)))
      ) {
        await this.clearCache();
      }
      throw e;
    }
  }

  /** POST helper for activate/renew: a token and its chain. */
  private async post(
    path: string,
    body: Record<string, unknown>,
  ): Promise<{ token: string; chain: CertChain }> {
    const data = await this.request<TokenResponse>(path, body);

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

  /**
   * Shared POST helper: sends `body` as JSON, maps a non-2xx status to its
   * error, and returns the decoded response.
   */
  private async request<T>(path: string, body: Record<string, unknown>): Promise<T> {
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
      let errBody: ErrorResponse = {};
      try {
        errBody = (await resp.json()) as ErrorResponse;
      } catch {
        // Non-JSON error body: fall through with an empty message.
      }
      const msg = errBody.error ?? "";
      switch (resp.status) {
        case 404:
          throw new LicenseNotFoundError();
        case 403:
          throw new LicenseExpiredError();
        case 409:
          // A 409 from deactivate is the seller's deactivation policy, never
          // a seat limit.
          if (path === "/v1/deactivate") {
            throw new DeactivationBlockedError(
              msg,
              errBody.reason ?? "",
              errBody.available_at ? new Date(errBody.available_at) : null,
            );
          }
          throw new SeatLimitError();
        case 401:
          throw new InvalidProjectKeyError();
        default:
          throw new ServerError(msg || `HTTP ${resp.status}`);
      }
    }

    try {
      return (await resp.json()) as T;
    } catch (e) {
      throw new ServerError(`decode response: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
}
