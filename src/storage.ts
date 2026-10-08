/**
 * On-disk/browser-storage caching for an activated license, so an
 * application doesn't have to hit the network on every startup.
 *
 * Two backends, auto-detected — there's no single "the filesystem" or
 * "the browser" in a package that runs in Node, browsers, and Electron
 * alike:
 *
 * - Browser (including an Electron renderer, which is a browser context):
 *   `window.localStorage`, keyed by `licenselatte:{projectKey}`.
 * - Node / Electron main process: a JSON file under the OS's per-user
 *   config directory, the same snake_case shape used by every other
 *   LicenseLatte SDK's cache file.
 *
 * If neither is available, caching is silently inert — the caller falls
 * back to the network, same as any other cache miss.
 *
 * The record shape (identical on both backends):
 *
 * ```json
 * {
 *   "timestamp": 1700000000,
 *   "token": "<activation JWT>",
 *   "submaster": "<submaster cert JWT>",
 *   "project": "<project cert JWT>",
 *   "daily": "<daily cert JWT>"
 * }
 * ```
 *
 * `timestamp` (unix seconds, set at save time) is metadata for a human
 * reading the file, not used by anything in this package.
 */

import type { CertChain } from "./domain.js";

export interface CachedActivation {
  readonly token: string;
  readonly chain: CertChain;
}

export interface Storage {
  load(): Promise<CachedActivation | null>;
  save(token: string, chain: CertChain): Promise<void>;
  clear(): Promise<void>;
}

interface StoredRecord {
  readonly timestamp?: number;
  readonly token?: string;
  readonly submaster?: string;
  readonly project?: string;
  readonly daily?: string;
}

function parseRecord(raw: string): CachedActivation | null {
  let data: StoredRecord;
  try {
    data = JSON.parse(raw) as StoredRecord;
  } catch {
    return null;
  }
  if (
    typeof data.token !== "string" ||
    typeof data.submaster !== "string" ||
    typeof data.project !== "string" ||
    typeof data.daily !== "string"
  ) {
    return null;
  }
  return {
    token: data.token,
    chain: { submaster: data.submaster, project: data.project, daily: data.daily },
  };
}

function serializeRecord(token: string, chain: CertChain): string {
  const record: Required<StoredRecord> = {
    timestamp: Math.floor(Date.now() / 1000),
    token,
    submaster: chain.submaster,
    project: chain.project,
    daily: chain.daily,
  };
  return JSON.stringify(record);
}

export function hasLocalStorage(): boolean {
  try {
    return typeof window !== "undefined" && typeof window.localStorage !== "undefined";
  } catch {
    // Some browsers (Safari private browsing, historically) throw on
    // accessing localStorage rather than leaving it undefined.
    return false;
  }
}

function browserStorage(projectKey: string): Storage {
  const key = `licenselatte:${projectKey}`;
  return {
    load(): Promise<CachedActivation | null> {
      let raw: string | null;
      try {
        raw = window.localStorage.getItem(key);
      } catch {
        return Promise.resolve(null);
      }
      return Promise.resolve(raw === null ? null : parseRecord(raw));
    },
    save(token: string, chain: CertChain): Promise<void> {
      try {
        window.localStorage.setItem(key, serializeRecord(token, chain));
      } catch {
        // Best-effort: quota exceeded or storage disabled shouldn't turn a
        // successful network activation into an error.
      }
      return Promise.resolve();
    },
    clear(): Promise<void> {
      try {
        window.localStorage.removeItem(key);
      } catch {
        // Ignored, same reasoning as save().
      }
      return Promise.resolve();
    },
  };
}

export function isNodeLike(): boolean {
  return typeof process !== "undefined" && process.versions?.node != null;
}

async function defaultNodeCachePath(projectKey: string): Promise<string> {
  const os = await import("node:os");
  const path = await import("node:path");

  const home = os.homedir();
  let configDir: string;
  if (process.platform === "win32") {
    configDir = process.env["APPDATA"] ?? path.join(home, "AppData", "Roaming");
  } else if (process.platform === "darwin") {
    configDir = path.join(home, "Library", "Application Support");
  } else {
    configDir = process.env["XDG_CONFIG_HOME"] ?? path.join(home, ".config");
  }
  return path.join(configDir, "LicenseLatte", `${projectKey}.json`);
}

function nodeStorage(filePath: string): Storage {
  return {
    async load(): Promise<CachedActivation | null> {
      const fs = await import("node:fs/promises");
      let raw: string;
      try {
        raw = await fs.readFile(filePath, "utf8");
      } catch {
        return null;
      }
      return parseRecord(raw);
    },
    async save(token: string, chain: CertChain): Promise<void> {
      const fs = await import("node:fs/promises");
      const path = await import("node:path");

      // Best-effort: a local write failure shouldn't turn a successful
      // network activation into an error.
      try {
        await fs.mkdir(path.dirname(filePath), { recursive: true });
        const tmpPath = `${filePath}.tmp`;
        await fs.writeFile(tmpPath, serializeRecord(token, chain));
        await fs.rename(tmpPath, filePath);
      } catch {
        // Ignored.
      }
    },
    async clear(): Promise<void> {
      const fs = await import("node:fs/promises");
      try {
        await fs.unlink(filePath);
      } catch {
        // Missing file (or any other failure) is not an error here.
      }
    },
  };
}

/**
 * Config for the on-disk/browser cache. `true` (the default) auto-detects
 * a backend; `false` disables caching entirely; `{ path }` forces the
 * Node/Electron-main filesystem backend at that exact path (meaningless in
 * a browser context, where it's silently ignored — `localStorage` has no
 * concept of a caller-chosen path).
 */
export type CacheConfig = boolean | { readonly path?: string };

/**
 * Picks a `Storage` backend for `projectKey`, or `null` if caching is
 * disabled or no supported backend is available in this environment.
 */
export async function resolveStorage(
  projectKey: string,
  config: CacheConfig | undefined,
): Promise<Storage | null> {
  if (config === false) {
    return null;
  }
  const override = typeof config === "object" ? config : undefined;

  if (hasLocalStorage()) {
    return browserStorage(projectKey);
  }
  if (isNodeLike()) {
    const filePath = override?.path ?? (await defaultNodeCachePath(projectKey));
    return nodeStorage(filePath);
  }
  return null;
}
