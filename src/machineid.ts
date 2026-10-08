/**
 * The machine ID this SDK sends as `machine_id` and compares against an
 * activation token's `mid` claim.
 *
 * The value is always derived, never raw: lowercase hex
 * HMAC-SHA256(key = raw machine ID as UTF-8, message = "licenselatte_" +
 * appId), the same value latte-go and every other LicenseLatte SDK sends.
 * The raw ID never leaves the machine.
 *
 * The raw ID is `Config.machineId` when the caller supplied one. Otherwise:
 *
 * - Node / Electron main: the platform's own machine ID, read the way
 *   denisbrodbeck/machineid reads it (dbus/systemd machine-id on Linux,
 *   IOPlatformUUID on macOS, MachineGuid on Windows, /etc/hostid or kenv on
 *   the BSDs).
 * - Browser / Electron renderer: there is no OS ID to read, so a random one
 *   is generated on first use and persisted in `localStorage`, the backend
 *   the licence cache uses there. Clearing site data loses it, and the
 *   next activation counts as a new machine.
 *
 * Node modules are imported dynamically, as in storage.ts, so a browser
 * bundle never pulls them in.
 */

import { MachineIdError } from "./errors.js";
import { hasLocalStorage, isNodeLike } from "./storage.js";

/** localStorage key holding the browser's generated raw machine ID. */
export const BROWSER_MACHINE_ID_KEY = "licenselatte:machine_id";

const BSD_PLATFORMS = new Set(["freebsd", "netbsd", "openbsd", "sunos"]);

/**
 * Derives the machine ID sent to the server from a raw ID: lowercase hex
 * HMAC-SHA256 keyed by `raw` (UTF-8, used byte for byte) over
 * `"licenselatte_" + appId`.
 */
export async function protectMachineId(raw: string, appId: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await globalThis.crypto.subtle.importKey(
    "raw",
    enc.encode(raw),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const mac = new Uint8Array(
    await globalThis.crypto.subtle.sign("HMAC", key, enc.encode(`licenselatte_${appId}`)),
  );
  return Array.from(mac, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Resolves the derived machine ID for `appId`: from `configured` when it is
 * non-empty, otherwise from the platform (Node) or a persisted random ID
 * (browser). Throws MachineIdError when none can be obtained.
 */
export async function resolveMachineId(appId: string, configured?: string): Promise<string> {
  const raw = configured ? configured : await defaultRawMachineId();
  return protectMachineId(raw, appId);
}

async function defaultRawMachineId(): Promise<string> {
  if (hasLocalStorage()) {
    return browserRawMachineId();
  }
  if (isNodeLike()) {
    return platformRawMachineId();
  }
  throw new MachineIdError("no platform ID or localStorage available; set Config.machineId");
}

function browserRawMachineId(): string {
  try {
    const existing = window.localStorage.getItem(BROWSER_MACHINE_ID_KEY);
    if (existing) {
      return existing;
    }
    const id = globalThis.crypto.randomUUID();
    window.localStorage.setItem(BROWSER_MACHINE_ID_KEY, id);
    return id;
  } catch (e) {
    // An ID that cannot be persisted would be a new seat on every load.
    throw new MachineIdError(
      `localStorage unavailable (${e instanceof Error ? e.message : String(e)}); set Config.machineId`,
    );
  }
}

async function platformRawMachineId(): Promise<string> {
  let id = "";
  try {
    switch (process.platform) {
      case "linux":
      case "android":
        id = await readFirstFile(["/var/lib/dbus/machine-id", "/etc/machine-id"]);
        break;
      case "darwin":
        id = parseIoregOutput(await run("/usr/sbin/ioreg", ["-rd1", "-c", "IOPlatformExpertDevice"]));
        break;
      case "win32":
        id = parseRegQueryOutput(
          await run(`${process.env.SystemRoot || "C:\\Windows"}\\System32\\reg.exe`, [
            "query",
            "HKLM\\SOFTWARE\\Microsoft\\Cryptography",
            "/v",
            "MachineGuid",
            "/reg:64",
          ]),
        );
        break;
      default:
        if (BSD_PLATFORMS.has(process.platform)) {
          id = await readFirstFile(["/etc/hostid"]);
          if (!id) {
            id = (await run("/bin/kenv", ["-q", "smbios.system.uuid"])).trim();
          }
        }
    }
  } catch (e) {
    throw new MachineIdError(`${e instanceof Error ? e.message : String(e)}; set Config.machineId`);
  }
  if (!id) {
    throw new MachineIdError(`no ID found on ${process.platform}; set Config.machineId`);
  }
  return id;
}

/** The first of `paths` that reads non-empty after trimming, or "". */
async function readFirstFile(paths: readonly string[]): Promise<string> {
  const fs = await import("node:fs/promises");
  for (const p of paths) {
    try {
      const id = (await fs.readFile(p, "utf8")).trim();
      if (id) {
        return id;
      }
    } catch {
      // Missing or unreadable: try the next path.
    }
  }
  return "";
}

// cmd is always an absolute path: a bare name is resolved through the current
// directory first on Windows, so a planted reg.exe beside the app would run.
async function run(cmd: string, args: readonly string[]): Promise<string> {
  const { execFile } = await import("node:child_process");
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { windowsHide: true }, (err, stdout) =>
      err ? reject(err) : resolve(stdout),
    );
  });
}

/**
 * Extracts IOPlatformUUID from `ioreg -rd1 -c IOPlatformExpertDevice`
 * output: the first line mentioning it that splits into exactly two parts
 * on `" = "`, with trailing quotes and surrounding whitespace removed.
 * Returns "" when no line matches.
 */
export function parseIoregOutput(output: string): string {
  for (const line of output.split("\n")) {
    if (!line.includes("IOPlatformUUID")) {
      continue;
    }
    const parts = line.split('" = "');
    if (parts.length === 2) {
      return (parts[1] as string).replace(/"+$/, "").trim();
    }
  }
  return "";
}

/**
 * Extracts the MachineGuid value from `reg query ... /v MachineGuid`
 * output, whose value line reads `    MachineGuid    REG_SZ    <value>`.
 * Returns "" when no line matches.
 */
export function parseRegQueryOutput(output: string): string {
  const m = /^\s*MachineGuid\s+REG_SZ\s+(.*?)\r?$/m.exec(output);
  return m?.[1] ?? "";
}
