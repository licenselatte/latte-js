/**
 * AppId (`pk_{env}_{32-char key}`) parsing and validation.
 *
 * Includes the undocumented-but-real `local` environment.
 */

import {
  InvalidAppIdFormatError,
  InvalidChecksumError,
  InvalidKeySegmentError,
  UnknownEnvironmentError,
} from "./errors.js";
import { validateKey } from "./key.js";

export type Environment = "live" | "test" | "local";

const BASE_URLS: Record<Environment, string> = {
  live: "https://api.licenselatte.com",
  test: "https://test.api.licenselatte.com",
  local: "http://localhost:8080",
};

export interface AppId {
  readonly env: Environment;
  /** The 32-character key segment, including its trailing 4-char checksum. */
  readonly key: string;
}

function isEnvironment(s: string): s is Environment {
  return s === "live" || s === "test" || s === "local";
}

export function baseUrlFor(env: Environment): string {
  return BASE_URLS[env];
}

export function parseAppId(appId: string): AppId {
  const parts = appId.split("_");
  if (parts.length !== 3 || parts[0] !== "pk") {
    throw new InvalidAppIdFormatError();
  }

  const envStr = parts[1] as string;
  if (!isEnvironment(envStr)) {
    throw new UnknownEnvironmentError(envStr);
  }

  const key = parts[2] as string;
  if (key.length !== 32) {
    throw new InvalidKeySegmentError();
  }
  if (!validateKey(key, 4)) {
    throw new InvalidChecksumError();
  }

  return { env: envStr, key };
}
