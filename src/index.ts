/**
 * TypeScript SDK for LicenseLatte license activation and offline
 * verification.
 *
 * Sdk activates and renews licenses over the network, with an optional
 * cache so a valid activation survives across restarts without a network
 * call.
 *
 * IMPORTANT — read the "Threat Model" section of README.md before relying
 * on this package for anything security-sensitive: in an Electron app,
 * the renderer/main process JS (even bundled into an asar archive) is
 * trivially extractable and patchable, so while this package's
 * cryptographic verification is correct, it provides no tamper resistance.
 */

import type { CertChain, License } from "./domain.js";

export * as appid from "./appid.js";
export * as domain from "./domain.js";
export * as errors from "./errors.js";
export * as key from "./key.js";
export * as validate from "./validate.js";
export * as verify from "./verify.js";
export type { CertChain, License };
export {
  VerifyError,
  ValidateError,
  MalformedTokenError,
  InvalidSignatureError,
  MissingClaimError,
  InvalidClaimError,
  WrongIssuerError,
  NotYetValidError,
  ExpiredError,
  ChainInconsistentError,
  HardExpiredError,
  GraceExpiredError,
  LicenseTooOldError,
  MachineIdMismatchError,
  InvalidFieldsError,
  LatteError,
  InvalidKeyError,
  LicenseExpiredError,
  NotActivatedError,
  SeatLimitError,
  LicenseNotFoundError,
  InvalidProjectKeyError,
  NetworkError,
  ServerError,
} from "./errors.js";
export type { PublicLicense } from "./license.js";
export { checkLicenseAt } from "./license.js";
export type { CacheConfig, CachedActivation, Storage } from "./storage.js";
export type { Config } from "./http.js";
export { Sdk } from "./http.js";
