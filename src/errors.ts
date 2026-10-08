/**
 * Error types. VerifyError covers chain/signature failures during
 * verification; every fixture that expects a "verify"-stage rejection
 * accepts any VerifyError subclass. ValidateError covers grace-period /
 * offline validation failures on an already-verified token.
 */

export abstract class VerifyError extends Error {}

export class MalformedTokenError extends VerifyError {
  constructor(reason: string) {
    super(`malformed token: ${reason}`);
  }
}

export class InvalidSignatureError extends VerifyError {
  constructor() {
    super("invalid signature");
  }
}

export class MissingClaimError extends VerifyError {
  constructor(public readonly claim: string) {
    super(`missing claim: ${claim}`);
  }
}

export class InvalidClaimError extends VerifyError {
  constructor(
    public readonly claim: string,
    reason: string,
  ) {
    super(`invalid claim ${claim}: ${reason}`);
  }
}

export class WrongIssuerError extends VerifyError {
  constructor() {
    super("unexpected issuer");
  }
}

export class NotYetValidError extends VerifyError {
  constructor() {
    super("token used before issued");
  }
}

export class ExpiredError extends VerifyError {
  constructor() {
    super("token is expired");
  }
}

export class ChainInconsistentError extends VerifyError {
  constructor(reason: string) {
    super(`chain inconsistent: ${reason}`);
  }
}

/**
 * Base class for grace-period / offline validation failures.
 */
export abstract class ValidateError extends Error {}

/** now > expiresAt. */
export class HardExpiredError extends ValidateError {
  constructor() {
    super("license expired");
  }
}

/**
 * now > issuedAt + gracePeriod, but not yet past expiresAt.
 */
export class GraceExpiredError extends ValidateError {
  constructor() {
    super("grace period expired");
  }
}

/**
 * now - issuedAt > 365 days, independent of expiry/grace.
 */
export class LicenseTooOldError extends ValidateError {
  constructor() {
    super("license too old");
  }
}

export class MachineIdMismatchError extends ValidateError {
  constructor() {
    super("machine ID does not match");
  }
}

export class InvalidFieldsError extends ValidateError {
  constructor(reason: string) {
    super(`invalid license: ${reason}`);
  }
}

/** Base class for AppID parsing/checksum failures. */
export abstract class AppIdError extends Error {}

export class InvalidAppIdFormatError extends AppIdError {
  constructor() {
    super("invalid AppID");
  }
}

export class UnknownEnvironmentError extends AppIdError {
  constructor(public readonly env: string) {
    super(`unknown environment: ${env}`);
  }
}

export class InvalidKeySegmentError extends AppIdError {
  constructor() {
    super("invalid app id key segment");
  }
}

export class InvalidChecksumError extends AppIdError {
  constructor() {
    super("invalid app id checksum");
  }
}

/**
 * Base class for errors raised by Sdk (activate, renew, check). Distinct
 * from VerifyError/ValidateError (chain/grace-period failures on an
 * already-fetched token) — these are failures of Sdk's own calls: bad key
 * format, transport failure, a non-2xx/malformed server response, or (for
 * check) no usable cached license.
 */
export abstract class LatteError extends Error {}

/**
 * The license key's format or checksum is invalid, or its short_id doesn't
 * match this SDK's project key. Never reaches the network.
 */
export class InvalidKeyError extends LatteError {
  constructor() {
    super("invalid license key");
  }
}

/**
 * The license is past its hard expiry — from a 403 response
 * (activate/renew) or a cached token (check).
 */
export class LicenseExpiredError extends LatteError {
  constructor() {
    super("license expired");
  }
}

/**
 * No usable license is currently active on this machine: nothing is
 * cached, the cache is unreadable/tampered, or it's valid but rejected for
 * a reason other than hard expiry (out of grace, too old, wrong machine).
 * Only thrown by check.
 */
export class NotActivatedError extends LatteError {
  constructor() {
    super("not activated on this machine");
  }
}

/**
 * No machine ID could be determined: none was supplied in `Config.machineId`
 * and the platform's own ID could not be read (or, in a browser, the
 * generated one could not be persisted).
 */
export class MachineIdError extends LatteError {
  constructor(reason: string) {
    super(`cannot determine machine ID: ${reason}`);
  }
}

/** Server returned 409 (activation seat limit reached). */
export class SeatLimitError extends LatteError {
  constructor() {
    super("activation seat limit reached");
  }
}

/** Server returned 404 (license not found). */
export class LicenseNotFoundError extends LatteError {
  constructor() {
    super("license not found");
  }
}

/** Server returned 401 (invalid project key). */
export class InvalidProjectKeyError extends LatteError {
  constructor() {
    super("invalid project key");
  }
}

/**
 * Transport-level failure (DNS, TCP, timeout) — the request never got a
 * response.
 */
export class NetworkError extends LatteError {}

/**
 * Non-2xx response with no specific sentinel, a malformed/empty response
 * body, or a server-issued token that failed local chain
 * verification/grace-period validation.
 */
export class ServerError extends LatteError {}
