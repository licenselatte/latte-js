# latte-js

TypeScript/JavaScript SDK for [LicenseLatte](https://licenselatte.com), the
software licensing platform. An idiomatic, from-scratch TypeScript
implementation of license activation and verification, with no native
dependencies (works in Node, browsers, and Electron main/renderer processes
alike).

**Read the [Threat Model](#threat-model) section below before relying on
this package for anything security-sensitive**, it is especially relevant
if you're shipping this inside an Electron app.

---

## What this package verifies

LicenseLatte licenses are issued as a chain of Ed25519-signed JWTs:

```
Master (root, hardcoded in the SDK)
  -> Submaster cert
       -> Project cert
            -> Daily cert
                 -> Activation token (what you actually check against a machine)
```

Each link is a standard compact-serialization JWT
(`base64url(header).base64url(payload).base64url(signature)`, `alg: EdDSA`,
signed with Ed25519 — see [RFC 8037]). Verifying a license means:

1. Verify the submaster cert's signature against the hardcoded master public
   key, extract the submaster's own public key from its `spk` claim.
2. Verify the project cert's signature against the submaster's public key,
   extract `ppk`.
3. Verify the daily cert's signature against the project's public key,
   extract `dpk`.
4. Verify the activation token's signature against the daily key.
5. Cross-check the claims (project ID agreement, timing consistency between
   the activation token and the daily cert that signed it).
6. Apply grace-period math: is the token still within its hard expiry, and —
   if the device has been offline — still within its configured grace
   window (30–90 days, chosen when the license is issued)?

This is a standard certificate-chain-of-trust design (the same shape as an
X.509 chain, just JWTs instead of X.509 certs), documented publicly here per
Kerckhoffs's principle: the *mechanism* is not the secret, the master
private key is. This SDK ships only the master **public** key; key rotation
cadence, key storage, and the tooling that issues certs are intentionally
not documented in any SDK repo.

[RFC 8037]: https://www.rfc-editor.org/rfc/rfc8037

## Cryptography

- **Ed25519** signature verification via [`@noble/ed25519`](https://github.com/paulmillr/noble-ed25519)
  (audited, zero native dependencies — works identically in Node, browsers,
  and Electron). No hand-rolled crypto anywhere in this package.
- Verification delegates SHA-512 to the WebCrypto API (`globalThis.crypto.subtle`),
  available in Node 19+, all evergreen browsers, and Electron — this is why
  the verification functions are `async`.
- JWT compact-serialization parsing is hand-written (`src/jwt.ts`) — this is
  structural (base64url + JSON), not cryptographic, so implementing it
  directly instead of pulling in a general-purpose JWT library is a
  reasonable, minimal-dependency choice for four call sites with one fixed
  algorithm.

## Installation

```sh
npm install @licenselatte/latte
```

## Quick start: activating a license

```typescript
import { Sdk, LatteError } from "@licenselatte/latte";

const sdk = new Sdk({ appId: "pk_live_..." }); // from the LicenseLatte dashboard

try {
  const lic = await sdk.activate("USER-PROVIDED-LICENSE-KEY", "opaque-machine-id");
  console.log("license OK, expires", new Date(lic.expiresAt * 1000));
  if (lic.inGracePeriod) {
    console.log("warning: offline a while, please reconnect soon");
  }
  // Keep lic.activationId around (in your own storage) so you can call
  // sdk.renew(lic.activationId, ...) later.
} catch (e) {
  if (e instanceof LatteError) {
    console.error("activation failed:", e.message);
  } else {
    throw e;
  }
}
```

By default, a successful `activate`/`renew` is cached, and a later
`activate` call for the same key returns the cached result without a
network round trip as long as it's still valid. The cache backend is
auto-detected: `window.localStorage` in a browser (including an Electron
renderer), a JSON file under the OS config directory in Node/Electron
main. There's no background renewal — call `renew` yourself on whatever
schedule fits your application. Pass `cache: false` in the `Sdk`
constructor's config to disable caching entirely.

## Checking a cached activation without a network call

```typescript
import { LicenseExpiredError, NotActivatedError } from "@licenselatte/latte";

try {
  const lic = await sdk.check("opaque-machine-id");
  console.log("license OK, expires", new Date(lic.expiresAt * 1000));
} catch (e) {
  if (e instanceof LicenseExpiredError) {
    console.error("license expired, please renew");
  } else if (e instanceof NotActivatedError) {
    console.error("not activated — call activate()");
  } else {
    throw e;
  }
}
```

## The cache

In a browser (or an Electron renderer), the cache lives in
`window.localStorage` under the key `licenselatte:{projectKey}`. In Node
or an Electron main process, it's a JSON file under the OS's per-user
config directory, `licenselatte/{projectKey}.json`:

```json
{
  "timestamp": 1700000000,
  "token": "<activation JWT>",
  "submaster": "<submaster cert JWT>",
  "project": "<project cert JWT>",
  "daily": "<daily cert JWT>"
}
```

File writes go to a temp file in the same directory and get renamed into
place, so a crash or a concurrent write can't leave a half-written file
behind. Pass `cache: { path: "..." }` to use a specific file path instead
of the default (Node/Electron-main only — a path override is meaningless
for `localStorage` and is silently ignored there).

## Re-verifying a token you're storing yourself

If you'd rather manage persistence yourself instead of using the built-in
cache, `checkLicenseAt` runs the same verify+validate pipeline
`Sdk.activate`/`Sdk.check` do, against a token/chain you already have:

```typescript
import { checkLicenseAt, CertChain, VerifyError, ValidateError } from "@licenselatte/latte";

const masterPub = hexToBytes(MASTER_PUBLIC_KEY_HEX); // Uint8Array, 32 bytes
const chain: CertChain = { submaster, project, daily };

try {
  const lic = await checkLicenseAt(masterPub, token, chain, machineId, Date.now() / 1000);
  console.log("license OK, expires", new Date(lic.expiresAt * 1000));
  if (lic.inGracePeriod) {
    console.log("warning: offline a while, please reconnect soon");
  }
} catch (e) {
  if (e instanceof VerifyError) {
    console.error("could not verify license:", e.message); // chain/signature/format problem
  } else if (e instanceof ValidateError) {
    console.error("license rejected:", e.message); // verified fine, but expired/out of grace/wrong machine
  } else {
    throw e;
  }
}
```

`checkLicenseAt` takes an explicit `now` (unix seconds) rather than reading
the system clock internally. That's what makes this package's test suite
fully reproducible against a fixed set of test vectors in `testdata/`.
Pass `Date.now() / 1000` for real-time use.

## Offline grace period

The grace period is an offline tolerance window measured **from the
license's last issuance/renewal**, not from its expiry:

```
issuedAt ──────────────────────────────────> expiresAt
              |                   |
              └── gracePeriod ────┘
                  ^ offline window
```

While `now <= issuedAt + gracePeriodSecs`, the license is still usable
without a network call. Once that deadline passes, verification throws
`GraceExpiredError`; once `now > expiresAt`, it throws `HardExpiredError`
(checked first — hard expiry always wins).

`PublicLicense.inGracePeriod` is a softer, earlier warning signal: it turns
`true` once more than 60 minutes have passed since the last
issuance/renewal without a fresh one arriving, while still inside the grace
window — surface it as a "please reconnect soon" hint, distinct from an
outright rejection.

## What this package does *not* do

OS-level machine-ID fingerprinting and background renewal scheduling are
intentionally out of scope. Pass your own machine-ID string into
`activate`/`renew`/`check`/`checkLicenseAt`; only the opaque string
compared against the token's `mid` claim matters, not the algorithm that
produces it. For renewal, there's no scheduler here — `Sdk.renew` is the
building block; call it on a timer, a web worker, in response to a UI
action, or whatever fits your application.

## Threat model

**Read this before you rely on `latte-js` for anything where tamper
resistance, not just cryptographic correctness, matters — this is
especially important for Electron apps.**

This is a statement of fact about the architecture, not a disclaimer to
skim past:

- Whether this package runs in a plain Node.js CLI, a browser tab, or an
  Electron app, the JavaScript actually executing is available to the
  runtime — and to the user — in a form that's trivially readable and
  patchable. **Electron's `asar` archive is not encryption or obfuscation:
  it's an uncompressed tar-like container.** Any user can unpack it
  (`npx asar extract app.asar ./out`), open the unpacked `.js` files in a
  text editor, find the call to `checkLicenseAt`, delete it or make it
  always resolve successfully, then repack and run the modified app. This
  requires no reverse engineering tools beyond a text editor and one
  publicly documented CLI command — this is fundamentally different from a
  compiled binary, where bypassing a license check requires actual binary
  patching or a debugger.
- This is a known, accepted tradeoff for a JS/Electron-environment SDK, not
  a bug in this package. **No amount of minification, bundling, or
  "clever" runtime obfuscation closes this gap** — a JS engine (V8, in
  Electron's case) always executes actual JavaScript source (or a
  trivially-decompiled bytecode form), and the user controls the machine
  it runs on.
- What this package *does* guarantee: the cryptographic verification
  itself is correct. A forged license — wrong signature, broken chain,
  tampered claims — will reliably fail verification. What it does *not*
  guarantee is that a determined user can't simply remove the call to this
  package from your application entirely.
- **If this distinction matters for your deployment** (e.g. you're
  protecting revenue from a motivated, technically capable user base, not
  just casual copying), the mitigation is **server-side re-validation**:
  don't treat a successful local `checkLicenseAt` call as the sole gate for
  a valuable feature or resource. Have your server independently verify
  activation state on a schedule using the same grace-period/re-check
  mechanism this package implements (`gracePeriodSecs`/`inGracePeriod`) —
  a periodic server-side check means a locally-patched client still can't
  use server-mediated features indefinitely without a valid, unexpired
  license the server itself is willing to recognize.
- This tradeoff is specific to source-distributed, dynamically-executed
  environments like JS/Electron. A compiled binary requires actual binary
  reverse engineering to bypass, which is a meaningfully higher bar, even
  though it isn't literally unbreakable either.

## Testing

```sh
npm install
npm test        # vitest, includes the full shared cross-language fixture suite
npm run typecheck
npm run lint
npm run build
```

`npm test` runs unit tests for the checksum algorithm and AppID parsing,
chain verification (valid chains, tampered signatures, broken intermediate
links, cross-check failures, clock-skew edge cases), grace-period math
(including exact boundary conditions), plus the full shared cross-language
fixture suite in `testdata/` (see `../latte-testvectors/README.md`).

## License

MIT, see [LICENSE](LICENSE).
