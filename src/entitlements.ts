/**
 * Typed entitlements: the answers a seller signed into a licence about what
 * their customer bought.
 *
 * An entitlement answers one of exactly two questions about the software you
 * shipped: *may this customer do X* (a boolean, read with `can`) and *how
 * many Y do they get* (an integer, read with `limit`). The values are set on
 * a policy and overridden per licence in the LicenseLatte dashboard,
 * resolved server-side, and signed into the activation token as the `ent`
 * claim — so `can` and `limit` answer fully offline, with no network call
 * and no second source of truth.
 *
 * They are deliberately not the same thing as `metadata` (the `pmd` claim):
 * metadata is arbitrary display data, filtered per field, and untyped.
 * Entitlements are booleans and integers, unfiltered, and exist precisely to
 * be read on the customer's machine. The two never merge, and the same key
 * may appear in both meaning different things.
 *
 * ## Absence denies, and that has a rollout consequence
 *
 * A key that is not in the claim answers `false` / `undefined`. There is no
 * "unknown means allow": the token is a bearer artefact sitting in a file on
 * the machine of the person it constrains, so if absence granted, stripping
 * the claim would unlock everything, and replaying a token minted before the
 * seller adopted entitlements would do the same with no tampering at all.
 *
 * The cost of that default lands on you, not on the server. Shipping
 *
 * ```ts
 * if (!lic.can("export_pdf")) hide();
 * ```
 *
 * before your installed base has renewed disables PDF export for every
 * customer whose cached token predates the claim. Use `hasEntitlements` to
 * bridge one release:
 *
 * ```ts
 * const enabled = lic.hasEntitlements ? lic.can("export_pdf") : legacyBehaviour();
 * ```
 *
 * Drop the fallback once the base has renewed — one grace window, which the
 * dashboard shows per policy.
 *
 * ## Tamper resistance
 *
 * Entitlements are a distribution mechanism for a signed answer, not a
 * tamper-proofing one. In an Electron app the renderer JS is trivially
 * patchable (see the Threat Model section of README.md), and entitlements
 * change nothing about that. If real revenue depends on a feature,
 * re-validate it server-side.
 */

/**
 * An entitlement value: a boolean, or an integer.
 *
 * Two types and no more. Strings would be the untyped bag with extra steps,
 * enums are N booleans with a schema the client has to know, and floats
 * round-trip through five JSON parsers with five opinions about `1.0` versus
 * `1`.
 */
export type EntitlementValue = boolean | number;

/**
 * The sentinel an integer entitlement carries to mean "no ceiling".
 * `limit()` returns it as-is; compare against this constant rather than
 * testing for a negative number.
 *
 * ```ts
 * const n = lic.limit("max_projects");
 * if (n !== undefined && n !== UNLIMITED && used >= n) throw new Error("too many");
 * ```
 */
export const UNLIMITED = -1;

/**
 * Narrows a raw `ent` claim to the two types the format admits, dropping
 * everything else.
 *
 * Dropping rather than throwing is the contract, not laxity: rejecting a
 * token because a seller managed to get a string into one value would take a
 * working product offline for a data-entry mistake, on a machine that cannot
 * be reached to fix it. Refusing bad values is the server's job at write
 * time, where there is a human and an error message.
 *
 * `JSON.parse` gives back one numeric type, so an integer is recognised by
 * being whole rather than by its type: `25` and `25.0` are both 25, and
 * `1.5` is dropped for the same reason a string is — the format has no
 * float, and a value that survived here but nowhere else would be worse than
 * one that survived nowhere.
 *
 * Returns `undefined` when the claim is absent, which is a different thing
 * from an empty object — `hasEntitlements` reads exactly that distinction.
 */
export function decodeEntitlements(
  claims: Record<string, unknown>,
): Record<string, EntitlementValue> | undefined {
  const raw = claims["ent"];
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return undefined;
  }
  const out: Record<string, EntitlementValue> = {};
  for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
    if (typeof value === "boolean") {
      out[key] = value;
    } else if (typeof value === "number" && Number.isInteger(value)) {
      out[key] = value;
    }
  }
  return out;
}

/**
 * Whether the boolean entitlement named by `key` is present and true.
 *
 * A key that is absent, or that holds a number rather than a boolean,
 * answers `false`. There is no coercion across kinds: `can` on an integer
 * entitlement is false even when that integer is non-zero, because a rule
 * that read "nonzero is true" is one five SDKs would eventually disagree
 * about.
 */
export function can(
  entitlements: Readonly<Record<string, EntitlementValue>> | undefined,
  key: string,
): boolean {
  return entitlements?.[key] === true;
}

/**
 * The integer entitlement named by `key`, or `undefined` when it is absent.
 *
 * The unlimited sentinel is returned as-is: compare the result against
 * {@link UNLIMITED} rather than testing for a negative number. A key that
 * holds a boolean rather than a number misses — `limit` on a boolean is
 * `undefined`, not 1 or 0.
 */
export function limit(
  entitlements: Readonly<Record<string, EntitlementValue>> | undefined,
  key: string,
): number | undefined {
  const value = entitlements?.[key];
  return typeof value === "number" ? value : undefined;
}
