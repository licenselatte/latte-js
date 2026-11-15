/**
 * Server-side client for the LicenseLatte admin REST API: issue, inspect,
 * update, suspend, revoke and release licenses from your own backend.
 *
 * An API key is a secret. Import this entry point (`@licenselatte/latte/admin`)
 * only in code you run yourself and never in an application you ship to end
 * users or bundle for a browser. It needs a global `fetch` (Node 19+), and the
 * default entry point never imports it.
 *
 * Objects keep the API's own snake_case field names, and any field this
 * version does not model is still readable through the index signature.
 */

export const DEFAULT_BASE_URL = "https://api.licenselatte.com/v1";

export type LicenseStatus =
  | "active"
  | "expired"
  | "revoked"
  | "suspended"
  | "pending_deactivation";

export type Metadata = Record<string, unknown>;

export interface License {
  id: string;
  project_id: string;
  policy_id: string;
  license_key: string;
  status: LicenseStatus;
  expires_at: string | null;
  metadata: Metadata;
  client_metadata: Metadata;
  created_at: string;
  updated_at: string;
  [field: string]: unknown;
}

export interface Policy {
  id: string;
  name: string;
  license_type: string;
  expiry_mode: string;
  expiry_date: string | null;
  expiry_days: number | null;
  max_activations: number | null;
  grace_period_hours: number | null;
  created_at: string;
  [field: string]: unknown;
}

export interface Activation {
  id: string;
  status: string;
  machine_id_hash: string;
  activated_at: string | null;
  last_renewed_at: string | null;
  deactivated_at: string | null;
  seat_held_until: string | null;
  sdk: unknown;
  metadata: Metadata | null;
  [field: string]: unknown;
}

export interface LicenseList {
  licenses: License[];
  /** The number of licenses in the project, not in this page. */
  total: number;
}

export interface IssueLicenseParams {
  policy_id: string;
  /** Setting it also emails the buyer their key, when the project allows it. */
  customer_email?: string;
  metadata?: Metadata;
  client_metadata?: Metadata;
}

export interface ListLicensesParams {
  /** Omit, or send 0, for every license. */
  limit?: number;
  offset?: number;
  customer_email?: string;
  status?: LicenseStatus;
}

export interface UpdateLicenseParams {
  /** Replaces the stored object wholesale. */
  metadata?: Metadata;
  /** Replaces the stored object wholesale. */
  client_metadata?: Metadata;
  /** A new expiry (a Date is sent as RFC 3339), or null to clear it. */
  expires_at?: Date | string | null;
}

export interface AdminClientOptions {
  /** Defaults to DEFAULT_BASE_URL. */
  baseUrl?: string;
  /** Replaces the global `fetch`. */
  fetch?: typeof fetch;
  /** Per-request timeout. Defaults to 30000; 0 disables it. */
  timeoutMs?: number;
}

/**
 * A non-2xx answer from the API. Branch on `status`; `message` is written for
 * a human reading a log. `code` is a machine-readable refusal code when the
 * API sends one, such as "plan_license_limit_reached" on a 409 from issue.
 */
export class AdminApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
    public readonly code?: string,
  ) {
    super(message);
    this.name = "AdminApiError";
  }
}

export class AdminClient {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly fetchFn: typeof fetch;
  private readonly timeoutMs: number;

  constructor(apiKey: string, options: AdminClientOptions = {}) {
    if (!apiKey) throw new TypeError("AdminClient: apiKey is required");
    this.apiKey = apiKey;
    this.baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
    this.fetchFn = options.fetch ?? ((...args) => fetch(...args));
    this.timeoutMs = options.timeoutMs ?? 30_000;
  }

  issueLicense(params: IssueLicenseParams): Promise<License> {
    return this.request("POST", "/licenses", { body: params });
  }

  listLicenses(params: ListLicensesParams = {}): Promise<LicenseList> {
    const q = new URLSearchParams();
    if (params.limit) q.set("limit", String(params.limit));
    if (params.offset) q.set("offset", String(params.offset));
    if (params.customer_email) q.set("customer_email", params.customer_email);
    if (params.status) q.set("status", params.status);
    return this.request("GET", "/licenses", { query: q });
  }

  getLicense(licenseKey: string): Promise<License> {
    return this.request("GET", licensePath(licenseKey));
  }

  updateLicense(
    licenseKey: string,
    params: UpdateLicenseParams,
  ): Promise<License> {
    const { expires_at, ...rest } = params;
    const body: Record<string, unknown> = { ...rest };
    if (expires_at !== undefined) {
      body.expires_at =
        expires_at instanceof Date ? expires_at.toISOString() : expires_at;
    }
    return this.request("PATCH", licensePath(licenseKey), { body });
  }

  async revokeLicense(licenseKey: string): Promise<void> {
    await this.request("DELETE", licensePath(licenseKey));
  }

  suspendLicense(licenseKey: string): Promise<License> {
    return this.request("POST", licensePath(licenseKey, "suspend"));
  }

  reinstateLicense(licenseKey: string): Promise<License> {
    return this.request("POST", licensePath(licenseKey, "reinstate"));
  }

  async listActivations(licenseKey: string): Promise<Activation[]> {
    const out = await this.request<{ activations: Activation[] }>(
      "GET",
      licensePath(licenseKey, "activations"),
    );
    return out.activations;
  }

  /** Frees one machine's seat. */
  async releaseActivation(
    licenseKey: string,
    activationId: string,
  ): Promise<void> {
    await this.request(
      "DELETE",
      licensePath(licenseKey, "activations", activationId),
    );
  }

  /** Queues the license-key email to the buyer again. */
  async resendLicenseEmail(licenseKey: string): Promise<void> {
    await this.request("POST", licensePath(licenseKey, "resend"));
  }

  async listPolicies(): Promise<Policy[]> {
    const out = await this.request<{ policies: Policy[] }>("GET", "/policies");
    return out.policies;
  }

  private async request<T>(
    method: string,
    path: string,
    opts: { query?: URLSearchParams; body?: unknown } = {},
  ): Promise<T> {
    const qs = opts.query?.toString();
    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.apiKey}`,
      Accept: "application/json",
    };
    const init: RequestInit = { method, headers };
    if (opts.body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(opts.body);
    }
    if (this.timeoutMs > 0) init.signal = AbortSignal.timeout(this.timeoutMs);

    const res = await this.fetchFn(
      this.baseUrl + path + (qs ? `?${qs}` : ""),
      init,
    );
    const text = await res.text();
    if (!res.ok) {
      let message = res.statusText || `HTTP ${res.status}`;
      let code: string | undefined;
      try {
        const b = JSON.parse(text) as { error?: unknown; code?: unknown };
        if (typeof b.error === "string" && b.error) message = b.error;
        if (typeof b.code === "string") code = b.code;
      } catch {
        // not JSON: keep the status text
      }
      throw new AdminApiError(res.status, message, code);
    }
    return (text ? JSON.parse(text) : undefined) as T;
  }
}

function licensePath(key: string, ...rest: string[]): string {
  return ["/licenses", ...[key, ...rest].map(encodeURIComponent)].join("/");
}
