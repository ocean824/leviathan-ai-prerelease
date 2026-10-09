import {
  completeFeatureMapV1,
  FEATURE_KEYS_V1,
  FeatureCatalogErrorV1,
  validateFeatureRecordV1,
  type FeatureKeyV1,
} from "./feature_catalog.js";

export const ALL_ACCESS_PLAN_ID_V1 = "all_access_v1" as const;
export type PlanIdV1 = typeof ALL_ACCESS_PLAN_ID_V1;

export const FEATURE_LIMIT_KEYS_V1 = Object.freeze([
  "seat_limit", "broker_connection_limit", "data_source_limit", "live_account_limit",
] as const);
export type FeatureLimitKeyV1 = (typeof FEATURE_LIMIT_KEYS_V1)[number];

/** Coordinator defaults only; limit and price/cadence approval remain PROPOSED. */
export const ALL_ACCESS_LIMITS_PROPOSED_V1: Readonly<Record<FeatureLimitKeyV1, string>> =
  Object.freeze({
    seat_limit: "5",
    broker_connection_limit: "10",
    data_source_limit: "50",
    live_account_limit: "3",
  });
export const ALL_ACCESS_LIMITS_STATUS_V1 = "PROPOSED" as const;
export const ALL_ACCESS_LIMITS_APPROVED_STATUS_V1 = "APPROVED" as const;

export interface PlanCapsConfigurationV1 {
  readonly owner_internal_caps_approved: boolean;
  readonly stripe_caps_approved: boolean;
  readonly limits: Readonly<Record<FeatureLimitKeyV1, string>>;
}

/** Owner provisioning is approved for internal testing; paid grants await price/cap approval. */
export const DEFAULT_PLAN_CAPS_CONFIGURATION_V1: PlanCapsConfigurationV1 = Object.freeze({
  owner_internal_caps_approved: true,
  stripe_caps_approved: false,
  limits: ALL_ACCESS_LIMITS_PROPOSED_V1,
});

export type PlanFeatureErrorCodeV1 =
  | "UNKNOWN_PLAN" | "UNKNOWN_PRICE_ID" | "INVALID_PRICE_ID"
  | "DUPLICATE_PRICE_ID" | "PRICE_PLAN_CONFIGURATION_INVALID" | "CAPS_CONFIGURATION_INVALID"
  | "CAPS_NOT_APPROVED"
  | "INVALID_LIMIT" | "UNKNOWN_LIMIT" | "DUPLICATE_LIMIT" | "INCOMPLETE_LIMIT_MAP"
  | "LIMIT_CONFIGURATION_MISMATCH" | "PARTIAL_PLAN_FEATURES"
  | "OWNER_COMMAND_INVALID" | "OWNER_AUDIT_REQUIRED";

export class PlanFeatureErrorV1 extends Error {
  constructor(readonly code: PlanFeatureErrorCodeV1) {
    super(code);
    this.name = "PlanFeatureErrorV1";
  }
}

export interface PlanFeaturesV1 {
  readonly schema_version: 1;
  readonly plan_id: PlanIdV1;
  readonly features: Readonly<Record<FeatureKeyV1, true>>;
  readonly limits: Readonly<Record<FeatureLimitKeyV1, string>>;
  readonly limits_status: typeof ALL_ACCESS_LIMITS_STATUS_V1 | typeof ALL_ACCESS_LIMITS_APPROVED_STATUS_V1;
  readonly owner_internal_caps_approved: boolean;
  readonly stripe_caps_approved: boolean;
  readonly grantable: boolean;
}

export interface StripeActivePlanGrantV1 {
  readonly schema_version: 1;
  readonly status: "ACTIVE";
  readonly stripe_price_id: string;
  readonly plan_id: PlanIdV1;
  readonly features: Readonly<Record<FeatureKeyV1, true>>;
  readonly limits: Readonly<Record<FeatureLimitKeyV1, string>>;
  readonly stripe_caps_approved: true;
}

export interface FeatureLimitEntryV1 {
  readonly key: unknown;
  readonly value: unknown;
}

export interface StripePricePlanMappingV1 {
  readonly stripe_price_id: string;
  readonly plan_id: string;
}

const INTEGER = /^(0|[1-9][0-9]*)$/;
const MAX_PG_BIGINT = 9_223_372_036_854_775_807n;
const PRICE_ID = /^price_[A-Za-z0-9_]{3,127}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;

function canonicalLimits(
  entries: readonly FeatureLimitEntryV1[],
): Readonly<Record<FeatureLimitKeyV1, string>> {
  if (!Array.isArray(entries)) throw new PlanFeatureErrorV1("INCOMPLETE_LIMIT_MAP");
  const output: Partial<Record<FeatureLimitKeyV1, string>> = Object.create(null) as Partial<Record<FeatureLimitKeyV1, string>>;
  for (const entry of entries) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new PlanFeatureErrorV1("INVALID_LIMIT");
    }
    const key = entry.key;
    const value = entry.value;
    if (typeof key !== "string" || !(FEATURE_LIMIT_KEYS_V1 as readonly string[]).includes(key)) {
      throw new PlanFeatureErrorV1("UNKNOWN_LIMIT");
    }
    if (Object.hasOwn(output, key)) throw new PlanFeatureErrorV1("DUPLICATE_LIMIT");
    if (typeof value !== "string" || value.length > 19 || !INTEGER.test(value)
        || BigInt(value) > MAX_PG_BIGINT) {
      throw new PlanFeatureErrorV1("INVALID_LIMIT");
    }
    output[key as FeatureLimitKeyV1] = value;
  }
  if (FEATURE_LIMIT_KEYS_V1.some((key) => !Object.hasOwn(output, key))) {
    throw new PlanFeatureErrorV1("INCOMPLETE_LIMIT_MAP");
  }
  return Object.freeze(output as Record<FeatureLimitKeyV1, string>);
}

function canonicalCapsConfiguration(
  value: PlanCapsConfigurationV1 = DEFAULT_PLAN_CAPS_CONFIGURATION_V1,
): PlanCapsConfigurationV1 {
  if (value === null || typeof value !== "object" || Array.isArray(value)
      || typeof value.owner_internal_caps_approved !== "boolean"
      || typeof value.stripe_caps_approved !== "boolean" || value.limits === null
      || typeof value.limits !== "object" || Array.isArray(value.limits)) {
    throw new PlanFeatureErrorV1("CAPS_CONFIGURATION_INVALID");
  }
  const keys = Reflect.ownKeys(value.limits);
  if (keys.length !== FEATURE_LIMIT_KEYS_V1.length || keys.some((key) => typeof key !== "string"
      || !(FEATURE_LIMIT_KEYS_V1 as readonly string[]).includes(key))) {
    throw new PlanFeatureErrorV1("CAPS_CONFIGURATION_INVALID");
  }
  const limits = canonicalLimits(FEATURE_LIMIT_KEYS_V1.map((key) => ({ key, value: value.limits[key] })));
  return Object.freeze({ owner_internal_caps_approved: value.owner_internal_caps_approved,
    stripe_caps_approved: value.stripe_caps_approved, limits });
}

function planFromConfiguration(
  configuration: PlanCapsConfigurationV1,
  features: Readonly<Record<FeatureKeyV1, true>> = allAccessFeatures(),
): PlanFeaturesV1 {
  const caps = canonicalCapsConfiguration(configuration);
  return Object.freeze({ schema_version: 1, plan_id: ALL_ACCESS_PLAN_ID_V1,
    features, limits: caps.limits,
    limits_status: caps.stripe_caps_approved ? ALL_ACCESS_LIMITS_APPROVED_STATUS_V1 : ALL_ACCESS_LIMITS_STATUS_V1,
    owner_internal_caps_approved: caps.owner_internal_caps_approved,
    stripe_caps_approved: caps.stripe_caps_approved, grantable: caps.stripe_caps_approved });
}

function allAccessFeatures(): Readonly<Record<FeatureKeyV1, true>> {
  return completeFeatureMapV1(FEATURE_KEYS_V1.map((key) => [key, true] as const)) as
    Readonly<Record<FeatureKeyV1, true>>;
}

/** Build an all-access plan preview or grantable plan from shared cap config. */
export function allAccessPlanFeaturesV1(
  configuration: PlanCapsConfigurationV1 = DEFAULT_PLAN_CAPS_CONFIGURATION_V1,
): PlanFeaturesV1 {
  return planFromConfiguration(configuration);
}

export function validatePlanFeatureSetV1(
  value: unknown,
  configuration: PlanCapsConfigurationV1 = DEFAULT_PLAN_CAPS_CONFIGURATION_V1,
): value is PlanFeaturesV1 {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  let caps: PlanCapsConfigurationV1;
  try { caps = canonicalCapsConfiguration(configuration); }
  catch { return false; }
  const plan = value as Record<string, unknown>;
  if (plan.schema_version !== 1 || plan.plan_id !== ALL_ACCESS_PLAN_ID_V1
      || plan.owner_internal_caps_approved !== caps.owner_internal_caps_approved
      || plan.stripe_caps_approved !== caps.stripe_caps_approved || plan.grantable !== caps.stripe_caps_approved
      || plan.limits_status !== (caps.stripe_caps_approved ? ALL_ACCESS_LIMITS_APPROVED_STATUS_V1 : ALL_ACCESS_LIMITS_STATUS_V1)
      || !validateFeatureRecordV1(plan.features)) return false;
  if (FEATURE_KEYS_V1.some((key) => (plan.features as Record<string, boolean>)[key] !== true)) return false;
  if (plan.limits === null || typeof plan.limits !== "object" || Array.isArray(plan.limits)) return false;
  const limits = plan.limits as Record<string, unknown>;
  const keys = Reflect.ownKeys(limits);
  if (keys.length !== FEATURE_LIMIT_KEYS_V1.length || keys.some((key) => typeof key !== "string"
      || !(FEATURE_LIMIT_KEYS_V1 as readonly string[]).includes(key))) return false;
  return FEATURE_LIMIT_KEYS_V1.every((key) => limits[key] === caps.limits[key]);
}

/** Resolve only an explicitly configured Stripe price ID; unknown prices never fall back. */
export function resolvePlanForStripePriceV1(
  stripePriceId: string,
  mappings: readonly StripePricePlanMappingV1[],
  configuration: PlanCapsConfigurationV1 = DEFAULT_PLAN_CAPS_CONFIGURATION_V1,
): PlanFeaturesV1 {
  if (typeof stripePriceId !== "string" || !PRICE_ID.test(stripePriceId)) {
    throw new PlanFeatureErrorV1("INVALID_PRICE_ID");
  }
  if (!Array.isArray(mappings) || mappings.length === 0) {
    throw new PlanFeatureErrorV1("PRICE_PLAN_CONFIGURATION_INVALID");
  }
  const caps = canonicalCapsConfiguration(configuration);
  const seenPrices = new Set<string>();
  let matchingPlan: string | null = null;
  for (const mapping of mappings) {
    if (!mapping || typeof mapping !== "object" || !PRICE_ID.test(mapping.stripe_price_id)
        || typeof mapping.plan_id !== "string" || mapping.plan_id.length === 0) {
      throw new PlanFeatureErrorV1("PRICE_PLAN_CONFIGURATION_INVALID");
    }
    if (seenPrices.has(mapping.stripe_price_id)) throw new PlanFeatureErrorV1("DUPLICATE_PRICE_ID");
    seenPrices.add(mapping.stripe_price_id);
    if (mapping.plan_id !== ALL_ACCESS_PLAN_ID_V1) throw new PlanFeatureErrorV1("UNKNOWN_PLAN");
    if (mapping.stripe_price_id === stripePriceId) matchingPlan = mapping.plan_id;
  }
  if (matchingPlan === null) throw new PlanFeatureErrorV1("UNKNOWN_PRICE_ID");
  return planFromConfiguration(caps);
}

/** Construct an ACTIVE Stripe grant only after the shared caps config is approved. */
export function stripeActivePlanGrantV1(
  stripePriceId: string,
  mappings: readonly StripePricePlanMappingV1[],
  configuration: PlanCapsConfigurationV1 = DEFAULT_PLAN_CAPS_CONFIGURATION_V1,
): StripeActivePlanGrantV1 {
  const plan = resolvePlanForStripePriceV1(stripePriceId, mappings, configuration);
  if (!plan.stripe_caps_approved || !plan.grantable) throw new PlanFeatureErrorV1("CAPS_NOT_APPROVED");
  return Object.freeze({ schema_version: 1, status: "ACTIVE", stripe_price_id: stripePriceId,
    plan_id: plan.plan_id, features: plan.features, limits: plan.limits, stripe_caps_approved: true });
}

/** Validate externally supplied map entries before they become a LIC-001 snapshot. */
export function validateAllAccessMapsV1(
  featureEntries: readonly (readonly [unknown, unknown])[],
  limitEntries: readonly FeatureLimitEntryV1[],
  configuration: PlanCapsConfigurationV1 = DEFAULT_PLAN_CAPS_CONFIGURATION_V1,
): PlanFeaturesV1 {
  let features: Readonly<Record<FeatureKeyV1, boolean>>;
  try { features = completeFeatureMapV1(featureEntries); }
  catch (error) {
    if (error instanceof FeatureCatalogErrorV1) throw error;
    throw new FeatureCatalogErrorV1("INCOMPLETE_FEATURE_MAP");
  }
  if (FEATURE_KEYS_V1.some((key) => features[key] !== true)) {
    throw new PlanFeatureErrorV1("PARTIAL_PLAN_FEATURES");
  }
  const suppliedLimits = canonicalLimits(limitEntries);
  const caps = canonicalCapsConfiguration(configuration);
  if (FEATURE_LIMIT_KEYS_V1.some((key) => suppliedLimits[key] !== caps.limits[key])) {
    throw new PlanFeatureErrorV1("LIMIT_CONFIGURATION_MISMATCH");
  }
  return planFromConfiguration(caps, features as Readonly<Record<FeatureKeyV1, true>>);
}

export interface OwnerInternalSubscriptionCommandV1 {
  readonly schema_version: 1;
  readonly org_id: string;
  readonly subscription_id: string;
  readonly revision: "1";
  readonly status: "ACTIVE";
  readonly plan_id: typeof ALL_ACCESS_PLAN_ID_V1;
  readonly billing_reference: "invoice-internal-owner";
  readonly source_event_id: string;
  readonly billing_amount_decimal: null;
  readonly billing_currency: null;
  readonly term_start_utc_ns: string;
  readonly term_end_utc_ns: string;
  readonly features: Readonly<Record<FeatureKeyV1, true>>;
  readonly limits: Readonly<Record<FeatureLimitKeyV1, string>>;
  readonly owner_internal_caps_approved: true;
  readonly stripe_caps_approved: false;
  readonly limits_status: typeof ALL_ACCESS_LIMITS_STATUS_V1;
  readonly audit_required: true;
  readonly audit_event_payload: Readonly<{
    provisioning_kind: "INTERNAL_OWNER_NON_STRIPE";
    billing_reference: "invoice-internal-owner";
    owner_internal_caps_approved: true;
    stripe_caps_approved: false;
  }>;
  readonly authorization_bypass: false;
}

export interface OwnerInternalSubscriptionInputV1 {
  readonly org_id: string;
  readonly subscription_id: string;
  readonly source_event_id: string;
  readonly term_start_utc_ns: string;
  readonly term_end_utc_ns: string;
}

export interface OwnerInternalSubscriptionResultV1 {
  readonly subscription_id: string;
  readonly revision: string;
  readonly audit_id: string;
}

/**
 * Adapter must apply the normal LIC-002 ledger rules and emit SEC-005 in one
 * transaction. The billing reference satisfies the existing ledger pattern;
 * the audit payload records that this subscription is internal and non-Stripe.
 * Owner role never bypasses snapshot/role/route enforcement.
 */
export interface OwnerInternalSubscriptionPortV1 {
  createAuditedInternalSubscription(
    command: OwnerInternalSubscriptionCommandV1,
  ): Promise<OwnerInternalSubscriptionResultV1>;
}

export function ownerInternalSubscriptionCommandV1(
  input: OwnerInternalSubscriptionInputV1,
  configuration: PlanCapsConfigurationV1 = DEFAULT_PLAN_CAPS_CONFIGURATION_V1,
): OwnerInternalSubscriptionCommandV1 {
  const caps = canonicalCapsConfiguration(configuration);
  if (!caps.owner_internal_caps_approved) throw new PlanFeatureErrorV1("CAPS_NOT_APPROVED");
  if (!input || !IDENTIFIER.test(input.org_id) || !IDENTIFIER.test(input.subscription_id)
      || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,118}$/.test(input.source_event_id)
      || typeof input.term_start_utc_ns !== "string" || !/^(0|[1-9][0-9]{0,18})$/.test(input.term_start_utc_ns)
      || typeof input.term_end_utc_ns !== "string" || !/^(0|[1-9][0-9]{0,18})$/.test(input.term_end_utc_ns)
      || BigInt(input.term_start_utc_ns) > 9_223_372_036_854_775_807n
      || BigInt(input.term_end_utc_ns) > 9_223_372_036_854_775_807n
      || BigInt(input.term_end_utc_ns) <= BigInt(input.term_start_utc_ns)) {
    throw new PlanFeatureErrorV1("OWNER_COMMAND_INVALID");
  }
  const plan = allAccessPlanFeaturesV1(caps);
  return Object.freeze({ schema_version: 1, org_id: input.org_id,
    subscription_id: input.subscription_id, revision: "1", status: "ACTIVE",
    plan_id: ALL_ACCESS_PLAN_ID_V1, billing_reference: "invoice-internal-owner",
    source_event_id: `internal:${input.source_event_id}`,
    billing_amount_decimal: null, billing_currency: null,
    term_start_utc_ns: input.term_start_utc_ns, term_end_utc_ns: input.term_end_utc_ns,
    features: plan.features, limits: plan.limits, owner_internal_caps_approved: true,
    stripe_caps_approved: false, limits_status: ALL_ACCESS_LIMITS_STATUS_V1, audit_required: true,
    audit_event_payload: Object.freeze({ provisioning_kind: "INTERNAL_OWNER_NON_STRIPE",
      billing_reference: "invoice-internal-owner", owner_internal_caps_approved: true,
      stripe_caps_approved: false }),
    authorization_bypass: false });
}

/** Internal provisioning is an explicit audited ledger call, never a role-derived grant. */
export async function provisionOwnerInternalSubscriptionV1(
  port: OwnerInternalSubscriptionPortV1,
  input: OwnerInternalSubscriptionInputV1,
  configuration: PlanCapsConfigurationV1 = DEFAULT_PLAN_CAPS_CONFIGURATION_V1,
): Promise<OwnerInternalSubscriptionResultV1> {
  const caps = canonicalCapsConfiguration(configuration);
  if (!caps.owner_internal_caps_approved) throw new PlanFeatureErrorV1("CAPS_NOT_APPROVED");
  if (!port || typeof port.createAuditedInternalSubscription !== "function") {
    throw new PlanFeatureErrorV1("OWNER_AUDIT_REQUIRED");
  }
  const command = ownerInternalSubscriptionCommandV1(input, caps);
  const result = await port.createAuditedInternalSubscription(command);
  if (!result || result.subscription_id !== command.subscription_id || result.revision !== "1"
      || typeof result.audit_id !== "string" || !IDENTIFIER.test(result.audit_id)) {
    throw new PlanFeatureErrorV1("OWNER_AUDIT_REQUIRED");
  }
  return Object.freeze({ ...result });
}
