import { readdir, readFile } from "node:fs/promises";
import { describe, expect, it, vi } from "vitest";
import { REGISTRY } from "../../../apps/terminal/src/navigation/registry.js";
import {
  API_FEATURE_ACTIONS_V1,
  catalogCompletenessErrorV1,
  completeFeatureMapV1,
  FEATURE_CATALOG_V1,
  FEATURE_KEYS_V1,
  featureForApiActionV1,
  featureForNavigationCodeV1,
  isFeatureKeyV1,
  NAVIGATION_FEATURES_V1,
  validateFeatureRecordV1,
} from "../src/entitlement/feature_catalog.js";
import {
  ALL_ACCESS_LIMITS_PROPOSED_V1,
  ALL_ACCESS_LIMITS_STATUS_V1,
  ALL_ACCESS_PLAN_ID_V1,
  allAccessPlanFeaturesV1,
  DEFAULT_PLAN_CAPS_CONFIGURATION_V1,
  ownerInternalSubscriptionCommandV1,
  PlanFeatureErrorV1,
  provisionOwnerInternalSubscriptionV1,
  resolvePlanForStripePriceV1,
  stripeActivePlanGrantV1,
  validateAllAccessMapsV1,
  validatePlanFeatureSetV1,
  type FeatureLimitEntryV1,
  type StripePricePlanMappingV1,
} from "../src/entitlement/plan_features.js";

const ROOT = new URL("../../../", import.meta.url);

function featureEntries(value = true) {
  return FEATURE_KEYS_V1.map((key) => [key, value] as const);
}

function limitEntries(): FeatureLimitEntryV1[] {
  return [
    { key: "seat_limit", value: "5" },
    { key: "broker_connection_limit", value: "10" },
    { key: "data_source_limit", value: "50" },
    { key: "live_account_limit", value: "3" },
  ];
}

const APPROVED_CAPS = Object.freeze({
  owner_internal_caps_approved: true,
  stripe_caps_approved: true,
  limits: Object.freeze({ seat_limit: "5", broker_connection_limit: "10",
    data_source_limit: "50", live_account_limit: "3" }),
});

function sourcePrefix(source: string): string {
  const direct = /\brouter\s*=\s*APIRouter\s*\([\s\S]{0,200}?prefix\s*=\s*["']([^"']+)["']/m.exec(source)?.[1];
  const constant = /_ROUTER_PREFIX\s*:\s*Final\s*=\s*["']([^"']+)["']/.exec(source)?.[1];
  return direct ?? constant ?? "";
}

function pathJoin(prefix: string, path: string): string {
  const joined = `${prefix.replace(/\/$/, "")}/${path.replace(/^\//, "")}`;
  return joined === "/" ? "/" : joined.replace(/\/$/, "");
}

async function currentApiRouteIds(): Promise<string[]> {
  const directory = new URL("apps/api/src/leviathan_api/routers/", ROOT);
  const entries = await readdir(directory, { withFileTypes: true });
  const files = entries.filter((entry) => entry.isFile() && entry.name.endsWith(".py"));
  const ids: string[] = [];
  for (const file of files) {
    const source = await readFile(new URL(file.name, directory), "utf8");
    const prefix = sourcePrefix(source);
    const pattern = /^\s*@router\.(get|post|put|patch|delete)\(\s*["']([^"']*)["']/gim;
    for (const match of source.matchAll(pattern)) {
      const method = match[1]!.toUpperCase();
      const path = pathJoin(prefix, match[2]!);
      ids.push(`${method} ${path}`);
    }
  }
  return ids.sort();
}

async function currentMountedApiRouteIds(): Promise<string[]> {
  const mountPath = new URL("apps/api/src/leviathan_api/wave35_mounts.py", ROOT);
  const mainPath = new URL("apps/api/src/leviathan_api/main.py", ROOT);
  const [mountSource, mainSource] = await Promise.all([
    readFile(mountPath, "utf8"), readFile(mainPath, "utf8"),
  ]);
  expect(mainSource).toContain("configure_wave35_mounts(");
  const mountTable = /for item, prefix in \(([\s\S]*?)\n\s*\):\s*\n\s*app\.include_router\(item, prefix=prefix\)/
    .exec(mountSource)?.[1];
  expect(mountTable, "production route mount tuple is present").toBeDefined();
  const moduleMountEntries: Readonly<Record<string, RegExp>> = {
    "data_sources.py": /data_sources\.create_data_sources_router\(registry\)/,
    "preferences.py": /\(preferences_router\s*,/,
    "chat_history.py": /\(history_router\s*,/,
    "chat_models.py": /\(models_router\s*,/,
    "mt5_ea_host.py": /\(ea_router\s*,/,
    "connections.py": /\(connections_router\s*,/,
    "chat_tools.py": /\(chat_tools_router\s*,/,
    "live_activation.py": /\(live_activation_router\s*,/,
  };
  const directory = new URL("apps/api/src/leviathan_api/routers/", ROOT);
  const ids: string[] = [];
  for (const [name, mountEntry] of Object.entries(moduleMountEntries)) {
    if (!mountEntry.test(mountTable!)) continue;
    const source = await readFile(new URL(name, directory), "utf8");
    const prefix = sourcePrefix(source);
    const pattern = /^\s*@router\.(get|post|put|patch|delete)\(\s*["']([^"']*)["']/gim;
    for (const match of source.matchAll(pattern)) {
      ids.push(`${match[1]!.toUpperCase()} ${pathJoin(prefix, match[2]!)}`);
    }
  }
  return ids.sort();
}

describe("closed entitlement feature catalog", () => {
  it("binds chart ticket minting to charts as a read action", () => {
    expect(featureForApiActionV1("POST", "/md/chart/ticket")).toBe("charts");
    expect(API_FEATURE_ACTIONS_V1.find((action) => action.action_id === "POST /md/chart/ticket"))
      .toMatchObject({ feature_key: "charts", classification: "READ", registration: "MOUNTED" });
  });

  it("maps every current terminal navigation registry code exactly once", () => {
    const registryCodes = REGISTRY.map((entry) => entry.code);
    expect(catalogCompletenessErrorV1(registryCodes)).toBeNull();
    expect(NAVIGATION_FEATURES_V1.map((binding) => binding.navigation_code).sort())
      .toEqual([...registryCodes].sort());
    expect(new Set(NAVIGATION_FEATURES_V1.map((binding) => binding.navigation_code)).size)
      .toBe(registryCodes.length);
    for (const entry of REGISTRY) expect(featureForNavigationCodeV1(entry.code)).not.toBeNull();
    expect(featureForNavigationCodeV1("NOT_A_NAV_CODE")).toBeNull();
    expect(featureForNavigationCodeV1("DATA")).toBe("data_sources");
    expect(featureForNavigationCodeV1("CHRT")).toBe("charts");
    expect(featureForNavigationCodeV1("PORD")).toBe("paper_trading");
    expect(FEATURE_CATALOG_V1.find((feature) => feature.feature_key === "live_trading")?.requirement_ids)
      .toContain("LEV-REQ-004");
  });

  it("requires every discovered mutating or pre-registered API route to have its exact closed binding", async () => {
    const actualIds = API_FEATURE_ACTIONS_V1.map((action) => action.action_id).sort();
    const discoveredIds = await currentApiRouteIds();
    const mountedIds = await currentMountedApiRouteIds();
    const preRegisteredIds = new Set(API_FEATURE_ACTIONS_V1.map((action) => action.action_id));
    expect(new Set(actualIds).size).toBe(actualIds.length);
    expect(new Set(API_FEATURE_ACTIONS_V1.map((action) => `${action.method} ${action.path}`)).size)
      .toBe(API_FEATURE_ACTIONS_V1.length);
    for (const action of API_FEATURE_ACTIONS_V1) {
      expect(isFeatureKeyV1(action.feature_key)).toBe(true);
      expect(featureForApiActionV1(action.method, action.path)).toBe(action.feature_key);
      expect(action.action_id).toBe(`${action.method} ${action.path}`);
    }
    const requiredDiscoveredIds = discoveredIds.filter((id) => !id.startsWith("GET ") || preRegisteredIds.has(id));
    for (const id of requiredDiscoveredIds) {
      const action = API_FEATURE_ACTIONS_V1.find((candidate) => candidate.action_id === id);
      if (!action) throw new Error(`UNMAPPED_API_ROUTE: ${id}`);
    }
    for (const id of mountedIds) {
      expect(API_FEATURE_ACTIONS_V1.find((action) => action.action_id === id),
        `production mounted route must be bound and marked MOUNTED: ${id}`)
        .toMatchObject({ registration: "MOUNTED" });
    }
    expect(API_FEATURE_ACTIONS_V1.filter((action) => action.registration === "WORKER_ROUTE")).toMatchObject([
      { action_id: "POST /v1/signup/checkout", feature_key: "admin_console", classification: "WRITE" },
      { action_id: "POST /v1/signup/webhook", feature_key: "admin_console", classification: "WRITE" },
    ]);
    for (const action of API_FEATURE_ACTIONS_V1.filter((candidate) => candidate.registration === "PLANNED")) {
      expect(action.action_id).toBe(`${action.method} ${action.path}`);
    }
    expect(API_FEATURE_ACTIONS_V1.find((action) => action.action_id === "POST /chat/complete"))
      .toMatchObject({ feature_key: "chat_terminal", classification: "WRITE", registration: "MOUNTED" });
    expect(API_FEATURE_ACTIONS_V1.find((action) => action.action_id === "POST /chat/stream"))
      .toMatchObject({ feature_key: "chat_terminal", classification: "WRITE", registration: "MOUNTED" });
    const plannedBindings = API_FEATURE_ACTIONS_V1.filter((action) => action.registration === "PLANNED");
    expect(plannedBindings.map((action) => action.action_id).sort()).toEqual([
      "GET /live-activation/status",
      "POST /chat/tools/confirm", "POST /chat/tools/plan", "POST /chat/tools/read",
      "GET /chat/tools/registry", "POST /live-activation/disable", "POST /live-activation/enable",
    ].sort());
    for (const action of plannedBindings) {
      expect(action.action_id).toBe(`${action.method} ${action.path}`);
    }
    for (const action of plannedBindings) {
      if (discoveredIds.includes(action.action_id)) {
        expect(mountedIds, `unmounted planned route remains outside production mount table: ${action.action_id}`)
          .not.toContain(action.action_id);
      }
    }
    for (const [actionId, featureKey, classification] of [
      ["GET /chat/tools/registry", "chat_terminal", "READ"],
      ["POST /chat/tools/plan", "chat_terminal", "WRITE"],
      ["POST /chat/tools/confirm", "chat_terminal", "WRITE"],
      ["POST /chat/tools/read", "chat_terminal", "READ"],
      ["GET /live-activation/status", "live_trading", "READ"],
      ["POST /live-activation/enable", "live_trading", "WRITE"],
      ["POST /live-activation/disable", "live_trading", "WRITE"],
    ] as const) {
      expect(API_FEATURE_ACTIONS_V1.find((action) => action.action_id === actionId))
        .toMatchObject({ feature_key: featureKey, classification, registration: "PLANNED" });
    }
    for (const [actionId, classification] of [
      ["GET /connections/catalog", "READ"],
      ["GET /connections/status", "READ"],
      ["POST /connections/{provider}/connect", "WRITE"],
      ["POST /connections/{provider}/cancel", "WRITE"],
      ["POST /connections/{provider}/disconnect", "WRITE"],
    ] as const) {
      expect(API_FEATURE_ACTIONS_V1.find((action) => action.action_id === actionId))
        .toMatchObject({ feature_key: "connections", classification, registration: "MOUNTED" });
      expect(discoveredIds).toContain(actionId);
      expect(mountedIds).toContain(actionId);
      expect(featureForApiActionV1(actionId.split(" ")[0]!, actionId.slice(actionId.indexOf(" ") + 1)))
        .toBe("connections");
    }
    expect(isFeatureKeyV1("user_settings")).toBe(true);
    expect(featureForApiActionV1("POST", "/unregistered/mutation")).toBeNull();
    for (const path of ["/mt5/ea-host/v1/install", "/mt5/ea-host/v1/sessions/{session_id}/kill"]) {
      expect(featureForApiActionV1("POST", path)).toBe("ea_hosting");
      expect(API_FEATURE_ACTIONS_V1.find((action) => action.path === path)).toMatchObject({
        classification: "WRITE", registration: "MOUNTED",
      });
    }
    expect(featureForApiActionV1("POST", "/mcp/actions/dry-run")).toBe("chat_terminal");
    expect(API_FEATURE_ACTIONS_V1.find((action) => action.path === "/mcp/actions/dry-run"))
      .toMatchObject({ classification: "WRITE" });
    for (const path of ["/api/preferences/{namespace}"]) {
      expect(featureForApiActionV1("PUT", path)).toBe("user_settings");
      expect(featureForApiActionV1("DELETE", path)).toBe("user_settings");
      const actions = API_FEATURE_ACTIONS_V1.filter((action) => action.path === path);
      expect(actions).toHaveLength(3);
      expect(actions.find((action) => action.method === "GET"))
        .toMatchObject({ classification: "READ", registration: "MOUNTED" });
      expect(actions.filter((action) => action.method !== "GET").every((action) =>
        action.classification === "WRITE" && action.registration === "MOUNTED")).toBe(true);
    }
    for (const [method, path] of [
      ["POST", "/chat/history/conversations"],
      ["POST", "/chat/history/conversations/{conversation_id}/messages"],
      ["DELETE", "/chat/history/conversations/{conversation_id}"],
    ] as const) {
      expect(featureForApiActionV1(method, path)).toBe("chat_terminal");
      expect(API_FEATURE_ACTIONS_V1.find((action) => action.action_id === `${method} ${path}`))
        .toMatchObject({ classification: "WRITE", registration: "MOUNTED" });
    }
    expect(API_FEATURE_ACTIONS_V1.filter((action) => action.classification === "SAFETY_OFF").length)
      .toBeGreaterThan(0);
    expect(FEATURE_CATALOG_V1).toHaveLength(FEATURE_KEYS_V1.length);
    expect(FEATURE_CATALOG_V1.every((feature) => feature.deny_behavior === "HIDE_DESTINATION_AND_DENY_ACTION"))
      .toBe(true);
  });

  it("rejects duplicate, unknown, partial and non-boolean feature entries", () => {
    const valid = completeFeatureMapV1(featureEntries());
    expect(validateFeatureRecordV1(valid)).toBe(true);
    expect(Object.keys(valid).sort()).toEqual([...FEATURE_KEYS_V1].sort());
    expect(() => completeFeatureMapV1([...featureEntries(), ["paper_trading", true]])).toThrow(/DUPLICATE_FEATURE/);
    expect(() => completeFeatureMapV1([...featureEntries(), ["unknown_key", true]])).toThrow(/UNKNOWN_FEATURE/);
    expect(() => completeFeatureMapV1(featureEntries().slice(1))).toThrow(/INCOMPLETE_FEATURE_MAP/);
    expect(() => completeFeatureMapV1(FEATURE_KEYS_V1.map((key) => [key, "true"]))).toThrow(/INVALID_FEATURE_VALUE/);
    expect(validateFeatureRecordV1({ ...valid, unknown_key: true })).toBe(false);
    expect(validateFeatureRecordV1(Object.fromEntries(FEATURE_KEYS_V1.slice(1).map((key) => [key, true])))).toBe(false);
  });
});

describe("all-access plan features", () => {
  it("builds a non-grantable proposed preview using exact integer limits", () => {
    const plan = allAccessPlanFeaturesV1();
    expect(plan).toEqual({ schema_version: 1, plan_id: "all_access_v1",
      features: Object.fromEntries(FEATURE_KEYS_V1.map((key) => [key, true])),
      limits: { seat_limit: "5", broker_connection_limit: "10", data_source_limit: "50", live_account_limit: "3" },
      limits_status: "PROPOSED", owner_internal_caps_approved: true,
      stripe_caps_approved: false, grantable: false });
    expect(ALL_ACCESS_PLAN_ID_V1).toBe("all_access_v1");
    expect(ALL_ACCESS_LIMITS_PROPOSED_V1).toEqual({ seat_limit: "5",
      broker_connection_limit: "10", data_source_limit: "50", live_account_limit: "3" });
    expect(ALL_ACCESS_LIMITS_STATUS_V1).toBe("PROPOSED");
    expect(validatePlanFeatureSetV1(plan)).toBe(true);
    expect(validatePlanFeatureSetV1({ ...plan, plan_id: "unknown_plan" })).toBe(false);
    expect(validatePlanFeatureSetV1({ ...plan, features: { paper_trading: true } })).toBe(false);
  });

  it("resolves only explicit configured Stripe price mappings and fails closed on ambiguity", () => {
    const configured: StripePricePlanMappingV1[] = [
      { stripe_price_id: "price_all_access_test", plan_id: "all_access_v1" },
    ];
    expect(resolvePlanForStripePriceV1("price_all_access_test", configured).plan_id).toBe("all_access_v1");
    const multiplePrices: StripePricePlanMappingV1[] = [
      { stripe_price_id: "price_monthly_test", plan_id: "all_access_v1" },
      { stripe_price_id: "price_annual_test", plan_id: "all_access_v1" },
    ];
    expect(resolvePlanForStripePriceV1("price_monthly_test", multiplePrices).plan_id).toBe("all_access_v1");
    expect(resolvePlanForStripePriceV1("price_annual_test", multiplePrices).plan_id).toBe("all_access_v1");
    expect(() => resolvePlanForStripePriceV1("price_unknown_test", configured)).toThrow(/UNKNOWN_PRICE_ID/);
    expect(() => resolvePlanForStripePriceV1("price_all_access_test", [])).toThrow(/PRICE_PLAN_CONFIGURATION_INVALID/);
    expect(() => resolvePlanForStripePriceV1("not_a_price", configured)).toThrow(/INVALID_PRICE_ID/);
    expect(() => resolvePlanForStripePriceV1("price_all_access_test", [
      ...configured, { stripe_price_id: "price_all_access_test", plan_id: "all_access_v1" },
    ])).toThrow(/DUPLICATE_PRICE_ID/);
    expect(() => resolvePlanForStripePriceV1("price_all_access_test", [
      { stripe_price_id: "price_all_access_test", plan_id: "unknown_plan" },
    ])).toThrow(/UNKNOWN_PLAN/);
  });

  it("rejects partial, duplicate, unknown and non-exact feature/limit maps", () => {
    expect(validateAllAccessMapsV1(featureEntries(), limitEntries()).plan_id).toBe("all_access_v1");
    expect(() => validateAllAccessMapsV1(featureEntries().slice(1), limitEntries())).toThrow(/INCOMPLETE_FEATURE_MAP/);
    expect(() => validateAllAccessMapsV1([...featureEntries(), ["charts", true]], limitEntries())).toThrow(/DUPLICATE_FEATURE/);
    expect(() => validateAllAccessMapsV1([...featureEntries(), ["unlisted", true]], limitEntries())).toThrow(/UNKNOWN_FEATURE/);
    expect(() => validateAllAccessMapsV1(FEATURE_KEYS_V1.map((key) => [key, false]), limitEntries()))
      .toThrow(/PARTIAL_PLAN_FEATURES/);
    expect(() => validateAllAccessMapsV1(featureEntries(), limitEntries().slice(1))).toThrow(/INCOMPLETE_LIMIT_MAP/);
    expect(() => validateAllAccessMapsV1(featureEntries(), [...limitEntries(), { key: "seat_limit", value: "5" }]))
      .toThrow(/DUPLICATE_LIMIT/);
    expect(() => validateAllAccessMapsV1(featureEntries(), [...limitEntries(), { key: "unknown_limit", value: "1" }]))
      .toThrow(/UNKNOWN_LIMIT/);
    expect(() => validateAllAccessMapsV1(featureEntries(), limitEntries().map((entry) =>
      entry.key === "seat_limit" ? { key: entry.key, value: 5 } : entry)))
      .toThrow(/INVALID_LIMIT/);
    expect(() => validateAllAccessMapsV1(featureEntries(), limitEntries().map((entry) =>
      entry.key === "seat_limit" ? { key: entry.key, value: "5.0" } : entry)))
      .toThrow(/INVALID_LIMIT/);
    const approvedCapsChanged = { owner_internal_caps_approved: true, stripe_caps_approved: true, limits: {
      seat_limit: "6", broker_connection_limit: "10", data_source_limit: "50", live_account_limit: "3",
    } } as const;
    const changedPlan = allAccessPlanFeaturesV1(approvedCapsChanged);
    expect(changedPlan.limits.seat_limit).toBe("6");
    expect(changedPlan.grantable).toBe(true);
    expect(validatePlanFeatureSetV1(changedPlan, approvedCapsChanged)).toBe(true);
    expect(validatePlanFeatureSetV1(changedPlan)).toBe(false);
    expect(validateAllAccessMapsV1(featureEntries(), [
      { key: "seat_limit", value: "6" }, ...limitEntries().slice(1),
    ], approvedCapsChanged)).toEqual(changedPlan);
    expect(() => validateAllAccessMapsV1(featureEntries(), limitEntries(), approvedCapsChanged))
      .toThrow(/LIMIT_CONFIGURATION_MISMATCH/);
  });

  it("blocks paid grants on proposed caps while allowing audited Owner provisioning", async () => {
    const mappings = [{ stripe_price_id: "price_all_access_test", plan_id: "all_access_v1" }] as const;
    expect(allAccessPlanFeaturesV1(DEFAULT_PLAN_CAPS_CONFIGURATION_V1)).toMatchObject({
      limits_status: "PROPOSED", owner_internal_caps_approved: true,
      stripe_caps_approved: false, grantable: false,
    });
    expect(() => stripeActivePlanGrantV1("price_all_access_test", mappings))
      .toThrowError(expect.objectContaining({ code: "CAPS_NOT_APPROVED" }));
    const input = { org_id: "owner_org", subscription_id: "owner_sub", source_event_id: "owner_seed_1",
      term_start_utc_ns: "100", term_end_utc_ns: "200" };
    const writer = vi.fn();
    const command = ownerInternalSubscriptionCommandV1(input);
    expect(command).toMatchObject({ status: "ACTIVE", limits_status: "PROPOSED",
      owner_internal_caps_approved: true, stripe_caps_approved: false,
      billing_reference: "invoice-internal-owner", source_event_id: "internal:owner_seed_1",
      billing_amount_decimal: null, billing_currency: null,
      audit_event_payload: { provisioning_kind: "INTERNAL_OWNER_NON_STRIPE" } });
    await expect(provisionOwnerInternalSubscriptionV1({
      createAuditedInternalSubscription: vi.fn(async () => ({ subscription_id: "owner_sub",
        revision: "1", audit_id: "owner_audit_1" })),
    }, input)).resolves.toMatchObject({ audit_id: "owner_audit_1" });
    const deniedWriter = vi.fn();
    const ownerApprovalRevoked = { ...DEFAULT_PLAN_CAPS_CONFIGURATION_V1, owner_internal_caps_approved: false };
    expect(() => ownerInternalSubscriptionCommandV1(input, ownerApprovalRevoked)).toThrowError(
      expect.objectContaining({ code: "CAPS_NOT_APPROVED" }));
    await expect(provisionOwnerInternalSubscriptionV1({ createAuditedInternalSubscription: deniedWriter }, input,
      ownerApprovalRevoked)).rejects.toThrowError(expect.objectContaining({ code: "CAPS_NOT_APPROVED" }));
    expect(deniedWriter).not.toHaveBeenCalled();
  });

  it("creates approved Stripe and audited internal Owner grants from shared limits", async () => {
    const input = { org_id: "owner_org", subscription_id: "owner_sub", source_event_id: "owner_seed_1",
      term_start_utc_ns: "100", term_end_utc_ns: "200" };
    const command = ownerInternalSubscriptionCommandV1(input, APPROVED_CAPS);
    expect(command).toMatchObject({ status: "ACTIVE", plan_id: "all_access_v1",
      billing_reference: "invoice-internal-owner", source_event_id: "internal:owner_seed_1",
      billing_amount_decimal: null, billing_currency: null,
      owner_internal_caps_approved: true, stripe_caps_approved: false, limits_status: "PROPOSED",
      audit_event_payload: { provisioning_kind: "INTERNAL_OWNER_NON_STRIPE",
        billing_reference: "invoice-internal-owner", owner_internal_caps_approved: true,
        stripe_caps_approved: false },
      audit_required: true, authorization_bypass: false });
    expect(command.features).toEqual(allAccessPlanFeaturesV1(APPROVED_CAPS).features);
    expect(command.limits).toEqual(allAccessPlanFeaturesV1(APPROVED_CAPS).limits);
    expect("role" in command).toBe(false);
    expect(() => ownerInternalSubscriptionCommandV1({ ...input, term_end_utc_ns: "100" }, APPROVED_CAPS))
      .toThrow(/OWNER_COMMAND_INVALID/);
    expect(() => ownerInternalSubscriptionCommandV1({ ...input, term_end_utc_ns: "9223372036854775808" }, APPROVED_CAPS))
      .toThrow(/OWNER_COMMAND_INVALID/);

    const stripeGrant = stripeActivePlanGrantV1("price_all_access_test", [
      { stripe_price_id: "price_all_access_test", plan_id: "all_access_v1" },
    ], APPROVED_CAPS);
    expect(stripeGrant).toMatchObject({ status: "ACTIVE", stripe_caps_approved: true,
      plan_id: "all_access_v1", limits: APPROVED_CAPS.limits });

    const writer = vi.fn(async (received) => ({ subscription_id: received.subscription_id,
      revision: "1", audit_id: "owner_audit_1" }));
    await expect(provisionOwnerInternalSubscriptionV1({ createAuditedInternalSubscription: writer }, input, APPROVED_CAPS))
      .resolves.toEqual({ subscription_id: "owner_sub", revision: "1", audit_id: "owner_audit_1" });
    expect(writer).toHaveBeenCalledWith(command);
    await expect(provisionOwnerInternalSubscriptionV1({ createAuditedInternalSubscription: vi.fn(async () => ({
      subscription_id: "owner_sub", revision: "2", audit_id: "owner_audit_1",
    })) }, input, APPROVED_CAPS)).rejects.toBeInstanceOf(PlanFeatureErrorV1);
    await expect(provisionOwnerInternalSubscriptionV1({ createAuditedInternalSubscription: null as never }, input, APPROVED_CAPS))
      .rejects.toThrow(/OWNER_AUDIT_REQUIRED/);
  });
});
