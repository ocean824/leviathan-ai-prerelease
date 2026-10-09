import { describe, expect, it, vi } from "vitest";
import { readdir, readFile } from "node:fs/promises";
import { REGISTRY } from "../../../apps/terminal/src/navigation/registry.js";
import {
  API_FEATURE_ACTIONS_V1,
  catalogCompletenessErrorV1,
  completeFeatureMapV1,
  FEATURE_CATALOG_V1,
  FEATURE_CATALOG_VERSION_V1,
  FEATURE_KEYS_V1,
  featureForApiActionV1,
  featureForNavigationCodeV1,
  NAVIGATION_FEATURES_V1,
} from "../src/entitlement/feature_catalog.js";
import {
  ALL_ACCESS_LIMITS_PROPOSED_V1,
  ALL_ACCESS_LIMITS_STATUS_V1,
  ALL_ACCESS_PLAN_ID_V1,
  DEFAULT_PLAN_CAPS_CONFIGURATION_V1,
  allAccessPlanFeaturesV1,
  type FeatureLimitEntryV1,
  ownerInternalSubscriptionCommandV1,
  PlanFeatureErrorV1,
  provisionOwnerInternalSubscriptionV1,
  resolvePlanForStripePriceV1,
  stripeActivePlanGrantV1,
  validateAllAccessMapsV1,
  validatePlanFeatureSetV1,
} from "../src/entitlement/plan_features.js";

const allFeatureEntries = () =>
  FEATURE_KEYS_V1.map((key) => [key, true] as const);
const allLimitEntries = (): FeatureLimitEntryV1[] => [
  { key: "seat_limit", value: "5" },
  { key: "broker_connection_limit", value: "10" },
  { key: "data_source_limit", value: "50" },
  { key: "live_account_limit", value: "3" },
];
const APPROVED_CAPS = {
  owner_internal_caps_approved: true,
  stripe_caps_approved: true,
  limits: {
    seat_limit: "5",
    broker_connection_limit: "10",
    data_source_limit: "50",
    live_account_limit: "3",
  },
} as const;
const OWNER_ONLY_CAPS = {
  owner_internal_caps_approved: true,
  stripe_caps_approved: false,
  limits: APPROVED_CAPS.limits,
} as const;
const STRIPE_ONLY_CAPS = {
  owner_internal_caps_approved: false,
  stripe_caps_approved: true,
  limits: APPROVED_CAPS.limits,
} as const;

const ROOT = new URL("../../../", import.meta.url);

function routerPrefix(source: string): string {
  const direct =
    /\brouter\s*=\s*APIRouter\s*\([\s\S]{0,200}?prefix\s*=\s*["']([^"']+)["']/m.exec(
      source,
    )?.[1];
  const constant = /_ROUTER_PREFIX\s*:\s*Final\s*=\s*["']([^"']+)["']/.exec(
    source,
  )?.[1];
  return direct ?? constant ?? "";
}

function joinRoute(prefix: string, path: string): string {
  const joined = `${prefix.replace(/\/$/, "")}/${path.replace(/^\//, "")}`;
  return joined === "/" ? "/" : joined.replace(/\/$/, "");
}

async function currentApiRouteIds(): Promise<string[]> {
  const directory = new URL("apps/api/src/leviathan_api/routers/", ROOT);
  const entries = await readdir(directory, { withFileTypes: true });
  const files = entries.filter(
    (entry) => entry.isFile() && entry.name.endsWith(".py"),
  );
  const ids: string[] = [];
  for (const file of files) {
    const source = await readFile(new URL(file.name, directory), "utf8");
    const prefix = routerPrefix(source);
    const pattern =
      /^\s*@router\.(get|post|put|patch|delete)\(\s*["']([^"']*)["']/gim;
    for (const match of source.matchAll(pattern)) {
      ids.push(`${match[1]!.toUpperCase()} ${joinRoute(prefix, match[2]!)}`);
    }
  }
  return [...new Set(ids)].sort();
}

async function currentMountedApiRouteIds(): Promise<string[]> {
  const mountPath = new URL(
    "apps/api/src/leviathan_api/wave35_mounts.py",
    ROOT,
  );
  const mainPath = new URL("apps/api/src/leviathan_api/main.py", ROOT);
  const [mountSource, mainSource] = await Promise.all([
    readFile(mountPath, "utf8"),
    readFile(mainPath, "utf8"),
  ]);
  expect(mainSource).toContain("configure_wave35_mounts(");
  for (const entry of [
    "data_sources.create_data_sources_router(registry)",
    "preferences_router",
    "history_router",
    "models_router",
    "ea_router",
    "connections_router",
  ]) {
    expect(mountSource, `production mount table includes ${entry}`).toContain(
      entry,
    );
  }

  const moduleFiles = [
    "data_sources.py",
    "preferences.py",
    "chat_history.py",
    "chat_models.py",
    "mt5_ea_host.py",
    "connections.py",
  ];
  const directory = new URL("apps/api/src/leviathan_api/routers/", ROOT);
  const ids: string[] = [];
  for (const name of moduleFiles) {
    const source = await readFile(new URL(name, directory), "utf8");
    const prefix = routerPrefix(source);
    const pattern =
      /^\s*@router\.(get|post|put|patch|delete)\(\s*["']([^"']*)["']/gim;
    for (const match of source.matchAll(pattern)) {
      ids.push(`${match[1]!.toUpperCase()} ${joinRoute(prefix, match[2]!)}`);
    }
  }
  return [...new Set(ids)].sort();
}

describe("ENTITLEMENT-FEATURES-001 independent acceptance", () => {
  it("uses a closed versioned catalog and maps every current navigation code exactly once", () => {
    const currentCodes = REGISTRY.map((entry) => entry.code);
    const mappedCodes = NAVIGATION_FEATURES_V1.map(
      (binding) => binding.navigation_code,
    );

    expect(FEATURE_CATALOG_VERSION_V1).toBe(1);
    expect(new Set(FEATURE_KEYS_V1).size).toBe(FEATURE_KEYS_V1.length);
    expect(catalogCompletenessErrorV1(currentCodes)).toBeNull();
    expect([...mappedCodes].sort()).toEqual([...currentCodes].sort());
    expect(new Set(mappedCodes).size).toBe(currentCodes.length);
    expect(FEATURE_CATALOG_V1.map((entry) => entry.feature_key).sort()).toEqual(
      [...FEATURE_KEYS_V1].sort(),
    );
    expect(FEATURE_KEYS_V1).toContain("user_settings");

    for (const code of currentCodes) {
      expect(featureForNavigationCodeV1(code)).not.toBeNull();
    }
    expect(featureForNavigationCodeV1("NOT_REGISTERED")).toBeNull();
    expect(featureForNavigationCodeV1("CONN")).toBe("connections");
    expect(featureForNavigationCodeV1("APPR")).toBe("user_settings");
    expect(featureForNavigationCodeV1("CHAT")).toBe("chat_terminal");
    expect(
      FEATURE_CATALOG_V1.find(
        (feature) => feature.feature_key === "live_trading",
      )?.requirement_ids,
    ).toContain("LEV-REQ-004");
    expect(featureForApiActionV1("POST", "/mcp/actions/dry-run")).toBe(
      "chat_terminal",
    );
    expect(
      API_FEATURE_ACTIONS_V1.find(
        (action) => action.path === "/mcp/actions/dry-run",
      ),
    ).toMatchObject({ classification: "WRITE" });
    for (const [method, path, featureKey] of [
      ["PUT", "/api/preferences/{namespace}", "user_settings"],
      ["DELETE", "/api/preferences/{namespace}", "user_settings"],
      ["POST", "/chat/history/conversations", "chat_terminal"],
      [
        "POST",
        "/chat/history/conversations/{conversation_id}/messages",
        "chat_terminal",
      ],
      [
        "DELETE",
        "/chat/history/conversations/{conversation_id}",
        "chat_terminal",
      ],
    ] as const) {
      expect(featureForApiActionV1(method, path)).toBe(featureKey);
    }
  });

  it("binds current routes and derives MOUNTED status from the production Wave-35 mount set", async () => {
    const discoveredIds = await currentApiRouteIds();
    const mountedIds = await currentMountedApiRouteIds();
    const catalogIds = new Set(
      API_FEATURE_ACTIONS_V1.map((action) => action.action_id),
    );
    const requiredIds = discoveredIds.filter(
      (id) => !id.startsWith("GET ") || catalogIds.has(id),
    );

    for (const id of requiredIds) {
      const action = API_FEATURE_ACTIONS_V1.find(
        (candidate) => candidate.action_id === id,
      );
      expect(
        action,
        `discovered API route requires an exact catalog binding: ${id}`,
      ).toBeDefined();
      expect(action?.action_id).toBe(`${action?.method} ${action?.path}`);
      expect(featureForApiActionV1(action!.method, action!.path)).toBe(
        action!.feature_key,
      );
    }

    const mountedRouteIds = [
      "GET /data-sources",
      "GET /api/preferences/{namespace}",
      "PUT /api/preferences/{namespace}",
      "DELETE /api/preferences/{namespace}",
      "GET /chat/history/conversations",
      "POST /chat/history/conversations",
      "GET /chat/history/conversations/{conversation_id}/messages",
      "POST /chat/history/conversations/{conversation_id}/messages",
      "DELETE /chat/history/conversations/{conversation_id}",
      "GET /chat/history/conversations/{conversation_id}/export",
      "GET /chat/models",
      "POST /chat/complete",
      "POST /chat/stream",
      "GET /connections/catalog",
      "GET /connections/status",
      "POST /connections/{provider}/connect",
      "POST /connections/{provider}/cancel",
      "POST /connections/{provider}/disconnect",
      "GET /mt5/ea-host/v1/sessions/{session_id}",
      "POST /mt5/ea-host/v1/install",
      "POST /mt5/ea-host/v1/sessions/{session_id}/kill",
    ].sort();
    expect(mountedIds).toEqual(mountedRouteIds);
    for (const id of mountedIds) {
      const action = API_FEATURE_ACTIONS_V1.find(
        (candidate) => candidate.action_id === id,
      );
      expect(
        action,
        `production mounted route requires exact catalog binding: ${id}`,
      ).toBeDefined();
      expect(
        action?.registration,
        `production mounted route must be MOUNTED: ${id}`,
      ).toBe("MOUNTED");
      expect(action?.action_id).toBe(`${action?.method} ${action?.path}`);
      expect(featureForApiActionV1(action!.method, action!.path)).toBe(
        action!.feature_key,
      );
    }

    for (const action of API_FEATURE_ACTIONS_V1.filter(
      (candidate) => candidate.registration === "PLANNED",
    )) {
      expect(action.action_id).toBe(`${action.method} ${action.path}`);
      expect(mountedIds).not.toContain(action.action_id);
      if (discoveredIds.includes(action.action_id)) {
        expect(
          action.registration,
          `discovered but unmounted route remains PLANNED: ${action.action_id}`,
        ).toBe("PLANNED");
      }
    }

    for (const [actionId, featureKey, classification, registration] of [
      ["POST /chat/complete", "chat_terminal", "WRITE", "MOUNTED"],
      ["POST /chat/stream", "chat_terminal", "WRITE", "MOUNTED"],
      ["GET /chat/tools/registry", "chat_terminal", "READ", "PLANNED"],
      ["POST /chat/tools/plan", "chat_terminal", "WRITE", "PLANNED"],
      ["POST /chat/tools/confirm", "chat_terminal", "WRITE", "PLANNED"],
      ["POST /chat/tools/read", "chat_terminal", "READ", "PLANNED"],
      ["GET /live-activation/status", "live_trading", "READ", "PLANNED"],
      ["POST /live-activation/enable", "live_trading", "WRITE", "PLANNED"],
      ["POST /live-activation/disable", "live_trading", "WRITE", "PLANNED"],
      ["POST /v1/signup/checkout", "admin_console", "WRITE", "WORKER_ROUTE"],
      ["POST /v1/signup/webhook", "admin_console", "WRITE", "WORKER_ROUTE"],
    ] as const) {
      const action = API_FEATURE_ACTIONS_V1.find(
        (candidate) => candidate.action_id === actionId,
      );
      expect(action).toMatchObject({
        action_id: actionId,
        feature_key: featureKey,
        classification,
      });
      if (registration === "PLANNED") {
        if (mountedIds.includes(actionId)) {
          expect(
            action?.registration,
            `mounted route is promoted: ${actionId}`,
          ).toBe("MOUNTED");
        } else if (discoveredIds.includes(actionId)) {
          expect(
            action?.registration,
            `defined but unmounted route remains PLANNED: ${actionId}`,
          ).toBe("PLANNED");
        } else {
          expect(action?.registration).toMatch(
            /^(PLANNED|DEFINED_NOT_MOUNTED)$/,
          );
        }
      } else {
        expect(action?.registration).toBe(registration);
      }
      expect(featureForApiActionV1(action!.method, action!.path)).toBe(
        featureKey,
      );
    }

    for (const [method, path, featureKey] of [
      ["GET", "/data-sources", "data_sources"],
      ["GET", "/api/preferences/{namespace}", "user_settings"],
      ["GET", "/chat/history/conversations", "chat_terminal"],
      [
        "GET",
        "/chat/history/conversations/{conversation_id}/messages",
        "chat_terminal",
      ],
      [
        "GET",
        "/chat/history/conversations/{conversation_id}/export",
        "chat_terminal",
      ],
      ["GET", "/chat/models", "chat_terminal"],
      ["GET", "/connections/catalog", "connections"],
      ["GET", "/connections/status", "connections"],
      ["GET", "/mt5/ea-host/v1/sessions/{session_id}", "ea_hosting"],
      ["GET", "/chat/tools/registry", "chat_terminal"],
      ["GET", "/live-activation/status", "live_trading"],
    ] as const) {
      const actionId = `${method} ${path}`;
      expect(discoveredIds, `read route discovered: ${actionId}`).toContain(
        actionId,
      );
      expect(featureForApiActionV1(method, path)).toBe(featureKey);
      expect(
        API_FEATURE_ACTIONS_V1.find(
          (candidate) => candidate.action_id === actionId,
        ),
      ).toMatchObject({ feature_key: featureKey, classification: "READ" });
    }

    const connectionActionIds = [
      "GET /connections/catalog",
      "GET /connections/status",
      "POST /connections/{provider}/connect",
      "POST /connections/{provider}/cancel",
      "POST /connections/{provider}/disconnect",
    ];
    const discoveredConnectionIds = discoveredIds.filter((id) =>
      id.includes("/connections/"),
    );
    expect(discoveredConnectionIds).toEqual([...connectionActionIds].sort());
    for (const actionId of connectionActionIds) {
      expect(discoveredIds).toContain(actionId);
      expect(mountedIds).toContain(actionId);
      const action = API_FEATURE_ACTIONS_V1.find(
        (candidate) => candidate.action_id === actionId,
      );
      expect(action).toMatchObject({
        feature_key: "connections",
        classification: actionId.startsWith("GET ") ? "READ" : "WRITE",
        registration: "MOUNTED",
      });
      expect(featureForApiActionV1(action!.method, action!.path)).toBe(
        "connections",
      );
    }
  });

  it("fails closed for unknown or duplicate features and incomplete feature maps", () => {
    expect(() =>
      completeFeatureMapV1([
        ...allFeatureEntries(),
        ["unlisted_feature", true],
      ]),
    ).toThrow("UNKNOWN_FEATURE");
    expect(() =>
      completeFeatureMapV1([...allFeatureEntries(), ["paper_trading", true]]),
    ).toThrow("DUPLICATE_FEATURE");
    expect(() => completeFeatureMapV1(allFeatureEntries().slice(1))).toThrow(
      "INCOMPLETE_FEATURE_MAP",
    );

    expect(() =>
      validateAllAccessMapsV1(allFeatureEntries().slice(1), allLimitEntries()),
    ).toThrow("INCOMPLETE_FEATURE_MAP");
    expect(() =>
      validateAllAccessMapsV1(
        [...allFeatureEntries(), ["paper_trading", true]],
        allLimitEntries(),
      ),
    ).toThrow("DUPLICATE_FEATURE");
    expect(() =>
      validateAllAccessMapsV1(
        allFeatureEntries().map(
          ([key]) => [key, key === "live_trading" ? false : true] as const,
        ),
        allLimitEntries(),
      ),
    ).toThrow("PARTIAL_PLAN_FEATURES");
  });

  it("accepts only the complete all-access plan and exact decimal-string limits", () => {
    const plan = allAccessPlanFeaturesV1();

    expect(ALL_ACCESS_PLAN_ID_V1).toBe("all_access_v1");
    expect(plan.plan_id).toBe("all_access_v1");
    expect(plan.schema_version).toBe(1);
    expect(plan.features).toEqual(
      Object.fromEntries(FEATURE_KEYS_V1.map((key) => [key, true])),
    );
    expect(
      Object.values(plan.features).every((enabled) => enabled === true),
    ).toBe(true);
    expect(plan.limits).toEqual({
      seat_limit: "5",
      broker_connection_limit: "10",
      data_source_limit: "50",
      live_account_limit: "3",
    });
    expect(plan.limits).toEqual(ALL_ACCESS_LIMITS_PROPOSED_V1);
    expect(plan.limits_status).toBe(ALL_ACCESS_LIMITS_STATUS_V1);
    expect(plan.owner_internal_caps_approved).toBe(true);
    expect(plan.stripe_caps_approved).toBe(false);
    expect(plan.grantable).toBe(false);
    expect(
      Object.values(plan.limits).every((value) => typeof value === "string"),
    ).toBe(true);
    expect(
      Object.values(plan.limits).some((value) => typeof value === "number"),
    ).toBe(false);
    expect(
      validatePlanFeatureSetV1(plan, DEFAULT_PLAN_CAPS_CONFIGURATION_V1),
    ).toBe(true);
    expect(
      validatePlanFeatureSetV1({ ...plan, plan_id: "unlisted_plan" }),
    ).toBe(false);
    expect(
      validatePlanFeatureSetV1({ ...plan, features: { paper_trading: true } }),
    ).toBe(false);
    expect(allAccessPlanFeaturesV1(DEFAULT_PLAN_CAPS_CONFIGURATION_V1)).toEqual(
      plan,
    );

    // There is no implicit trial/free/default entitlement in the closed vocabulary.
    expect(FEATURE_KEYS_V1).not.toContain("trial");
    expect(FEATURE_KEYS_V1).not.toContain("default");
    expect(() =>
      resolvePlanForStripePriceV1("price_trial_test", [
        { stripe_price_id: "price_trial_test", plan_id: "trial" },
      ]),
    ).toThrow("UNKNOWN_PLAN");
  });

  it("rejects partial, duplicate, unknown, and non-string limit maps", () => {
    expect(() =>
      validateAllAccessMapsV1(allFeatureEntries(), allLimitEntries().slice(1)),
    ).toThrow("INCOMPLETE_LIMIT_MAP");
    expect(() =>
      validateAllAccessMapsV1(allFeatureEntries(), [
        ...allLimitEntries(),
        { key: "seat_limit", value: "5" },
      ]),
    ).toThrow("DUPLICATE_LIMIT");
    expect(() =>
      validateAllAccessMapsV1(allFeatureEntries(), [
        ...allLimitEntries(),
        { key: "unlisted_limit", value: "1" },
      ]),
    ).toThrow("UNKNOWN_LIMIT");
    expect(() =>
      validateAllAccessMapsV1(
        allFeatureEntries(),
        allLimitEntries().map((entry) =>
          entry.key === "seat_limit" ? { key: entry.key, value: 5 } : entry,
        ),
      ),
    ).toThrow("INVALID_LIMIT");
    for (const invalidValue of ["5.0", "+5", "-5", "9223372036854775808"]) {
      expect(() =>
        validateAllAccessMapsV1(
          allFeatureEntries(),
          allLimitEntries().map((entry) =>
            entry.key === "seat_limit"
              ? { key: entry.key, value: invalidValue }
              : entry,
          ),
        ),
      ).toThrow("INVALID_LIMIT");
    }
  });

  it("resolves only an explicit configured Stripe price ID and rejects unknown or ambiguous mappings", () => {
    const configured = [
      { stripe_price_id: "price_all_access_test", plan_id: "all_access_v1" },
    ];

    expect(
      resolvePlanForStripePriceV1("price_all_access_test", configured),
    ).toEqual(allAccessPlanFeaturesV1());
    const distinctPricesForOnePlan = [
      { stripe_price_id: "price_monthly_test", plan_id: "all_access_v1" },
      { stripe_price_id: "price_annual_test", plan_id: "all_access_v1" },
    ];
    expect(
      resolvePlanForStripePriceV1(
        "price_monthly_test",
        distinctPricesForOnePlan,
      ).plan_id,
    ).toBe("all_access_v1");
    expect(
      resolvePlanForStripePriceV1("price_annual_test", distinctPricesForOnePlan)
        .plan_id,
    ).toBe("all_access_v1");
    expect(() =>
      resolvePlanForStripePriceV1("price_unknown_test", configured),
    ).toThrow("UNKNOWN_PRICE_ID");
    expect(() =>
      resolvePlanForStripePriceV1("price_all_access_test", []),
    ).toThrow("PRICE_PLAN_CONFIGURATION_INVALID");
    expect(() =>
      resolvePlanForStripePriceV1("not-a-price", configured),
    ).toThrow("INVALID_PRICE_ID");
    expect(() =>
      resolvePlanForStripePriceV1("price_all_access_test", [
        ...configured,
        { stripe_price_id: "price_all_access_test", plan_id: "all_access_v1" },
      ]),
    ).toThrow("DUPLICATE_PRICE_ID");
    expect(() =>
      resolvePlanForStripePriceV1("price_all_access_test", [
        { stripe_price_id: "price_all_access_test", plan_id: "other_plan" },
      ]),
    ).toThrow("UNKNOWN_PLAN");
  });

  it("gives the Owner org the same paid feature set and limits through an audited internal subscription", async () => {
    const paidPlan = resolvePlanForStripePriceV1(
      "price_paid_test",
      [{ stripe_price_id: "price_paid_test", plan_id: "all_access_v1" }],
      APPROVED_CAPS,
    );
    const input = {
      org_id: "owner_org",
      subscription_id: "owner_sub",
      source_event_id: "owner_seed_001",
      term_start_utc_ns: "100",
      term_end_utc_ns: "200",
    };
    const command = ownerInternalSubscriptionCommandV1(input, OWNER_ONLY_CAPS);

    expect(command).toMatchObject({
      status: "ACTIVE",
      plan_id: "all_access_v1",
      billing_reference: "invoice-internal-owner",
      source_event_id: "internal:owner_seed_001",
      billing_amount_decimal: null,
      billing_currency: null,
      owner_internal_caps_approved: true,
      stripe_caps_approved: false,
      limits_status: "PROPOSED",
      audit_required: true,
      audit_event_payload: {
        provisioning_kind: "INTERNAL_OWNER_NON_STRIPE",
        billing_reference: "invoice-internal-owner",
        owner_internal_caps_approved: true,
        stripe_caps_approved: false,
      },
      authorization_bypass: false,
    });
    expect(command.features).toEqual(paidPlan.features);
    expect(command.limits).toEqual(paidPlan.limits);
    expect("role" in command).toBe(false);

    const auditedWriter = vi.fn(async (received: typeof command) => ({
      subscription_id: received.subscription_id,
      revision: "1",
      audit_id: "owner_audit_001",
    }));
    await expect(
      provisionOwnerInternalSubscriptionV1(
        { createAuditedInternalSubscription: auditedWriter },
        input,
        OWNER_ONLY_CAPS,
      ),
    ).resolves.toEqual({
      subscription_id: "owner_sub",
      revision: "1",
      audit_id: "owner_audit_001",
    });
    expect(auditedWriter).toHaveBeenCalledOnce();
    expect(auditedWriter).toHaveBeenCalledWith(command);
    expect(() =>
      ownerInternalSubscriptionCommandV1(
        {
          ...input,
          term_end_utc_ns: "100",
        },
        APPROVED_CAPS,
      ),
    ).toThrow(PlanFeatureErrorV1);
  });

  it("keeps proposed caps preview-only and denies Stripe and Owner writes before the port call", async () => {
    const mappings = [
      { stripe_price_id: "price_all_access_test", plan_id: "all_access_v1" },
    ];
    const preview = resolvePlanForStripePriceV1(
      "price_all_access_test",
      mappings,
    );
    expect(preview).toMatchObject({
      owner_internal_caps_approved: true,
      stripe_caps_approved: false,
      grantable: false,
      limits_status: "PROPOSED",
    });
    expect(() =>
      stripeActivePlanGrantV1("price_all_access_test", mappings),
    ).toThrowError(expect.objectContaining({ code: "CAPS_NOT_APPROVED" }));

    const input = {
      org_id: "owner_org",
      subscription_id: "owner_sub",
      source_event_id: "owner_seed_001",
      term_start_utc_ns: "100",
      term_end_utc_ns: "200",
    };
    const defaultOwnerCommand = ownerInternalSubscriptionCommandV1(input);
    expect(defaultOwnerCommand).toMatchObject({
      status: "ACTIVE",
      owner_internal_caps_approved: true,
      stripe_caps_approved: false,
      limits_status: "PROPOSED",
      audit_event_payload: {
        provisioning_kind: "INTERNAL_OWNER_NON_STRIPE",
        owner_internal_caps_approved: true,
        stripe_caps_approved: false,
      },
    });
    const writer = vi.fn(async () => ({
      subscription_id: "owner_sub",
      revision: "1",
      audit_id: "owner_audit_001",
    }));
    await expect(
      provisionOwnerInternalSubscriptionV1(
        { createAuditedInternalSubscription: writer },
        input,
      ),
    ).resolves.toMatchObject({
      subscription_id: "owner_sub",
      audit_id: "owner_audit_001",
    });
    expect(writer).toHaveBeenCalledOnce();

    const deniedOwnerWriter = vi.fn(async () => ({
      subscription_id: "owner_sub",
      revision: "1",
      audit_id: "owner_audit_001",
    }));
    expect(() =>
      ownerInternalSubscriptionCommandV1(input, STRIPE_ONLY_CAPS),
    ).toThrowError(expect.objectContaining({ code: "CAPS_NOT_APPROVED" }));
    await expect(
      provisionOwnerInternalSubscriptionV1(
        { createAuditedInternalSubscription: deniedOwnerWriter },
        input,
        STRIPE_ONLY_CAPS,
      ),
    ).rejects.toThrowError(
      expect.objectContaining({ code: "CAPS_NOT_APPROVED" }),
    );
    expect(deniedOwnerWriter).not.toHaveBeenCalled();
  });

  it("uses one approved caps configuration for previews, validation, Stripe grants and Owner commands", async () => {
    const approved = allAccessPlanFeaturesV1(APPROVED_CAPS);
    expect(approved).toMatchObject({
      owner_internal_caps_approved: true,
      stripe_caps_approved: true,
      grantable: true,
      limits_status: "APPROVED",
    });
    expect(validatePlanFeatureSetV1(approved, APPROVED_CAPS)).toBe(true);
    expect(
      validatePlanFeatureSetV1(approved, DEFAULT_PLAN_CAPS_CONFIGURATION_V1),
    ).toBe(false);
    expect(() =>
      validateAllAccessMapsV1(allFeatureEntries(), allLimitEntries(), {
        owner_internal_caps_approved: true,
        stripe_caps_approved: true,
        limits: { ...APPROVED_CAPS.limits, seat_limit: "6" },
      }),
    ).toThrow("LIMIT_CONFIGURATION_MISMATCH");

    const stripeGrant = stripeActivePlanGrantV1(
      "price_paid_test",
      [{ stripe_price_id: "price_paid_test", plan_id: "all_access_v1" }],
      APPROVED_CAPS,
    );
    expect(stripeGrant).toMatchObject({
      status: "ACTIVE",
      stripe_caps_approved: true,
      plan_id: "all_access_v1",
    });
    expect(stripeGrant.features).toEqual(approved.features);
    expect(stripeGrant.limits).toEqual(approved.limits);

    const input = {
      org_id: "owner_org",
      subscription_id: "owner_sub",
      source_event_id: "owner_seed_001",
      term_start_utc_ns: "100",
      term_end_utc_ns: "200",
    };
    const command = ownerInternalSubscriptionCommandV1(input, OWNER_ONLY_CAPS);
    expect(command.features).toEqual(stripeGrant.features);
    expect(command.limits).toEqual(stripeGrant.limits);
    expect(
      Object.values(approved.limits).every(
        (value) => typeof value === "string",
      ),
    ).toBe(true);
    const writer = vi.fn(async () => ({
      subscription_id: "owner_sub",
      revision: "1",
      audit_id: "owner_audit_001",
    }));
    await expect(
      provisionOwnerInternalSubscriptionV1(
        { createAuditedInternalSubscription: writer },
        input,
        APPROVED_CAPS,
      ),
    ).resolves.toMatchObject({
      subscription_id: "owner_sub",
      audit_id: "owner_audit_001",
    });
    expect(writer).toHaveBeenCalledOnce();
  });

  it("defaults unknown navigation and API actions to no feature", () => {
    expect(featureForNavigationCodeV1("NOT_A_DESTINATION")).toBeNull();
    expect(featureForApiActionV1("POST", "/unregistered/action")).toBeNull();
    expect(API_FEATURE_ACTIONS_V1.length).toBeGreaterThan(0);
    expect(
      API_FEATURE_ACTIONS_V1.every((action) =>
        FEATURE_KEYS_V1.includes(action.feature_key),
      ),
    ).toBe(true);
  });
});
