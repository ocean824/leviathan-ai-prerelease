import type { SignupDependenciesV1 } from "./models.js";
import { signupCheckoutRoute } from "./handler.js";
import { signupWebhookRoute } from "./webhook.js";

/** Compose only signup routes; the coordinator owns Worker-level dispatch. */
export async function signupRoutes(
  request: Request, deps?: SignupDependenciesV1,
): Promise<Response | null> {
  const path = new URL(request.url).pathname;
  if (path !== "/v1/signup/checkout" && path !== "/v1/signup/webhook") return null;
  if (!deps) {
    return new Response(JSON.stringify({ schema_version: 1, request_id: "not-configured",
      observed_at_ns: "0", error: { code: "NOT_CONFIGURED", message: "Request could not be completed." } }), {
      status: 503,
      headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
    });
  }
  if (path === "/v1/signup/checkout") return signupCheckoutRoute(request, deps);
  if (path === "/v1/signup/webhook") return signupWebhookRoute(request, deps);
  return null;
}
