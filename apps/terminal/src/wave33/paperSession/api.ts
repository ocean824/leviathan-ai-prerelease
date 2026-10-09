import { createPaperActivationApi } from "../../wave27/api/paperActivation";
import type {
  PaperActivationApiResult,
  PaperActivationErrorCode,
  PaperActivationReceiptV1,
  PaperActivationScope,
  PaperOrderStatusV1,
} from "../../wave27/api/paperActivation";
import type { RiskGuardReport } from "../../wave26/api/liveGuard";

export type PaperSessionScope = PaperActivationScope;
export type PaperSessionResult<T> = PaperActivationApiResult<T>;
export type PaperSessionErrorCode = PaperActivationErrorCode;

export interface PaperSessionApi {
  getOrderStatus(): Promise<PaperSessionResult<PaperOrderStatusV1>>;
  getRiskStatus(): Promise<PaperSessionResult<RiskGuardReport>>;
  pause(scope: PaperSessionScope): Promise<PaperSessionResult<PaperActivationReceiptV1>>;
  resume(scope: PaperSessionScope): Promise<PaperSessionResult<PaperActivationReceiptV1>>;
}

export function createPaperSessionApi(
  fetcher: typeof fetch = fetch,
): PaperSessionApi {
  const activationApi = createPaperActivationApi(fetcher);
  return {
    getOrderStatus: () => activationApi.getOrderStatus(),
    getRiskStatus: () => activationApi.getRiskStatus(),
    pause: (scope) => activationApi.revoke(scope),
    resume: (scope) => activationApi.activate(scope),
  };
}