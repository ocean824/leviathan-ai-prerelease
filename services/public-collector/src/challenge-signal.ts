import type { ChallengeResult } from "./learn-canary.js";

export type ChallengeSignalState = { current: boolean };

export function isChallengeResponse(status: number, body: string): boolean {
  return [403, 429, 503].includes(status) && /(?:captcha|verify you are human|security check|unusual traffic|bot challenge|cf-chl-|_cf_chl_opt|awsWafCaptcha|px-captcha|datadome)/i.test(body);
}

export async function callWithChallengeSignal<T extends ChallengeResult>(
  run: () => Promise<T>,
  signal: ChallengeSignalState,
): Promise<T & { challenge: boolean }> {
  signal.current = false;
  const result = await run();
  const challenge = result.challenge === true || signal.current;
  signal.current = false;
  return { ...result, challenge } as T & { challenge: boolean };
}
