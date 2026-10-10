export type ChallengeResult = { challenge?: boolean };

/** Retry a learn canary only after the production challenge hand-off has completed. */
export async function runLearnCanary<T extends ChallengeResult>(
  run: (maxTier: 1 | 2) => Promise<T>,
  handoff: () => Promise<void>,
): Promise<T> {
  let result = await run(1);
  if (result.challenge) {
    await handoff();
    result = await run(2);
  }
  return result;
}
