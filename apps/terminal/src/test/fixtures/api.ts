export const timestampedFixture = {
  source: "Fixture",
  asOf: 1_700_000_000_000,
  value: "deterministic test datum",
};

export function apiResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    statusText: status >= 500 ? "Internal Server Error" : "OK",
    headers: { "Content-Type": "application/json" },
  });
}

export const disconnectedFetch = async (): Promise<never> => {
  throw new TypeError("Failed to fetch");
};
