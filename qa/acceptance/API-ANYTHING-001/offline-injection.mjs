const originalFetch = globalThis.fetch;
globalThis.fetch = async (input, init) => {
  const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url);
  if (url.protocol === "https:") {
    if (url.pathname === "/robots.txt") return new Response("", { status: 404 });
    return new Response(JSON.stringify({ data: [] }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }
  return originalFetch(input, init);
};
