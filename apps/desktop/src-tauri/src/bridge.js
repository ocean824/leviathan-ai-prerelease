(() => {
  const capability = "__CAPABILITY__";
  const nativeFetch = window.fetch.bind(window);
  window.fetch = (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    if (url.origin === window.location.origin && url.pathname.startsWith("/api/")) {
      const headers = new Headers(request.headers);
      headers.set("X-Leviathan-Capability", capability);
      return nativeFetch(new Request(request, { headers }));
    }
    return nativeFetch(request);
  };
})();
