(() => {
  "use strict";

  function isAllowedWorkerOrigin(candidate, allowedOrigins) {
    if (typeof candidate !== "string" || !Array.isArray(allowedOrigins)) return false;
    try {
      const url = new URL(candidate);
      return url.protocol === "https:"
        && url.username === ""
        && url.password === ""
        && url.pathname === "/"
        && url.search === ""
        && url.hash === ""
        && url.origin === candidate.replace(/\/$/, "")
        && allowedOrigins.some((origin) => origin === url.origin);
    } catch {
      return false;
    }
  }

  function extractTotpSecret(uriText) {
    if (typeof uriText !== "string" || uriText.length > 4096) return null;
    try {
      const uri = new URL(uriText);
      const secrets = uri.searchParams.getAll("secret");
      if (uri.protocol !== "otpauth:" || uri.hostname !== "totp"
        || uri.username !== "" || uri.password !== "" || uri.port !== ""
        || uri.hash !== "" || !uri.pathname.replaceAll("/", "")
        || secrets.length !== 1) return null;
      const secret = secrets[0].toUpperCase();
      const unpadded = secret.replace(/=+$/, "");
      const padding = secret.length - unpadded.length;
      if (!/^[A-Z2-7]+$/.test(unpadded) || padding > 6
        || !/^=*$/.test(secret.slice(unpadded.length))) return null;
      return unpadded;
    } catch {
      return null;
    }
  }

  function deriveUnlockView(outcome, featureMap) {
    const grace = outcome === "GRACE" || outcome === "GRACE_OFFLINE";
    const state = grace ? "GRACE" : outcome;
    const features = {};
    if (state !== "VERIFIED_ONLINE" && !grace) {
      return Object.freeze({
        state: "LOCKED",
        unlocked: false,
        readOnly: true,
        features: Object.freeze(features),
      });
    }
    if (!featureMap || typeof featureMap !== "object" || Array.isArray(featureMap)) {
      return Object.freeze({
        state: "LOCKED",
        unlocked: false,
        readOnly: true,
        features: Object.freeze(features),
      });
    }
    for (const [name, enabled] of Object.entries(featureMap)) {
      if (typeof name !== "string" || typeof enabled !== "boolean") {
        return Object.freeze({
          state: "LOCKED",
          unlocked: false,
          readOnly: true,
          features: Object.freeze({}),
        });
      }
      if (enabled && (!grace || !/live/i.test(name))) {
        features[name] = true;
      }
    }
    const readOnly = grace;
    return Object.freeze({
      state,
      unlocked: true,
      readOnly,
      features: Object.freeze(features),
    });
  }

  const api = Object.freeze({
    isAllowedWorkerOrigin,
    extractTotpSecret,
    deriveUnlockView,
  });
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  if (typeof window !== "undefined") {
    window.LeviathanSignIn = api;
    window.licenseBridge = Object.freeze({
      invoke(name, args) {
        const native = window.__TAURI_INTERNALS__;
        if (!native || typeof native.invoke !== "function") {
          return Promise.reject(new Error("LICENSE_BRIDGE_UNAVAILABLE"));
        }
        return native.invoke(name, args);
      },
    });
  }
})();
