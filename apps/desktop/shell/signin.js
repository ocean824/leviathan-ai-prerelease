(() => {
  "use strict";

  const COMMANDS = Object.freeze({
    signIn: "license_sign_in",
    enrollTotp: "license_enroll_totp",
    status: "license_status",
    signOut: "license_sign_out",
  });

  let bridgeApi = {};
  if (typeof module !== "undefined" && module.exports) {
    bridgeApi = require("../src/bridge_license.js");
  }
  const pageApi = Object.freeze({ ...bridgeApi, COMMANDS });
  if (typeof module !== "undefined" && module.exports) module.exports = pageApi;
  if (typeof window === "undefined" || typeof document === "undefined") return;

  const api = window.LeviathanSignIn;
  const bridge = window.licenseBridge;
  const form = document.getElementById("signin-form");
  const status = document.getElementById("status");
  const button = form.querySelector("button");
  const enrollment = document.getElementById("totp-enrollment");
  const enrollmentUri = document.getElementById("totp-uri");
  const enrollmentSecret = document.getElementById("totp-secret");
  const enrollmentQr = document.getElementById("totp-qr");
  const confirmForm = document.getElementById("totp-confirm-form");
  const confirmButton = confirmForm.querySelector("button");

  function showMessage(message) {
    status.textContent = message;
  }

  function clearEnrollmentMaterial() {
    if (window.SigninQr) window.SigninQr.clearOtpauthQr(enrollmentQr);
    enrollmentUri.textContent = "";
    enrollmentSecret.value = "";
    confirmForm.elements.namedItem("enrollment_code").value = "";
  }

  function displayEnrollment(uri) {
    const secret = api.extractTotpSecret(uri);
    if (!secret) return false;
    if (window.SigninQr) window.SigninQr.renderOtpauthQr(enrollmentQr, uri);
    enrollmentUri.textContent = uri;
    enrollmentSecret.value = secret;
    form.hidden = true;
    enrollment.hidden = false;
    showMessage("Enter the setup key in your authenticator app, then enter its current code below. This setup material is shown once.");
    return true;
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    button.disabled = true;
    showMessage("Checking sign-in and license…");
    const emailField = form.elements.namedItem("email");
    const passwordField = form.elements.namedItem("password");
    const totpField = form.elements.namedItem("totp_code");
    try {
      const view = await bridge.invoke(COMMANDS.signIn, {
        email: emailField.value,
        password: passwordField.value,
        totpCode: totpField.value || null,
      });
      passwordField.value = "";
      totpField.value = "";
      if (view && view.state === "TOTP_ENROLLMENT_REQUIRED") {
        if (!displayEnrollment(view.otpauthUri)) throw new Error("INVALID_ENROLLMENT_URI");
        button.disabled = false;
        return;
      }
      const unlock = api.deriveUnlockView(view.state, view.features || {});
      if (!unlock.unlocked) {
        throw new Error("LICENSE_NOT_VERIFIED");
      }
      if (unlock.state !== "VERIFIED_ONLINE") {
        throw new Error("LICENSE_NOT_VERIFIED");
      }
      showMessage("License verified. Opening desktop…");
    } catch {
      passwordField.value = "";
      totpField.value = "";
      clearEnrollmentMaterial();
      enrollment.hidden = true;
      form.hidden = false;
      showMessage("Sign-in or license verification failed. Check your details or contact support.");
      button.disabled = false;
    }
  });

  confirmForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    confirmButton.disabled = true;
    const code = confirmForm.elements.namedItem("enrollment_code").value;
    try {
      await bridge.invoke(COMMANDS.enrollTotp, { code });
      clearEnrollmentMaterial();
      enrollment.hidden = true;
      form.hidden = false;
      button.disabled = false;
      showMessage("Authenticator confirmed. Sign in again with your current authenticator code.");
    } catch {
      confirmForm.elements.namedItem("enrollment_code").value = "";
      showMessage("Authenticator confirmation failed. Enter a current code and try again.");
    } finally {
      confirmButton.disabled = false;
    }
  });

  window.addEventListener("DOMContentLoaded", async () => {
    try {
      const view = await bridge.invoke(COMMANDS.status);
      const unlock = api.deriveUnlockView(view.state, view.features || {});
      if (unlock.unlocked && unlock.readOnly) {
        showMessage("Offline license is within the 72-hour grace window. It remains read-only and LIVE capabilities stay disabled.");
      }
    } catch {
      // No cached license is a normal locked state. Details remain in native error codes only.
    }
  });
})();
