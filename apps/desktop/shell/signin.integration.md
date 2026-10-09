# SIGNIN-QR-001 integration note

This slice is deliberately standalone. It adds a dependency-free QR encoder and does not edit `signin.html` or `signin.js`; DESKTOP-SIGNIN-WIRE-001 owns applying the hook after its sign-in files freeze.

## API

Load `qr.js` before the sign-in page script. It exposes `window.SigninQr` in the browser and the same two functions through CommonJS for Node tests:

- `renderOtpauthQr(container, uri) -> boolean`: validate a bounded `otpauth://totp/` URI with exactly one Base32 `secret`, encode it in byte mode at ECC M (QR versions 1–10), and replace the dedicated container with an inline SVG. Returns `false` without changing the container for invalid or unsupported input.
- `clearOtpauthQr(container)`: remove QR children from the dedicated container. The caller separately clears the URI and manual key text.

The SVG contains only the QR module geometry and a fixed accessible label. The module does not log or persist enrollment material.

## Two call-site hooks for WIRE

1. In `signin.html`, add a dedicated `#totp-qr` container beside `#totp-uri` and load `qr.js` before `signin.js`.
2. In `signin.js`, call `window.SigninQr.renderOtpauthQr(qrContainer, uri)` when valid enrollment material is displayed, and call `window.SigninQr.clearOtpauthQr(qrContainer)` from the existing enrollment-material clear path used on confirmation.

Preserve the existing URI and manual-key fallback. A QR-render failure must not remove either fallback. Do not persist or log the URI/key.

## Verification

Run the standalone Node vectors and DOM-clearing checks with `node --test apps/desktop/qa/test_signin_qr.js`. The fixed matrices are independent byte-mode ECC-M known answers. They are stored in the test file so Python is not needed at runtime.
