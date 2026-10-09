# macOS Big Sur internal test checklist

Builds from the macOS workflow are unsigned and unnotarized. Test on the owner's Intel Mac running macOS 11.7.11. Keep the DMG as downloaded; do not put provider keys in the test notes or screenshots.

## Install and open

- [ ] Download the `leviathan-macos-x86_64-dmg` workflow artifact and open the DMG.
- [ ] Copy Leviathan AI to Applications.
- [ ] In Applications, Control-click or right-click Leviathan AI, choose **Open**, then choose **Open** again in the Gatekeeper warning. This first-open exception is expected for the unsigned internal build.
- [ ] Confirm the app opens to the sign-in screen. Confirm the desktop does not start into the trading terminal before sign-in.
- [ ] Sign in with an internal test account. If macOS asks whether Leviathan AI may access a Keychain item, allow the app's expected access and record whether the prompt repeats. Do not capture or send credentials or recovery codes.

## Runtime behavior

- [ ] Confirm the app support directory exists at `~/Library/Application Support/LeviathanAI`.
- [ ] With no market-data provider credentials configured, confirm the market-data runtime reports `NOT_CONFIGURED`. Do not add real keys just to clear this state.
- [ ] Press **HALT** and confirm the UI reports the halted state and paper actions are blocked. Use the authorized lift flow only if the test procedure explicitly calls for it.
- [ ] Quit Leviathan AI normally, then relaunch it. Confirm the sign-in-first screen appears and the persisted profile/HALT state is handled consistently.
- [ ] Confirm the app log exists at `~/Library/Application Support/LeviathanAI/desktop-sidecar.log`.

## Data survives reinstall

- [ ] Quit the app and remove Leviathan AI from Applications. Eject the DMG.
- [ ] Confirm `~/Library/Application Support/LeviathanAI` still exists and contains the same test profile data.
- [ ] Reopen the DMG, reinstall Leviathan AI to Applications, and repeat the Gatekeeper first-open step if prompted.
- [ ] Sign in and confirm the app can use the retained data without resetting or re-provisioning the profile.

## Report results

Send the build run URL, Mac model/architecture, macOS version, pass/fail for each checkbox, and relevant nonsecret excerpts from `desktop-sidecar.log`. Redact account identifiers and never send provider keys, license tokens, Keychain contents, or recovery codes. Preserve the log locally until the coordinator asks for it.
