//! Device-bound licensing boundary for the desktop sign-in gate.
//!
//! Credentials are accepted only for the one build-configured HTTPS Worker origin.
//! The cached session reference is encrypted with current-user DPAPI before disk I/O.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, Once};
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager, State};

pub const GRACE_UNLOCK_ENABLED: bool = false;
pub const GRACE_SECONDS: u64 = 72 * 3600;
const GRACE_NS: u128 = GRACE_SECONDS as u128 * 1_000_000_000;
const MAX_CACHED_BYTES: usize = 128 * 1024;
#[cfg(windows)]
const CACHE_FILE: &str = "license-session.dpapi";
#[cfg(target_os = "macos")]
const CACHE_FILE: &str = "license-session.keychain-ref";
const DEVICE_ID_DOMAIN: &[u8] = b"leviathan-desktop-device-v1\0";
const WORKER_CONFIG_JSON: &str = include_str!(concat!(env!("OUT_DIR"), "/license_worker.json"));
const GOOGLE_CLIENT_CONFIG_JSON: &str =
    include_str!(concat!(env!("OUT_DIR"), "/google_oauth.json"));
static INSTALL_RUSTLS_PROVIDER: Once = Once::new();

/// The pre-session bearer is memory-only and is discarded after TOTP confirmation.
#[derive(Default)]
pub struct PendingTotpEnrollment {
    session_token: Mutex<Option<String>>,
    google_enrollment_token: Mutex<Option<String>>,
}

/// One-shot native proof consumed by the main-window launch listener.
#[derive(Default)]
pub struct VerifiedOnlineGate(Mutex<Option<StartupUnlockProof>>);

#[derive(Clone, Debug, Eq, PartialEq)]
struct StartupUnlockProof {
    state: &'static str,
    read_only: bool,
    features: BTreeMap<String, bool>,
    principal_id: String,
    entitlement_digest: String,
}

fn consume_startup_proof(
    proof: &mut Option<StartupUnlockProof>,
    claimed_state: &str,
    claimed_read_only: bool,
    claimed_features: &BTreeMap<String, bool>,
    claimed_principal_id: &str,
    claimed_entitlement_digest: &str,
) -> bool {
    if proof.as_ref().is_some_and(|issued| {
        issued.state == claimed_state
            && issued.read_only == claimed_read_only
            && issued.features == *claimed_features
            && issued.principal_id == claimed_principal_id
            && issued.entitlement_digest == claimed_entitlement_digest
    }) {
        proof.take();
        true
    } else {
        false
    }
}

pub fn consume_verified_online_unlock(
    app: &AppHandle,
    claimed_state: &str,
    claimed_read_only: bool,
    claimed_features: &BTreeMap<String, bool>,
    claimed_principal_id: &str,
    claimed_entitlement_digest: &str,
) -> bool {
    app.try_state::<VerifiedOnlineGate>()
        .and_then(|gate| {
            gate.0.lock().ok().map(|mut proof| {
                consume_startup_proof(
                    &mut proof,
                    claimed_state,
                    claimed_read_only,
                    claimed_features,
                    claimed_principal_id,
                    claimed_entitlement_digest,
                )
            })
        })
        .unwrap_or(false)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LicenseError {
    InvalidInput,
    DeviceUnavailable,
    ProtectionFailed,
    CacheUnavailable,
    InvalidLicense,
    WorkerUnavailable,
    AuthenticationDenied,
}

impl LicenseError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidInput => "LICENSE_INVALID_INPUT",
            Self::DeviceUnavailable => "LICENSE_DEVICE_UNAVAILABLE",
            Self::ProtectionFailed => "LICENSE_PROTECTION_FAILED",
            Self::CacheUnavailable => "LICENSE_CACHE_UNAVAILABLE",
            Self::InvalidLicense => "LICENSE_INVALID",
            Self::WorkerUnavailable => "LICENSE_WORKER_UNAVAILABLE",
            Self::AuthenticationDenied => "LICENSE_AUTHENTICATION_DENIED",
        }
    }
}

impl fmt::Display for LicenseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for LicenseError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnlockView {
    pub state: &'static str,
    pub unlocked: bool,
    pub read_only: bool,
    pub features: BTreeMap<String, bool>,
}

impl UnlockView {
    fn locked() -> Self {
        Self {
            state: "LOCKED",
            unlocked: false,
            read_only: true,
            features: BTreeMap::new(),
        }
    }

    fn json(&self) -> Value {
        json!({
            "state": self.state,
            "unlocked": self.unlocked,
            "readOnly": self.read_only,
            "features": self.features,
        })
    }
}

/// Read and validate the single configured HTTPS Worker origin embedded at build time.
pub fn configured_worker_origin() -> Result<String, LicenseError> {
    let config: Value =
        serde_json::from_str(WORKER_CONFIG_JSON).map_err(|_| LicenseError::InvalidInput)?;
    let object = config.as_object().ok_or(LicenseError::InvalidInput)?;
    if object.len() != 1 {
        return Err(LicenseError::InvalidInput);
    }
    let candidate = object
        .get("origin")
        .and_then(Value::as_str)
        .ok_or(LicenseError::InvalidInput)?;
    let url = url::Url::parse(candidate).map_err(|_| LicenseError::InvalidInput)?;
    let origin = url.origin().ascii_serialization();
    let is_https = url.scheme() == "https" && url.host_str().is_some();
    let is_loopback = url.scheme() == "http"
        && matches!(url.host_str(), Some("127.0.0.1" | "localhost"))
        && url.port().is_some_and(|port| port > 0);
    if !(is_https || is_loopback)
        || url.username() != ""
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || origin != candidate
    {
        return Err(LicenseError::InvalidInput);
    }
    Ok(origin)
}

/// Derive a stable, non-reversible device identifier from the Windows MachineGuid.
pub fn derive_device_id(machine_identity: &str) -> Result<String, LicenseError> {
    let normalized = machine_identity
        .trim()
        .trim_matches(['{', '}'])
        .to_ascii_lowercase();
    if normalized.len() != 36
        || !normalized
            .bytes()
            .enumerate()
            .all(|(index, byte)| match index {
                8 | 13 | 18 | 23 => byte == b'-',
                _ => byte.is_ascii_hexdigit(),
            })
    {
        return Err(LicenseError::InvalidInput);
    }
    let mut hash = Sha256::new();
    hash.update(DEVICE_ID_DOMAIN);
    hash.update(normalized.as_bytes());
    Ok(format!("LVD1-{}", hex(&hash.finalize())))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

/// Grace is bounded by the approved 72-hour value and the license term.
pub fn resolve_unlock(
    outcome: &str,
    device_matches: bool,
    features: &BTreeMap<String, bool>,
    last_online_ns: u128,
    term_end_ns: u128,
    now_ns: u128,
) -> UnlockView {
    if !device_matches {
        return UnlockView::locked();
    }
    let (state, read_only) = match outcome {
        "VERIFIED_ONLINE" if now_ns < term_end_ns => ("VERIFIED_ONLINE", false),
        "GRACE" | "GRACE_OFFLINE"
            if now_ns >= last_online_ns
                && now_ns.saturating_sub(last_online_ns) <= GRACE_NS
                && now_ns < term_end_ns =>
        {
            ("GRACE", true)
        }
        _ => return UnlockView::locked(),
    };
    let allowed = features
        .iter()
        .filter(|(name, enabled)| {
            **enabled && (!read_only || !name.to_ascii_uppercase().contains("LIVE"))
        })
        .map(|(name, _)| (name.clone(), true))
        .collect();
    UnlockView {
        state,
        unlocked: true,
        read_only,
        features: allowed,
    }
}

fn worker_snapshot<'a>(response: &'a Value) -> Result<&'a Value, LicenseError> {
    if response.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err(LicenseError::InvalidLicense);
    }
    response
        .get("license")
        .filter(|value| value.is_object())
        .ok_or(LicenseError::InvalidLicense)
}

fn feature_map(snapshot: &Value) -> Result<BTreeMap<String, bool>, LicenseError> {
    let features = snapshot
        .get("features")
        .and_then(Value::as_object)
        .ok_or(LicenseError::InvalidLicense)?;
    let mut result = BTreeMap::new();
    for (name, enabled) in features {
        let enabled = enabled.as_bool().ok_or(LicenseError::InvalidLicense)?;
        result.insert(name.clone(), enabled);
    }
    Ok(result)
}

fn unsigned_decimal(value: &Value) -> Result<u128, LicenseError> {
    value
        .as_str()
        .filter(|text| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|text| text.parse::<u128>().ok())
        .ok_or(LicenseError::InvalidLicense)
}

fn current_utc_ns() -> Result<u128, LicenseError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| LicenseError::InvalidInput)?;
    Ok(duration.as_nanos())
}

fn cached_path(app: &AppHandle) -> Result<PathBuf, LicenseError> {
    #[cfg(windows)]
    {
        return app
            .path()
            .app_data_dir()
            .map(|path| path.join(CACHE_FILE))
            .map_err(|_| LicenseError::CacheUnavailable);
    }
    #[cfg(target_os = "macos")]
    {
        let _ = app;
        return crate::platform::data_root()
            .map(|path| path.join(CACHE_FILE))
            .map_err(|_| LicenseError::CacheUnavailable);
    }
    #[allow(unreachable_code)]
    Err(LicenseError::CacheUnavailable)
}

fn cache_reference(app: &AppHandle, value: &[u8]) -> Result<(), LicenseError> {
    if value.is_empty() || value.len() > MAX_CACHED_BYTES {
        return Err(LicenseError::InvalidInput);
    }
    let protected = protect_for_current_user(value)?;
    let path = cached_path(app)?;
    let parent = path.parent().ok_or(LicenseError::CacheUnavailable)?;
    fs::create_dir_all(parent).map_err(|_| LicenseError::CacheUnavailable)?;
    fs::write(path, protected).map_err(|_| LicenseError::CacheUnavailable)
}

fn read_reference(app: &AppHandle) -> Result<Option<Vec<u8>>, LicenseError> {
    let path = cached_path(app)?;
    let protected = match fs::read(path) {
        Ok(bytes) if bytes.len() <= MAX_CACHED_BYTES + 4096 => bytes,
        Ok(_) => return Err(LicenseError::CacheUnavailable),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(LicenseError::CacheUnavailable),
    };
    let value = unprotect_for_current_user(&protected)?;
    if value.len() > MAX_CACHED_BYTES {
        return Err(LicenseError::CacheUnavailable);
    }
    Ok(Some(value))
}

fn validate_device_id(value: &str, expected: &str) -> Result<(), LicenseError> {
    if value == expected {
        Ok(())
    } else {
        Err(LicenseError::InvalidLicense)
    }
}

fn validate_snapshot(
    snapshot: &Value,
    device_id: &str,
    now_ns: u128,
) -> Result<(BTreeMap<String, bool>, u128), LicenseError> {
    if snapshot.get("schemaVersion").and_then(Value::as_u64) != Some(1)
        || snapshot.get("audience").and_then(Value::as_str) != Some("leviathan-desktop")
        || snapshot.get("status").and_then(Value::as_str) != Some("ACTIVE")
    {
        return Err(LicenseError::InvalidLicense);
    }
    validate_device_id(
        snapshot
            .get("deviceId")
            .and_then(Value::as_str)
            .ok_or(LicenseError::InvalidLicense)?,
        device_id,
    )?;
    let signature = snapshot
        .get("signature")
        .and_then(Value::as_object)
        .ok_or(LicenseError::InvalidLicense)?;
    if signature.get("algorithm").and_then(Value::as_str) != Some("ECDSA_P256_SHA256")
        || signature
            .get("value")
            .and_then(Value::as_str)
            .is_none_or(|value| value.is_empty() || value.len() > 128)
    {
        return Err(LicenseError::InvalidLicense);
    }
    let term_start = unsigned_decimal(
        snapshot
            .get("termStartUtcNs")
            .ok_or(LicenseError::InvalidLicense)?,
    )?;
    let term_end = unsigned_decimal(
        snapshot
            .get("termEndUtcNs")
            .ok_or(LicenseError::InvalidLicense)?,
    )?;
    if term_start > now_ns || term_end <= term_start {
        return Err(LicenseError::InvalidLicense);
    }
    Ok((feature_map(snapshot)?, term_end))
}

fn verified_online_view(
    response: &Value,
    device_id: &str,
    now_ns: u128,
) -> Result<UnlockView, LicenseError> {
    if response.get("entitlement_state").and_then(Value::as_str) != Some("VERIFIED_ONLINE") {
        return Err(LicenseError::InvalidLicense);
    }
    let snapshot = worker_snapshot(response)?;
    let (features, term_end) = validate_snapshot(snapshot, device_id, now_ns)?;
    Ok(resolve_unlock(
        "VERIFIED_ONLINE",
        true,
        &features,
        now_ns,
        term_end,
        now_ns,
    ))
}

fn worker_url(path: &str) -> Result<url::Url, LicenseError> {
    let origin = configured_worker_origin()?;
    url::Url::parse(&format!("{origin}{path}")).map_err(|_| LicenseError::InvalidInput)
}

fn valid_totp_uri(value: &str) -> bool {
    if value.len() > 4096 {
        return false;
    }
    let Ok(uri) = url::Url::parse(value) else {
        return false;
    };
    let mut secrets = uri
        .query_pairs()
        .filter(|(key, _)| key.eq_ignore_ascii_case("secret"));
    let Some((_, secret)) = secrets.next() else {
        return false;
    };
    let normalized_secret = secret.to_ascii_uppercase();
    let unpadded = normalized_secret.trim_end_matches('=');
    let padding_length = normalized_secret.len() - unpadded.len();
    uri.scheme() == "otpauth"
        && uri.host_str() == Some("totp")
        && !uri.path().trim_matches('/').is_empty()
        && uri.username().is_empty()
        && uri.password().is_none()
        && uri.port().is_none()
        && uri.fragment().is_none()
        && secrets.next().is_none()
        && !unpadded.is_empty()
        && normalized_secret.len() <= 128
        && padding_length <= 6
        && unpadded
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte))
}

fn http_client() -> Result<reqwest::Client, LicenseError> {
    INSTALL_RUSTLS_PROVIDER.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
    let origin = configured_worker_origin()?;
    reqwest::Client::builder()
        .https_only(origin.starts_with("https://"))
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|_| LicenseError::WorkerUnavailable)
}

pub fn valid_principal_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
}

pub fn enabled_feature_csv(features: &BTreeMap<String, bool>) -> String {
    features
        .iter()
        .filter_map(|(name, enabled)| enabled.then_some(name.as_str()))
        .collect::<Vec<_>>()
        .join(",")
}

fn entitlement_digest(features: &BTreeMap<String, bool>) -> String {
    hex(&Sha256::digest(enabled_feature_csv(features).as_bytes()))
}

fn introspection_subject_matches(response: &Value, principal_id: &str) -> bool {
    response.get("subject_id").and_then(Value::as_str) == Some(principal_id)
}

fn cached_value(
    device_id: &str,
    session_token: &str,
    principal_id: &str,
    last_online_ns: u128,
    snapshot: &Value,
) -> Result<Vec<u8>, LicenseError> {
    if session_token.is_empty() || session_token.len() > 8192 || !valid_principal_id(principal_id) {
        return Err(LicenseError::InvalidLicense);
    }
    serde_json::to_vec(&json!({
        "device_id": device_id,
        "session_token": session_token,
        "principal_id": principal_id,
        "last_online_ns": last_online_ns.to_string(),
        "snapshot": snapshot,
    }))
    .map_err(|_| LicenseError::InvalidLicense)
}

fn decode_worker_json(status: reqwest::StatusCode, bytes: &[u8]) -> Result<Value, LicenseError> {
    if !status.is_success() {
        return Err(match status.as_u16() {
            401 | 403 => LicenseError::AuthenticationDenied,
            500..=599 => LicenseError::WorkerUnavailable,
            _ => LicenseError::InvalidLicense,
        });
    }
    if bytes.is_empty() || bytes.len() > MAX_CACHED_BYTES {
        return Err(LicenseError::InvalidLicense);
    }
    serde_json::from_slice(bytes).map_err(|_| LicenseError::InvalidLicense)
}

async fn bounded_response_body(
    mut response: reqwest::Response,
) -> Result<(reqwest::StatusCode, Vec<u8>), LicenseError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_CACHED_BYTES as u64)
    {
        return Err(LicenseError::InvalidLicense);
    }
    let status = response.status();
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| LicenseError::WorkerUnavailable)?
    {
        if body.len().saturating_add(chunk.len()) > MAX_CACHED_BYTES {
            return Err(LicenseError::InvalidLicense);
        }
        body.extend_from_slice(&chunk);
    }
    Ok((status, body))
}

async fn fetch_license(session_token: &str) -> Result<Value, LicenseError> {
    let client = http_client()?;
    let response = client
        .post(worker_url("/v1/auth/introspect")?)
        .bearer_auth(session_token)
        .send()
        .await
        .map_err(|_| LicenseError::WorkerUnavailable)?;
    let (status, bytes) = bounded_response_body(response).await?;
    decode_worker_json(status, &bytes)
}

fn cache_worker_snapshot(
    app: &AppHandle,
    device_id: &str,
    session_token: &str,
    principal_id: &str,
    verified_at_ns: u128,
    response: &Value,
) -> Result<(), LicenseError> {
    let snapshot = worker_snapshot(response)?;
    let bytes = cached_value(
        device_id,
        session_token,
        principal_id,
        verified_at_ns,
        snapshot,
    )?;
    cache_reference(app, &bytes)
}

fn offline_view_from_cache(
    cached: &Value,
    device_id: &str,
    now_ns: u128,
) -> Result<(UnlockView, String), LicenseError> {
    let principal_id = cached
        .get("principal_id")
        .and_then(Value::as_str)
        .filter(|value| valid_principal_id(value))
        .ok_or(LicenseError::CacheUnavailable)?
        .to_owned();
    let cached_device = cached
        .get("device_id")
        .and_then(Value::as_str)
        .ok_or(LicenseError::CacheUnavailable)?;
    validate_device_id(cached_device, device_id)?;
    let snapshot = cached
        .get("snapshot")
        .filter(|value| value.is_object())
        .ok_or(LicenseError::CacheUnavailable)?;
    let (features, term_end_ns) = validate_snapshot(snapshot, device_id, now_ns)?;
    let last_online_ns = unsigned_decimal(
        cached
            .get("last_online_ns")
            .ok_or(LicenseError::CacheUnavailable)?,
    )?;
    let view = resolve_unlock(
        "GRACE_OFFLINE",
        true,
        &features,
        last_online_ns,
        term_end_ns,
        now_ns,
    );
    if view.unlocked {
        Ok((view, principal_id))
    } else {
        Err(LicenseError::InvalidLicense)
    }
}

fn startup_unlock_allowed(view: &UnlockView) -> bool {
    view.unlocked
        && match view.state {
            "VERIFIED_ONLINE" => !view.read_only,
            "GRACE" => GRACE_UNLOCK_ENABLED && view.read_only,
            _ => false,
        }
}

fn emit_startup_unlock(
    app: &AppHandle,
    view: &UnlockView,
    principal_id: &str,
) -> Result<Value, LicenseError> {
    if !startup_unlock_allowed(view) || !valid_principal_id(principal_id) {
        return Err(LicenseError::InvalidLicense);
    }
    let digest = entitlement_digest(&view.features);
    let mut value = view.json();
    let object = value.as_object_mut().ok_or(LicenseError::InvalidLicense)?;
    object.insert(
        "principalId".to_owned(),
        Value::String(principal_id.to_owned()),
    );
    object.insert(
        "entitlementDigest".to_owned(),
        Value::String(digest.clone()),
    );
    let gate = app
        .try_state::<VerifiedOnlineGate>()
        .ok_or(LicenseError::InvalidInput)?;
    *gate.0.lock().map_err(|_| LicenseError::InvalidInput)? = Some(StartupUnlockProof {
        state: view.state,
        read_only: view.read_only,
        features: view.features.clone(),
        principal_id: principal_id.to_owned(),
        entitlement_digest: digest,
    });
    if app.emit("license-unlocked", value.clone()).is_err() {
        *gate.0.lock().map_err(|_| LicenseError::InvalidInput)? = None;
        return Err(LicenseError::InvalidInput);
    }
    Ok(value)
}

#[tauri::command]
pub async fn license_sign_in(
    app: AppHandle,
    pending: State<'_, PendingTotpEnrollment>,
    email: String,
    password: String,
    totp_code: Option<String>,
) -> Result<Value, String> {
    if let Ok(mut token) = pending.session_token.lock() {
        *token = None;
    }
    if let Ok(mut token) = pending.google_enrollment_token.lock() {
        *token = None;
    }
    let result = async {
        if email.is_empty()
            || email.len() > 254
            || email.trim() != email
            || email.chars().any(char::is_control)
            || password.is_empty()
            || password.len() > 1024
            || totp_code.as_ref().is_some_and(|code| {
                code.is_empty()
                    || code.len() > 12
                    || !code.bytes().all(|byte| byte.is_ascii_digit())
            })
        {
            return Err(LicenseError::InvalidInput);
        }
        let device_id = machine_guid().and_then(|identity| derive_device_id(&identity))?;
        let client = http_client()?;
        let mut body = json!({
            "email": email,
            "password": password,
            "device_id": device_id,
        });
        if let Some(code) = totp_code {
            body.as_object_mut()
                .ok_or(LicenseError::InvalidInput)?
                .insert("totp_code".to_owned(), Value::String(code));
        }
        let response = client
            .post(worker_url("/v1/auth/session")?)
            .json(&body)
            .send()
            .await
            .map_err(|_| LicenseError::WorkerUnavailable)?;
        let (status, bytes) = bounded_response_body(response).await?;
        let session = decode_worker_json(status, &bytes)?;
        if session.get("schema_version").and_then(Value::as_u64) != Some(1) {
            return Err(LicenseError::InvalidLicense);
        }
        let principal_id = session
            .get("principal_id")
            .and_then(Value::as_str)
            .filter(|value| valid_principal_id(value))
            .ok_or(LicenseError::AuthenticationDenied)?;
        let session_token = session
            .get("session_token")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty() && token.len() <= 8192)
            .ok_or(LicenseError::AuthenticationDenied)?;
        let snapshot = session
            .get("license_snapshot")
            .filter(|value| value.is_object())
            .ok_or(LicenseError::InvalidLicense)?;
        let now_ns = current_utc_ns()?;
        let worker_response = json!({
            "schema_version": 1,
            "entitlement_state": "VERIFIED_ONLINE",
            "observed_at_ns": now_ns.to_string(),
            "license": snapshot,
        });
        let view = verified_online_view(&worker_response, &device_id, now_ns)?;
        if session.get("totp_state").and_then(Value::as_str) == Some("ENROLLMENT_REQUIRED") {
            *pending
                .session_token
                .lock()
                .map_err(|_| LicenseError::InvalidInput)? = Some(session_token.to_owned());
            let enrollment = http_client()?
                .post(worker_url("/v1/auth/session/totp/enroll")?)
                .bearer_auth(session_token)
                .json(&json!({}))
                .send()
                .await
                .map_err(|_| LicenseError::WorkerUnavailable)?;
            let (enrollment_status, enrollment_bytes) = bounded_response_body(enrollment).await?;
            let enrollment = decode_worker_json(enrollment_status, &enrollment_bytes)?;
            let otpauth_uri = enrollment
                .get("otpauth_uri")
                .and_then(Value::as_str)
                .filter(|value| valid_totp_uri(value))
                .ok_or(LicenseError::InvalidLicense)?;
            return Ok(json!({
                "state": "TOTP_ENROLLMENT_REQUIRED",
                "otpauthUri": otpauth_uri,
                "features": {},
                "unlocked": false,
                "readOnly": true,
            }));
        }
        if session.get("totp_state").and_then(Value::as_str) != Some("ENROLLED") {
            return Err(LicenseError::InvalidLicense);
        }
        *pending
            .session_token
            .lock()
            .map_err(|_| LicenseError::InvalidInput)? = None;
        cache_worker_snapshot(
            &app,
            &device_id,
            session_token,
            principal_id,
            now_ns,
            &worker_response,
        )?;
        emit_startup_unlock(&app, &view, principal_id)
    }
    .await;
    result.map_err(|error: LicenseError| error.code().to_string())
}

fn google_desktop_client_id() -> Result<String, LicenseError> {
    let config: Value =
        serde_json::from_str(GOOGLE_CLIENT_CONFIG_JSON).map_err(|_| LicenseError::InvalidInput)?;
    config
        .get("desktop_client_id")
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 256
                && value.ends_with(".apps.googleusercontent.com")
        })
        .map(str::to_owned)
        .ok_or(LicenseError::InvalidInput)
}

#[tauri::command]
pub async fn license_google_sign_in(
    app: AppHandle,
    pending: State<'_, PendingTotpEnrollment>,
    totp_code: Option<String>,
) -> Result<Value, String> {
    if let Ok(mut token) = pending.google_enrollment_token.lock() {
        *token = None;
    }
    let result = async {
        if totp_code
            .as_ref()
            .is_some_and(|code| code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()))
        {
            return Err(LicenseError::InvalidInput);
        }
        let device_id = machine_guid().and_then(|identity| derive_device_id(&identity))?;
        let client_id = google_desktop_client_id()?;
        let client = http_client()?;
        let origin = url::Url::parse(&configured_worker_origin()?)
            .map_err(|_| LicenseError::InvalidInput)?;
        let worker_session = crate::google_login::desktop_google_login(
            &client,
            &origin,
            &client_id,
            &device_id,
            totp_code.as_deref(),
        )
        .await
        .map_err(|error| match error {
            crate::google_login::GoogleLoginError::WorkerUnavailable
            | crate::google_login::GoogleLoginError::GoogleTokenUnavailable
            | crate::google_login::GoogleLoginError::CallbackUnavailable
            | crate::google_login::GoogleLoginError::BrowserUnavailable => {
                LicenseError::WorkerUnavailable
            }
            crate::google_login::GoogleLoginError::ConfigurationUnavailable
            | crate::google_login::GoogleLoginError::InvalidCallback
            | crate::google_login::GoogleLoginError::InvalidWorkerResponse => {
                LicenseError::InvalidLicense
            }
        })?;
        let data = worker_session
            .get("data")
            .ok_or(LicenseError::InvalidLicense)?;
        if data.get("totp_state").and_then(Value::as_str) == Some("ENROLLMENT_REQUIRED") {
            let token = data
                .get("enrollment_token")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= 256)
                .ok_or(LicenseError::InvalidLicense)?;
            let uri = data
                .get("otpauth_uri")
                .and_then(Value::as_str)
                .filter(|value| valid_totp_uri(value))
                .ok_or(LicenseError::InvalidLicense)?;
            *pending
                .google_enrollment_token
                .lock()
                .map_err(|_| LicenseError::InvalidInput)? = Some(token.to_owned());
            return Ok(
                json!({ "state": "TOTP_ENROLLMENT_REQUIRED", "otpauthUri": uri,
                "features": {}, "unlocked": false, "readOnly": true }),
            );
        }
        let session_token = data
            .get("session_token")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 8192)
            .ok_or(LicenseError::AuthenticationDenied)?;
        let principal_id = data
            .get("principal_id")
            .and_then(Value::as_str)
            .filter(|value| valid_principal_id(value))
            .ok_or(LicenseError::AuthenticationDenied)?;
        let snapshot = data
            .get("license_snapshot")
            .filter(|value| value.is_object())
            .ok_or(LicenseError::InvalidLicense)?;
        if !matches!(
            data.get("totp_state").and_then(Value::as_str),
            Some("ENROLLED" | "OPTIONAL")
        ) {
            return Err(LicenseError::AuthenticationDenied);
        }
        let now_ns = current_utc_ns()?;
        let response = json!({ "schema_version": 1, "entitlement_state": "VERIFIED_ONLINE",
            "observed_at_ns": now_ns.to_string(), "license": snapshot });
        let view = verified_online_view(&response, &device_id, now_ns)?;
        cache_worker_snapshot(
            &app,
            &device_id,
            session_token,
            principal_id,
            now_ns,
            &response,
        )?;
        emit_startup_unlock(&app, &view, principal_id)
    }
    .await;
    result.map_err(|error: LicenseError| error.code().to_string())
}

#[tauri::command]
pub async fn license_google_enroll_totp(
    app: AppHandle,
    pending: State<'_, PendingTotpEnrollment>,
    code: String,
) -> Result<Value, String> {
    if code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(LicenseError::InvalidInput.code().to_string());
    }
    let token = pending
        .google_enrollment_token
        .lock()
        .map_err(|_| LicenseError::InvalidInput.code().to_string())?
        .clone()
        .ok_or_else(|| LicenseError::AuthenticationDenied.code().to_string())?;
    let result = async {
        let device_id = machine_guid().and_then(|identity| derive_device_id(&identity))?;
        let response = http_client()?
            .post(worker_url("/v1/auth/google/desktop/totp/confirm")?)
            .json(&json!({ "device_id": device_id, "enrollment_token": token, "code": code }))
            .send()
            .await
            .map_err(|_| LicenseError::WorkerUnavailable)?;
        let (status, bytes) = bounded_response_body(response).await?;
        let body = decode_worker_json(status, &bytes)?;
        if body.pointer("data.totp_state").and_then(Value::as_str) != Some("ENROLLED") {
            return Err(LicenseError::AuthenticationDenied);
        }
        *pending
            .google_enrollment_token
            .lock()
            .map_err(|_| LicenseError::InvalidInput)? = None;
        let _ = app;
        Ok(json!({ "totp_state": "ENROLLED" }))
    }
    .await;
    result.map_err(|error: LicenseError| error.code().to_string())
}

#[tauri::command]
pub async fn license_enroll_totp(
    pending: State<'_, PendingTotpEnrollment>,
    code: String,
) -> Result<Value, String> {
    if code.is_empty() || code.len() > 12 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(LicenseError::InvalidInput.code().to_string());
    }
    let session_token = pending
        .session_token
        .lock()
        .map_err(|_| LicenseError::InvalidInput.code().to_string())?
        .clone()
        .ok_or_else(|| LicenseError::AuthenticationDenied.code().to_string())?;
    let result = async {
        let response = http_client()?
            .post(worker_url("/v1/auth/session/totp/confirm")?)
            .bearer_auth(session_token)
            .json(&json!({ "code": code }))
            .send()
            .await
            .map_err(|_| LicenseError::WorkerUnavailable)?;
        let (status, bytes) = bounded_response_body(response).await?;
        let value = decode_worker_json(status, &bytes)?;
        if value.get("totp_state").and_then(Value::as_str) != Some("ENROLLED") {
            return Err(LicenseError::AuthenticationDenied);
        }
        Ok(json!({ "state": "TOTP_ENROLLED", "requiresSignIn": true }))
    }
    .await;
    if result.is_ok() {
        if let Ok(mut token) = pending.session_token.lock() {
            *token = None;
        }
    }
    result.map_err(|error: LicenseError| error.code().to_string())
}

#[tauri::command]
pub async fn license_status(app: AppHandle) -> Result<Value, String> {
    let result = async {
        let Some(bytes) = read_reference(&app)? else {
            return Ok(UnlockView::locked().json());
        };
        let cached: Value =
            serde_json::from_slice(&bytes).map_err(|_| LicenseError::CacheUnavailable)?;
        let device_id = machine_guid().and_then(|identity| derive_device_id(&identity))?;
        let token = cached
            .get("session_token")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 8192)
            .ok_or(LicenseError::CacheUnavailable)?;
        let principal_id = cached
            .get("principal_id")
            .and_then(Value::as_str)
            .filter(|value| valid_principal_id(value))
            .ok_or(LicenseError::CacheUnavailable)?
            .to_owned();
        match fetch_license(token).await {
            Ok(response) => {
                if !introspection_subject_matches(&response, &principal_id) {
                    return Err(LicenseError::AuthenticationDenied);
                }
                let now_ns = current_utc_ns()?;
                let view = verified_online_view(&response, &device_id, now_ns)?;
                cache_worker_snapshot(&app, &device_id, token, &principal_id, now_ns, &response)?;
                emit_startup_unlock(&app, &view, &principal_id)
            }
            Err(LicenseError::WorkerUnavailable) => {
                let (view, principal_id) =
                    offline_view_from_cache(&cached, &device_id, current_utc_ns()?)?;
                if startup_unlock_allowed(&view) {
                    emit_startup_unlock(&app, &view, &principal_id)
                } else {
                    Ok(view.json())
                }
            }
            Err(error) => Err(error),
        }
    }
    .await;
    result.map_err(|error: LicenseError| error.code().to_string())
}

#[tauri::command]
pub async fn license_sign_out(
    app: AppHandle,
    pending: State<'_, PendingTotpEnrollment>,
) -> Result<Value, String> {
    if let Ok(mut token) = pending.session_token.lock() {
        *token = None;
    }
    let reference = read_reference(&app).ok().flatten();
    let cached = reference
        .as_deref()
        .and_then(|bytes| serde_json::from_slice::<Value>(bytes).ok());
    let token = cached
        .as_ref()
        .and_then(|value| value.get("session_token"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 8192)
        .map(str::to_owned);
    let clear_result = clear_local_license_cache(clear_protected_cache(), || {
        let path = cached_path(&app)?;
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(LicenseError::CacheUnavailable),
        }
    });
    if let Err(error) = clear_result {
        return Err(error.code().to_string());
    }
    if let Some(token) = token {
        if let (Ok(client), Ok(url)) = (http_client(), worker_url("/v1/auth/session")) {
            let _ = client.delete(url).bearer_auth(token).send().await;
        }
    }
    // A sidecar principal is immutable for its process lifetime. Exit so a
    // subsequent sign-in starts a new sidecar bound to the new session.
    app.exit(0);
    Ok(UnlockView::locked().json())
}

fn clear_local_license_cache(
    protected_cache: Result<(), LicenseError>,
    remove_reference: impl FnOnce() -> Result<(), LicenseError>,
) -> Result<(), LicenseError> {
    protected_cache?;
    remove_reference()
}

#[cfg(any(target_os = "macos", test))]
fn keychain_delete_result(status: Result<(), i32>) -> Result<(), LicenseError> {
    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
    match status {
        Ok(()) => Ok(()),
        Err(ERR_SEC_ITEM_NOT_FOUND) => Ok(()),
        Err(_) => Err(LicenseError::CacheUnavailable),
    }
}

#[cfg(windows)]
fn machine_guid() -> Result<String, LicenseError> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let system_root = std::env::var_os("SystemRoot").ok_or(LicenseError::DeviceUnavailable)?;
    let reg = std::path::PathBuf::from(system_root)
        .join("System32")
        .join("reg.exe");
    let output = std::process::Command::new(reg)
        .args([
            "query",
            r"HKLM\SOFTWARE\Microsoft\Cryptography",
            "/v",
            "MachineGuid",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|_| LicenseError::DeviceUnavailable)?;
    if !output.status.success() {
        return Err(LicenseError::DeviceUnavailable);
    }
    let text = String::from_utf8(output.stdout).map_err(|_| LicenseError::DeviceUnavailable)?;
    text.lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next() == Some("MachineGuid"))
                .then(|| fields.nth(1).map(str::to_owned))
                .flatten()
        })
        .ok_or(LicenseError::DeviceUnavailable)
}

#[cfg(target_os = "macos")]
fn machine_guid() -> Result<String, LicenseError> {
    let output = std::process::Command::new("/usr/sbin/ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .map_err(|_| LicenseError::DeviceUnavailable)?;
    if !output.status.success() {
        return Err(LicenseError::DeviceUnavailable);
    }
    let text = String::from_utf8(output.stdout).map_err(|_| LicenseError::DeviceUnavailable)?;
    text.lines()
        .find_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key.trim().trim_matches('"') == "IOPlatformUUID")
                .then(|| value.trim().trim_matches('"').to_owned())
        })
        .filter(|value| !value.is_empty())
        .ok_or(LicenseError::DeviceUnavailable)
}

#[cfg(not(any(windows, target_os = "macos")))]
fn machine_guid() -> Result<String, LicenseError> {
    Err(LicenseError::DeviceUnavailable)
}

#[cfg(windows)]
fn protect_for_current_user(plaintext: &[u8]) -> Result<Vec<u8>, LicenseError> {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: plaintext.len() as u32,
        pbData: plaintext.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    let success = unsafe {
        CryptProtectData(
            &input,
            null(),
            null(),
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if success == 0 || output.pbData.is_null() {
        return Err(LicenseError::ProtectionFailed);
    }
    let encrypted =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    unsafe {
        LocalFree(output.pbData.cast());
    }
    Ok(encrypted)
}

#[cfg(target_os = "macos")]
fn protect_for_current_user(plaintext: &[u8]) -> Result<Vec<u8>, LicenseError> {
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };
    if get_generic_password("com.xyrasystems.leviathanai", "license-session-cache").is_ok() {
        delete_generic_password("com.xyrasystems.leviathanai", "license-session-cache")
            .map_err(|_| LicenseError::ProtectionFailed)?;
    }
    set_generic_password(
        "com.xyrasystems.leviathanai",
        "license-session-cache",
        plaintext,
    )
    .map_err(|_| LicenseError::ProtectionFailed)?;
    Ok(b"keychain:v1".to_vec())
}

#[cfg(not(any(windows, target_os = "macos")))]
fn protect_for_current_user(_: &[u8]) -> Result<Vec<u8>, LicenseError> {
    Err(LicenseError::ProtectionFailed)
}

#[cfg(windows)]
fn unprotect_for_current_user(ciphertext: &[u8]) -> Result<Vec<u8>, LicenseError> {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: ciphertext.len() as u32,
        pbData: ciphertext.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    let success = unsafe {
        CryptUnprotectData(
            &input,
            null_mut(),
            null(),
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if success == 0 || output.pbData.is_null() {
        return Err(LicenseError::ProtectionFailed);
    }
    let plaintext =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    unsafe {
        LocalFree(output.pbData.cast());
    }
    Ok(plaintext)
}

#[cfg(target_os = "macos")]
fn unprotect_for_current_user(reference: &[u8]) -> Result<Vec<u8>, LicenseError> {
    use security_framework::passwords::get_generic_password;
    if reference != b"keychain:v1" {
        return Err(LicenseError::ProtectionFailed);
    }
    get_generic_password("com.xyrasystems.leviathanai", "license-session-cache")
        .map_err(|_| LicenseError::ProtectionFailed)
}

#[cfg(target_os = "macos")]
fn clear_protected_cache() -> Result<(), LicenseError> {
    use security_framework::passwords::delete_generic_password;
    keychain_delete_result(
        delete_generic_password("com.xyrasystems.leviathanai", "license-session-cache")
            .map_err(|error| error.code()),
    )
}

#[cfg(not(target_os = "macos"))]
fn clear_protected_cache() -> Result<(), LicenseError> {
    Ok(())
}

#[cfg(not(any(windows, target_os = "macos")))]
fn unprotect_for_current_user(_: &[u8]) -> Result<Vec<u8>, LicenseError> {
    Err(LicenseError::ProtectionFailed)
}

#[cfg(test)]
mod tests {
    use super::{
        clear_local_license_cache, consume_startup_proof, derive_device_id, enabled_feature_csv,
        entitlement_digest, hex, introspection_subject_matches, keychain_delete_result,
        resolve_unlock, startup_unlock_allowed, valid_principal_id, valid_totp_uri,
        validate_snapshot, LicenseError, StartupUnlockProof, GRACE_SECONDS, GRACE_UNLOCK_ENABLED,
    };
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    #[test]
    fn sign_out_does_not_remove_reference_or_report_success_if_keychain_delete_fails() {
        let mut reference_removed = false;
        let result = clear_local_license_cache(Err(LicenseError::CacheUnavailable), || {
            reference_removed = true;
            Ok(())
        });
        assert_eq!(result, Err(LicenseError::CacheUnavailable));
        assert!(!reference_removed);
    }

    #[test]
    fn keychain_item_not_found_is_success_but_other_delete_errors_fail_closed() {
        assert_eq!(keychain_delete_result(Err(-25300)), Ok(()));
        assert_eq!(
            keychain_delete_result(Err(-25293)),
            Err(LicenseError::CacheUnavailable)
        );
    }

    #[test]
    fn device_id_is_stable_normalized_and_does_not_expose_machine_identity() {
        let machine = "{01234567-89AB-CDEF-0123-456789ABCDEF}";
        let first = derive_device_id(machine).expect("valid machine id");
        let second = derive_device_id("01234567-89ab-cdef-0123-456789abcdef")
            .expect("normalized machine id");
        assert_eq!(first, second);
        assert!(!first.contains("01234567"));
        assert_ne!(
            first,
            derive_device_id("11234567-89ab-cdef-0123-456789abcdef").expect("different machine id")
        );
    }

    #[test]
    fn invalid_device_identity_returns_fixed_non_echoing_error() {
        let value = "SECRET-MACHINE-GUID-CANARY";
        let error = derive_device_id(value).expect_err("invalid identity");
        assert_eq!(error, LicenseError::InvalidInput);
        assert_eq!(error.to_string(), "LICENSE_INVALID_INPUT");
        assert!(!error.to_string().contains(value));
    }

    #[test]
    fn worker_origin_config_is_one_exact_https_origin() {
        let origin = super::configured_worker_origin().expect("valid build placeholder");
        assert_eq!(origin, "https://license.invalid");
    }

    #[test]
    fn totp_uri_requires_a_single_base32_secret() {
        assert!(valid_totp_uri(
            "otpauth://totp/Leviathan:user%40example.test?secret=JBSWY3DPEHPK3PXP&issuer=Leviathan"
        ));
        assert!(!valid_totp_uri(
            "https://example.test/?secret=JBSWY3DPEHPK3PXP"
        ));
        assert!(!valid_totp_uri("otpauth://totp/account?issuer=Leviathan"));
        assert!(!valid_totp_uri(
            "otpauth://totp/account?secret=JBSWY3DPEHPK3PXP&secret=AAAA"
        ));
        assert!(!valid_totp_uri("otpauth://totp/account?secret=not-base32!"));
    }

    #[test]
    fn snapshot_requires_active_desktop_audience_and_bound_device() {
        let snapshot = json!({
            "schemaVersion": 1,
            "status": "ACTIVE",
            "audience": "leviathan-desktop",
            "deviceId": "device-1",
            "termStartUtcNs": "100",
            "termEndUtcNs": "300",
            "features": { "PAPER": true },
            "signature": {
                "algorithm": "ECDSA_P256_SHA256",
                "value": "synthetic-signature"
            }
        });
        assert!(validate_snapshot(&snapshot, "device-1", 200).is_ok());
        assert_eq!(
            validate_snapshot(&snapshot, "device-2", 200),
            Err(LicenseError::InvalidLicense)
        );
        let mut wrong_audience = snapshot.clone();
        wrong_audience["audience"] = json!("admin");
        assert_eq!(
            validate_snapshot(&wrong_audience, "device-1", 200),
            Err(LicenseError::InvalidLicense)
        );
        assert_eq!(
            validate_snapshot(&snapshot, "device-1", 99),
            Err(LicenseError::InvalidLicense)
        );
    }

    #[test]
    fn state_machine_fails_closed_for_unknown_denied_and_device_mismatch() {
        let features = BTreeMap::from([("PAPER".to_owned(), true), ("LIVE".to_owned(), true)]);
        for outcome in ["UNKNOWN", "DENIED", "MALFORMED"] {
            assert!(!resolve_unlock(outcome, true, &features, 10, 100, 20).unlocked);
        }
        assert!(!resolve_unlock("VERIFIED_ONLINE", false, &features, 10, 100, 20).unlocked);
    }

    #[test]
    fn online_unlocks_only_server_granted_features_and_grace_is_read_only_without_live() {
        let features = BTreeMap::from([
            ("PAPER".to_owned(), true),
            ("LIVE".to_owned(), true),
            ("REPORTS".to_owned(), false),
        ]);
        let online = resolve_unlock("VERIFIED_ONLINE", true, &features, 10, 100, 20);
        assert!(online.unlocked);
        assert!(!online.read_only);
        assert_eq!(
            online.features,
            BTreeMap::from([("LIVE".to_owned(), true), ("PAPER".to_owned(), true)])
        );

        let grace = resolve_unlock("GRACE_OFFLINE", true, &features, 10, 100, 20);
        assert!(grace.unlocked);
        assert_eq!(grace.state, "GRACE");
        assert!(grace.read_only);
        assert_eq!(grace.features, BTreeMap::from([("PAPER".to_owned(), true)]));
    }

    #[test]
    fn grace_is_bounded_by_approved_duration_and_license_term() {
        let features = BTreeMap::from([("PAPER".to_owned(), true)]);
        let last = 1_000u128;
        let end = last + GRACE_SECONDS as u128 * 1_000_000_000 + 1_000;
        assert!(
            resolve_unlock(
                "GRACE_OFFLINE",
                true,
                &features,
                last,
                end,
                last + GRACE_SECONDS as u128 * 1_000_000_000
            )
            .unlocked
        );
        assert!(
            !resolve_unlock(
                "GRACE_OFFLINE",
                true,
                &features,
                last,
                end,
                last + GRACE_SECONDS as u128 * 1_000_000_000 + 1
            )
            .unlocked
        );
        assert!(!resolve_unlock("GRACE_OFFLINE", true, &features, last, end, last - 1).unlocked);
    }

    #[test]
    fn disabled_grace_gate_allows_only_verified_online_startup() {
        assert!(!GRACE_UNLOCK_ENABLED);
        let features = BTreeMap::from([("PAPER".to_owned(), true)]);
        let online = resolve_unlock("VERIFIED_ONLINE", true, &features, 10, 100, 20);
        let grace = resolve_unlock("GRACE_OFFLINE", true, &features, 10, 100, 20);
        assert!(startup_unlock_allowed(&online));
        assert!(!startup_unlock_allowed(&grace));
    }

    #[test]
    fn forged_grace_event_cannot_consume_verified_online_proof() {
        let mut proof = Some(StartupUnlockProof {
            state: "VERIFIED_ONLINE",
            read_only: false,
            features: BTreeMap::from([("PAPER".to_owned(), true)]),
            principal_id: "user-1".to_owned(),
            entitlement_digest: "a".repeat(64),
        });
        let valid_features = BTreeMap::from([("PAPER".to_owned(), true)]);
        let forged_features = BTreeMap::from([("LIVE".to_owned(), true)]);

        assert!(!consume_startup_proof(
            &mut proof,
            "GRACE",
            true,
            &valid_features,
            "user-1",
            &"a".repeat(64),
        ));
        assert!(!consume_startup_proof(
            &mut proof,
            "VERIFIED_ONLINE",
            false,
            &forged_features,
            "user-1",
            &"a".repeat(64),
        ));
        assert!(!consume_startup_proof(
            &mut proof,
            "VERIFIED_ONLINE",
            false,
            &valid_features,
            "other-user",
            &"a".repeat(64),
        ));
        assert!(!consume_startup_proof(
            &mut proof,
            "VERIFIED_ONLINE",
            false,
            &valid_features,
            "user-1",
            &"b".repeat(64),
        ));
        assert_eq!(
            proof,
            Some(StartupUnlockProof {
                state: "VERIFIED_ONLINE",
                read_only: false,
                features: valid_features.clone(),
                principal_id: "user-1".to_owned(),
                entitlement_digest: "a".repeat(64),
            })
        );
        assert!(consume_startup_proof(
            &mut proof,
            "VERIFIED_ONLINE",
            false,
            &valid_features,
            "user-1",
            &"a".repeat(64),
        ));
        assert!(proof.is_none());
        assert!(!consume_startup_proof(
            &mut proof,
            "VERIFIED_ONLINE",
            false,
            &valid_features,
            "user-1",
            &"a".repeat(64),
        ));
    }

    #[test]
    fn shell_identity_uses_a_closed_subject_grammar_and_sorted_entitlement_digest() {
        assert!(valid_principal_id("user-1:google"));
        assert!(!valid_principal_id(""));
        assert!(!valid_principal_id(" user-1"));
        assert!(!valid_principal_id("user/1"));
        let features = BTreeMap::from([
            ("paper_trading".to_owned(), true),
            ("live_trading".to_owned(), true),
            ("charts".to_owned(), false),
        ]);
        assert_eq!(enabled_feature_csv(&features), "live_trading,paper_trading");
        assert_eq!(
            entitlement_digest(&features),
            hex(&Sha256::digest(b"live_trading,paper_trading"))
        );
        assert!(introspection_subject_matches(
            &json!({"subject_id": "user-1"}),
            "user-1"
        ));
        assert!(!introspection_subject_matches(
            &json!({"subject_id": "other-user"}),
            "user-1"
        ));
    }
}
