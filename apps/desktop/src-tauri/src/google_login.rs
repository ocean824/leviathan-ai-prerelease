use reqwest::{Client, Response};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::time::{Duration, Instant};
use url::Url;

const GOOGLE_AUTH_ORIGIN: &str = "https://accounts.google.com";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const MAX_WORKER_RESPONSE: usize = 32 * 1024;
const MAX_CALLBACK_REQUEST: usize = 16 * 1024;
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GoogleLoginError {
    ConfigurationUnavailable,
    WorkerUnavailable,
    BrowserUnavailable,
    CallbackUnavailable,
    InvalidCallback,
    GoogleTokenUnavailable,
    InvalidWorkerResponse,
}

impl GoogleLoginError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::ConfigurationUnavailable => "GOOGLE_NOT_CONFIGURED",
            Self::WorkerUnavailable => "WORKER_UNAVAILABLE",
            Self::BrowserUnavailable => "BROWSER_UNAVAILABLE",
            Self::CallbackUnavailable => "GOOGLE_CALLBACK_UNAVAILABLE",
            Self::InvalidCallback => "GOOGLE_CALLBACK_INVALID",
            Self::GoogleTokenUnavailable => "GOOGLE_TOKEN_UNAVAILABLE",
            Self::InvalidWorkerResponse => "GOOGLE_AUTH_UNAVAILABLE",
        }
    }
}

fn b64url(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((bytes.len() * 4 + 2) / 3);
    let mut index = 0;
    while index + 3 <= bytes.len() {
        let n = ((bytes[index] as u32) << 16)
            | ((bytes[index + 1] as u32) << 8)
            | bytes[index + 2] as u32;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push(TABLE[(n & 63) as usize] as char);
        index += 3;
    }
    match bytes.len() - index {
        1 => {
            let n = (bytes[index] as u32) << 16;
            out.push(TABLE[((n >> 18) & 63) as usize] as char);
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
        }
        2 => {
            let n = ((bytes[index] as u32) << 16) | ((bytes[index + 1] as u32) << 8);
            out.push(TABLE[((n >> 18) & 63) as usize] as char);
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
            out.push(TABLE[((n >> 6) & 63) as usize] as char);
        }
        _ => {}
    }
    out
}

fn form_body(pairs: &[(&str, &str)]) -> String {
    fn component(value: &str) -> String {
        let mut output = String::with_capacity(value.len());
        for byte in value.bytes() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                output.push(byte as char);
            } else {
                output.push('%');
                output.push_str(&format!("{byte:02X}"));
            }
        }
        output
    }
    pairs
        .iter()
        .map(|(key, value)| format!("{}={}", component(key), component(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn system_browser_command(url: &Url) -> Command {
    #[cfg(windows)]
    let mut command = Command::new("explorer.exe");
    #[cfg(target_os = "macos")]
    let mut command = Command::new("/usr/bin/open");
    #[cfg(not(any(windows, target_os = "macos")))]
    let mut command = Command::new("xdg-open");
    command.arg(url.as_str());
    command
}

fn open_google(url: &Url) -> Result<(), GoogleLoginError> {
    let expected_origin = Url::parse(GOOGLE_AUTH_ORIGIN)
        .map_err(|_| GoogleLoginError::ConfigurationUnavailable)?
        .origin();
    if url.scheme() != "https"
        || url.host_str() != Some("accounts.google.com")
        || url.origin() != expected_origin
        || url.path() != "/o/oauth2/v2/auth"
        || url.query().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some_and(|port| port != 443)
        || url.query_pairs().any(|(key, value)| {
            (key == "redirect_uri" && !value.starts_with("http://127.0.0.1:"))
                || (key == "response_type" && value != "code")
                || (key == "code_challenge_method" && value != "S256")
        })
    {
        return Err(GoogleLoginError::InvalidWorkerResponse);
    }
    system_browser_command(url)
        .spawn()
        .map(|_| ())
        .map_err(|_| GoogleLoginError::BrowserUnavailable)
}

fn callback(listener: TcpListener, expected_state: String) -> Result<String, GoogleLoginError> {
    listener
        .set_nonblocking(true)
        .map_err(|_| GoogleLoginError::CallbackUnavailable)?;
    let deadline = Instant::now() + CALLBACK_TIMEOUT;
    let mut attempts = 0;
    while Instant::now() < deadline && attempts < 10 {
        match listener.accept() {
            Ok((mut stream, address)) => {
                attempts += 1;
                if !address.ip().is_loopback() {
                    write_callback_page(&mut stream, false);
                    continue;
                }
                let mut bytes = [0_u8; MAX_CALLBACK_REQUEST + 1];
                let count = (&mut stream)
                    .take((MAX_CALLBACK_REQUEST + 1) as u64)
                    .read(&mut bytes)
                    .map_err(|_| GoogleLoginError::CallbackUnavailable)?;
                if count > MAX_CALLBACK_REQUEST {
                    write_callback_page(&mut stream, false);
                    return Err(GoogleLoginError::InvalidCallback);
                }
                let request = std::str::from_utf8(&bytes[..count])
                    .map_err(|_| GoogleLoginError::InvalidCallback)?;
                let first = request
                    .lines()
                    .next()
                    .ok_or(GoogleLoginError::InvalidCallback)?;
                let mut pieces = first.split_ascii_whitespace();
                if pieces.next() != Some("GET") {
                    write_callback_page(&mut stream, false);
                    continue;
                }
                let target = pieces.next().ok_or(GoogleLoginError::InvalidCallback)?;
                let version = pieces.next();
                if version != Some("HTTP/1.1") && version != Some("HTTP/1.0") {
                    write_callback_page(&mut stream, false);
                    continue;
                }
                let parsed = Url::parse(&format!("http://127.0.0.1{target}"))
                    .map_err(|_| GoogleLoginError::InvalidCallback)?;
                if parsed.path() != "/oauth/callback" || parsed.fragment().is_some() {
                    write_callback_page(&mut stream, false);
                    continue;
                }
                let state = parsed
                    .query_pairs()
                    .find(|(key, _)| key == "state")
                    .map(|(_, value)| value.into_owned());
                let code = parsed
                    .query_pairs()
                    .find(|(key, _)| key == "code")
                    .map(|(_, value)| value.into_owned());
                let error = parsed
                    .query_pairs()
                    .find(|(key, _)| key == "error")
                    .map(|(_, value)| value.into_owned());
                if error.is_some()
                    || state.as_deref() != Some(expected_state.as_str())
                    || code
                        .as_ref()
                        .is_none_or(|value| value.is_empty() || value.len() > 4096)
                    || parsed
                        .query_pairs()
                        .filter(|(key, _)| key == "state")
                        .count()
                        != 1
                    || parsed
                        .query_pairs()
                        .filter(|(key, _)| key == "code")
                        .count()
                        != 1
                {
                    write_callback_page(&mut stream, false);
                    continue;
                }
                write_callback_page(&mut stream, true);
                return code.ok_or(GoogleLoginError::InvalidCallback);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => return Err(GoogleLoginError::CallbackUnavailable),
        }
    }
    Err(GoogleLoginError::CallbackUnavailable)
}

fn write_callback_page(stream: &mut TcpStream, success: bool) {
    let (status, body) = if success {
        (
            "200 OK",
            "Google sign-in completed. You can return to Leviathan AI.",
        )
    } else {
        (
            "400 Bad Request",
            "Sign-in could not be completed. Return to Leviathan AI and retry.",
        )
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

async fn bounded_json(response: Response) -> Result<Value, GoogleLoginError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_WORKER_RESPONSE as u64)
    {
        return Err(GoogleLoginError::InvalidWorkerResponse);
    }
    let mut response = response;
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| GoogleLoginError::WorkerUnavailable)?
    {
        if body.len() + chunk.len() > MAX_WORKER_RESPONSE {
            return Err(GoogleLoginError::InvalidWorkerResponse);
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| GoogleLoginError::InvalidWorkerResponse)
}

pub async fn desktop_google_login(
    client: &Client,
    worker_origin: &Url,
    client_id: &str,
    device_id: &str,
    totp_code: Option<&str>,
) -> Result<Value, GoogleLoginError> {
    if client_id.is_empty()
        || client_id.len() > 256
        || !client_id.ends_with(".apps.googleusercontent.com")
        || device_id.is_empty()
        || device_id.len() > 128
    {
        return Err(GoogleLoginError::ConfigurationUnavailable);
    }
    let mut verifier_bytes = [0_u8; 32];
    getrandom::fill(&mut verifier_bytes).map_err(|_| GoogleLoginError::ConfigurationUnavailable)?;
    let verifier = b64url(&verifier_bytes);
    let challenge = b64url(&Sha256::digest(verifier.as_bytes()));
    let listener =
        TcpListener::bind(("127.0.0.1", 0)).map_err(|_| GoogleLoginError::CallbackUnavailable)?;
    let port = listener
        .local_addr()
        .map_err(|_| GoogleLoginError::CallbackUnavailable)?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}/oauth/callback");
    let start_url = worker_origin
        .join("/v1/auth/google/desktop/start")
        .map_err(|_| GoogleLoginError::ConfigurationUnavailable)?;
    let start = client
        .post(start_url)
        .json(&json!({ "device_id": device_id, "redirect_uri": redirect_uri, "code_challenge": challenge }))
        .send()
        .await
        .map_err(|_| GoogleLoginError::WorkerUnavailable)?;
    if !start.status().is_success() {
        return Err(GoogleLoginError::WorkerUnavailable);
    }
    let start_body = bounded_json(start).await?;
    let data = start_body
        .get("data")
        .and_then(Value::as_object)
        .ok_or(GoogleLoginError::InvalidWorkerResponse)?;
    let state = data
        .get("state")
        .and_then(Value::as_str)
        .filter(|value| (32..=256).contains(&value.len()))
        .ok_or(GoogleLoginError::InvalidWorkerResponse)?
        .to_owned();
    let authorization_url = data
        .get("authorization_url")
        .and_then(Value::as_str)
        .filter(|value| value.len() <= 4096)
        .ok_or(GoogleLoginError::InvalidWorkerResponse)?;
    let parsed_auth =
        Url::parse(authorization_url).map_err(|_| GoogleLoginError::InvalidWorkerResponse)?;
    let pairs: Vec<(String, String)> = parsed_auth
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    let expected_challenge = pairs
        .iter()
        .any(|(key, value)| key == "code_challenge" && value == &challenge);
    let expected_state = pairs
        .iter()
        .any(|(key, value)| key == "state" && value == &state);
    let expected_redirect = pairs
        .iter()
        .any(|(key, value)| key == "redirect_uri" && value == &redirect_uri);
    let expected_client = pairs
        .iter()
        .any(|(key, value)| key == "client_id" && value == client_id);
    let expected_method = pairs
        .iter()
        .any(|(key, value)| key == "code_challenge_method" && value == "S256");
    let expected_response = pairs
        .iter()
        .any(|(key, value)| key == "response_type" && value == "code");
    let expected_scope = pairs
        .iter()
        .any(|(key, value)| key == "scope" && value == "openid email profile");
    let expected_nonce = pairs
        .iter()
        .any(|(key, value)| key == "nonce" && value.len() >= 32 && value.len() <= 256);
    let allowed = [
        "client_id",
        "redirect_uri",
        "response_type",
        "scope",
        "state",
        "nonce",
        "code_challenge",
        "code_challenge_method",
    ];
    let exact_keys = pairs.len() == allowed.len()
        && pairs.iter().all(|(key, _)| allowed.contains(&key.as_str()));
    if !expected_challenge
        || !expected_state
        || !expected_redirect
        || !expected_client
        || !expected_method
        || !expected_response
        || !expected_scope
        || !expected_nonce
        || !exact_keys
    {
        return Err(GoogleLoginError::InvalidWorkerResponse);
    }
    open_google(&parsed_auth)?;

    let callback_state = state.clone();
    let callback_task =
        tauri::async_runtime::spawn_blocking(move || callback(listener, callback_state));
    let code = callback_task
        .await
        .map_err(|_| GoogleLoginError::CallbackUnavailable)??;

    let token = client
        .post(GOOGLE_TOKEN_URL)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(form_body(&[
            ("code", code.as_str()),
            ("client_id", client_id),
            ("redirect_uri", redirect_uri.as_str()),
            ("grant_type", "authorization_code"),
            ("code_verifier", verifier.as_str()),
        ]))
        .send()
        .await
        .map_err(|_| GoogleLoginError::GoogleTokenUnavailable)?;
    if !token.status().is_success() {
        return Err(GoogleLoginError::GoogleTokenUnavailable);
    }
    let token_body = bounded_json(token)
        .await
        .map_err(|_| GoogleLoginError::GoogleTokenUnavailable)?;
    let id_token = token_body
        .get("id_token")
        .and_then(Value::as_str)
        .filter(|value| (1..=32_768).contains(&value.len()))
        .ok_or(GoogleLoginError::GoogleTokenUnavailable)?;
    let mut payload = json!({ "state": state, "device_id": device_id, "id_token": id_token });
    if let Some(code) = totp_code {
        if code.len() != 6 || !code.bytes().all(|value| value.is_ascii_digit()) {
            return Err(GoogleLoginError::InvalidWorkerResponse);
        }
        payload["totp_code"] = json!(code);
    }
    let complete_url = worker_origin
        .join("/v1/auth/google/desktop/complete")
        .map_err(|_| GoogleLoginError::ConfigurationUnavailable)?;
    let complete = client
        .post(complete_url)
        .json(&payload)
        .send()
        .await
        .map_err(|_| GoogleLoginError::WorkerUnavailable)?;
    bounded_json(complete).await
}

#[cfg(test)]
mod tests {
    use super::{b64url, GoogleLoginError};

    #[test]
    fn base64url_encoding_is_unpadded_and_stable() {
        assert_eq!(b64url(b"f"), "Zg");
        assert_eq!(b64url(b"fo"), "Zm8");
        assert_eq!(b64url(b"foo"), "Zm9v");
    }

    #[test]
    fn errors_are_fixed_codes_without_external_text() {
        assert_eq!(
            GoogleLoginError::InvalidCallback.code(),
            "GOOGLE_CALLBACK_INVALID"
        );
    }
}
