use serde_json::Value;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn valid_origin(value: &str) -> bool {
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    let is_https = url.scheme() == "https"
        && url.host_str().is_some()
        && url.port().is_none_or(|port| port > 0);
    let is_loopback = url.scheme() == "http"
        && matches!(url.host_str(), Some("127.0.0.1" | "localhost"))
        && url.port().is_some_and(|port| port > 0);
    let origin = url.origin().ascii_serialization();
    (is_https || is_loopback)
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && origin == value
}

fn write_worker_config(manifest_dir: &Path) {
    println!("cargo:rerun-if-env-changed=LEVIATHAN_LICENSE_WORKER_CONFIG");
    let source = match env::var_os("LEVIATHAN_LICENSE_WORKER_CONFIG") {
        Some(path) => {
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                panic!("invalid license Worker config path");
            }
            path
        }
        None => manifest_dir.join("../../../infra/release/license_worker.json"),
    };
    println!("cargo:rerun-if-changed={}", source.display());

    let contents = fs::read(&source).expect("license Worker config is unavailable");
    let config: Value =
        serde_json::from_slice(&contents).expect("license Worker config is invalid");
    let object = config
        .as_object()
        .filter(|value| value.len() == 1)
        .expect("license Worker config is invalid");
    let origin = object
        .get("origin")
        .and_then(Value::as_str)
        .filter(|value| valid_origin(value))
        .expect("license Worker origin is invalid");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is missing"));
    let output = out_dir.join("license_worker.json");
    let output_contents = serde_json::to_vec(&serde_json::json!({ "origin": origin }))
        .expect("license Worker config could not be encoded");
    fs::write(output, output_contents).expect("license Worker config could not be embedded");
}

fn write_google_client_config(manifest_dir: &Path) {
    println!("cargo:rerun-if-env-changed=LEVIATHAN_GOOGLE_CLIENT_CONFIG");
    let source = match env::var_os("LEVIATHAN_GOOGLE_CLIENT_CONFIG") {
        Some(path) => {
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                panic!("invalid Google client config path");
            }
            path
        }
        None => manifest_dir.join("../../../infra/release/google_oauth.json"),
    };
    println!("cargo:rerun-if-changed={}", source.display());
    let contents = fs::read(&source).expect("Google OAuth client config is unavailable");
    let config: Value =
        serde_json::from_slice(&contents).expect("Google OAuth client config is invalid");
    let object = config
        .as_object()
        .filter(|value| value.len() == 1)
        .expect("Google OAuth client config is invalid");
    let client_id = object
        .get("desktop_client_id")
        .and_then(Value::as_str)
        .filter(|value| {
            value.is_empty()
                || (value.len() <= 256 && value.ends_with(".apps.googleusercontent.com"))
        })
        .expect("Google Desktop client ID is invalid");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is missing"));
    fs::write(
        out_dir.join("google_oauth.json"),
        serde_json::to_vec(&serde_json::json!({
            "desktop_client_id": client_id,
        }))
        .expect("Google config could not be encoded"),
    )
    .expect("Google config could not be embedded");
}

fn main() {
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir missing"));
    write_worker_config(&manifest_dir);
    write_google_client_config(&manifest_dir);
    tauri_build::build();
}
