#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use tauri::Manager;

fn valid_device_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn read_device_id(path: &PathBuf) -> Result<String, String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "Device identity is unavailable")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 64 {
        return Err("Device identity is unavailable".to_string());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| "Device identity is unavailable")?;
    let mut value = String::new();
    file.read_to_string(&mut value)
        .map_err(|_| "Device identity is unavailable")?;
    let value = value.trim();
    if !valid_device_id(value) {
        return Err("Device identity is unavailable".to_string());
    }
    Ok(value.to_ascii_lowercase())
}

#[tauri::command]
fn device_id(app: tauri::AppHandle) -> Result<String, String> {
    let directory = app
        .path()
        .app_local_data_dir()
        .map_err(|_| "Device identity is unavailable")?;
    fs::create_dir_all(&directory).map_err(|_| "Device identity is unavailable")?;
    let path = directory.join("admin-device-id");
    if path.exists() {
        return read_device_id(&path);
    }

    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| "Device identity is unavailable")?;
    let value = bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return read_device_id(&path),
        Err(_) => return Err("Device identity is unavailable".to_string()),
    };
    file.write_all(value.as_bytes())
        .map_err(|_| "Device identity is unavailable")?;
    file.sync_all()
        .map_err(|_| "Device identity is unavailable")?;
    Ok(value)
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .invoke_handler(tauri::generate_handler![device_id])
        .run(tauri::generate_context!())
        .expect("failed to run Leviathan Admin");
}
