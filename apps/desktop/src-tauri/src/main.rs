#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use leviathan_desktop_shell::license::{self, PendingTotpEnrollment, VerifiedOnlineGate};
use leviathan_desktop_shell::opener;
use leviathan_desktop_shell::platform::{
    self, dialog, IDYES, MB_ICONERROR, MB_ICONINFORMATION, MB_ICONWARNING, MB_OK, MB_YESNO,
};
use sha2::{Digest, Sha256};
use tauri::{Listener, Manager, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_updater::UpdaterExt;

mod update_policy;

struct Runtime {
    child: Mutex<Option<Child>>,
    closing: AtomicBool,
    connection: Mutex<Option<(u16, String)>>,
    shutdown_file: Mutex<Option<PathBuf>>,
    deferred_update_file: Mutex<Option<PathBuf>>,
}

struct DataScopeLock {
    _file: File,
}

#[derive(Clone)]
struct ProfileEvidence {
    data_dir_preexisted: bool,
    entries_sha256: String,
}

fn checked_metadata(path: &Path) -> std::io::Result<Option<fs::Metadata>> {
    platform::checked_metadata(path)
}

fn hash_entry_names(directory: &Path, label: &[u8], hasher: &mut Sha256) -> std::io::Result<()> {
    let Some(metadata) = checked_metadata(directory)? else {
        return Ok(());
    };
    if !metadata.is_dir() {
        return Err(std::io::Error::other(
            "profile data path is not a directory",
        ));
    }
    let mut names = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        checked_metadata(&entry.path())?;
        names.push(platform::encode_name(&entry.file_name()));
    }
    names.sort();
    for name in names {
        hasher.update(label);
        hasher.update(name);
        #[cfg(windows)]
        hasher.update([0u8, 0u8]);
        #[cfg(not(windows))]
        hasher.update([0u8]);
    }
    Ok(())
}

fn observe_profile(data_root: &Path) -> std::io::Result<ProfileEvidence> {
    let data_dir = data_root.join("data");
    let data_dir_preexisted = checked_metadata(&data_dir)?.is_some();
    let mut hasher = Sha256::new();
    hash_entry_names(data_root, b"root/", &mut hasher)?;
    hash_entry_names(&data_dir, b"data/", &mut hasher)?;
    let entries_sha256 = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(ProfileEvidence {
        data_dir_preexisted,
        entries_sha256,
    })
}

fn new_capability() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("secure Windows random source");
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn append_log(path: &Path, line: &str) {
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{line}");
    }
}

fn kill_sidecar(runtime: &Runtime) {
    if let Ok(mut guard) = runtime.child.lock() {
        if let Some(mut child) = guard.take() {
            if let Some(path) = runtime
                .shutdown_file
                .lock()
                .ok()
                .and_then(|path| path.clone())
            {
                let _ = fs::write(path, b"shutdown\n");
            }
            let deadline = Instant::now() + Duration::from_secs(8);
            while Instant::now() < deadline {
                match child.try_wait() {
                    Ok(Some(_)) => {
                        let _ = child.wait();
                        *runtime.connection.lock().expect("connection lock") = None;
                        return;
                    }
                    Ok(None) => thread::sleep(Duration::from_millis(100)),
                    Err(_) => break,
                }
            }
            platform::kill_tree(&mut child);
            *runtime.connection.lock().expect("connection lock") = None;
        }
    }
}

fn readiness_safe(port: u16, capability: &str) -> Result<bool, String> {
    let address = format!("127.0.0.1:{port}")
        .parse()
        .map_err(|_| "invalid loopback address".to_string())?;
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))
        .map_err(|_| "readiness endpoint unavailable")?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| "readiness timeout setup failed")?;
    write!(
        stream,
        "GET /desktop/update-readiness HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://127.0.0.1:{port}\r\nx-leviathan-capability: {capability}\r\nConnection: close\r\n\r\n"
    )
    .map_err(|_| "readiness request failed")?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|_| "readiness response failed")?;
    let response = String::from_utf8(response).map_err(|_| "readiness response invalid")?;
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| "readiness response invalid".to_string())?;
    if !headers
        .lines()
        .next()
        .is_some_and(|line| line.contains(" 200 "))
    {
        return Err("readiness endpoint refused request".into());
    }
    let payload: serde_json::Value =
        serde_json::from_str(body).map_err(|_| "readiness response invalid".to_string())?;
    let safe = payload
        .get("safe")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| "readiness response invalid".to_string())?;
    let reasons = payload
        .get("reasons")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "readiness response invalid".to_string())?;
    Ok(safe && reasons.is_empty())
}

fn readiness_cli_safe(executable: &Path) -> Result<bool, String> {
    let mut command = Command::new(executable);
    command
        .arg("update-readiness")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    platform::configure_child(&mut command);
    let mut child = command
        .spawn()
        .map_err(|_| "readiness CLI could not start")?;
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut output = String::new();
                if let Some(mut stdout) = child.stdout.take() {
                    let _ = stdout.read_to_string(&mut output);
                }
                if !status.success() {
                    return Err("readiness CLI failed".into());
                }
                let payload: serde_json::Value = serde_json::from_str(output.trim())
                    .map_err(|_| "readiness CLI response invalid")?;
                let safe = payload
                    .get("safe")
                    .and_then(serde_json::Value::as_bool)
                    .ok_or_else(|| "readiness CLI response invalid".to_string())?;
                let reasons = payload
                    .get("reasons")
                    .and_then(serde_json::Value::as_array)
                    .ok_or_else(|| "readiness CLI response invalid".to_string())?;
                return Ok(safe && reasons.is_empty());
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("readiness CLI timed out".into());
            }
        }
    }
}

fn persist_deferred_update(runtime: &Runtime, version: &str) -> Result<(), String> {
    let path = runtime
        .deferred_update_file
        .lock()
        .map_err(|_| "update state unavailable")?
        .clone()
        .ok_or("update state unavailable")?;
    let temp = path.with_extension("tmp");
    fs::write(&temp, version.as_bytes()).map_err(|_| "update state could not be saved")?;
    fs::rename(&temp, &path).map_err(|_| "update state could not be committed".into())
}

fn clear_deferred_update(runtime: &Runtime) {
    if let Some(path) = runtime
        .deferred_update_file
        .lock()
        .ok()
        .and_then(|path| path.clone())
    {
        let _ = fs::remove_file(path);
    }
}

fn updater_worker(
    app: tauri::AppHandle,
    runtime: Arc<Runtime>,
    executable: PathBuf,
    startup_gate: mpsc::Sender<()>,
) {
    tauri::async_runtime::spawn(async move {
        let deferred_on_start = runtime
            .deferred_update_file
            .lock()
            .ok()
            .and_then(|path| path.clone())
            .is_some_and(|path| path.is_file());
        let mut blocked_deferred_start = false;
        if deferred_on_start {
            match readiness_cli_safe(&executable) {
                Ok(true) => {
                    let updater = app
                        .updater_builder()
                        .version_comparator(|current, release| {
                            update_policy::strictly_newer(
                                &current.to_string(),
                                &release.version.to_string(),
                            )
                            .unwrap_or(false)
                        })
                        .on_before_exit({
                            let runtime = runtime.clone();
                            move || kill_sidecar(&runtime)
                        })
                        .build();
                    if let Ok(updater) = updater {
                        match updater.check().await {
                            Ok(Some(update))
                                if update_policy::strictly_newer(
                                    env!("CARGO_PKG_VERSION"),
                                    &update.version,
                                )
                                .unwrap_or(false) =>
                            {
                                if let Ok(bytes) = update.download(|_, _| {}, || {}).await {
                                    if readiness_cli_safe(&executable) == Ok(true) {
                                        if update.install(&bytes).is_ok() {
                                            clear_deferred_update(&runtime);
                                        }
                                    }
                                }
                            }
                            Ok(None) => clear_deferred_update(&runtime),
                            _ => {}
                        }
                    }
                }
                _ => {
                    blocked_deferred_start = true;
                    dialog(
                        "The pending update is unsafe to install now or readiness could not be verified. It will be checked again on the next launch.",
                        MB_OK | MB_ICONWARNING,
                    );
                }
            }
        }
        let _ = startup_gate.send(());
        loop {
            if runtime.closing.load(Ordering::SeqCst) {
                return;
            }
            let connection = runtime
                .connection
                .lock()
                .ok()
                .and_then(|connection| connection.clone());
            let has_connection = connection.is_some();
            if let Some((port, capability)) = connection {
                let version = match app
                    .updater_builder()
                    .version_comparator(|current, release| {
                        update_policy::strictly_newer(
                            &current.to_string(),
                            &release.version.to_string(),
                        )
                        .unwrap_or(false)
                    })
                    .on_before_exit({
                        let runtime = runtime.clone();
                        move || kill_sidecar(&runtime)
                    })
                    .build()
                {
                    Ok(updater) => match updater.check().await {
                        Ok(update) => update,
                        Err(_) => None,
                    },
                    Err(_) => None,
                };
                if let Some(update) = version {
                    let newer =
                        update_policy::strictly_newer(env!("CARGO_PKG_VERSION"), &update.version)
                            .unwrap_or(false);
                    if newer {
                        let deferred = runtime
                            .deferred_update_file
                            .lock()
                            .ok()
                            .and_then(|path| path.clone())
                            .is_some_and(|path| path.is_file());
                        let choice = if deferred && blocked_deferred_start {
                            0
                        } else if deferred {
                            IDYES
                        } else {
                            dialog(
                                &format!(
                                    "Version {} is available.\n\nDownload and install now?\nChoose No to install later.",
                                    update.version
                                ),
                                MB_YESNO | MB_ICONINFORMATION,
                            )
                        };
                        if choice == IDYES {
                            match readiness_safe(port, &capability) {
                                Ok(true) => match update.download(|_, _| {}, || {}).await {
                                    Ok(bytes) => match readiness_safe(port, &capability) {
                                        Ok(true) => {
                                            if update.install(&bytes).is_ok() {
                                                clear_deferred_update(&runtime);
                                                if let Some(window) = app.get_webview_window("main")
                                                {
                                                    let _ = window.eval(
                                                            "window.__TAURI_INTERNALS__.invoke('plugin:process|restart')",
                                                        );
                                                }
                                            }
                                        }
                                        _ => {
                                            let _ =
                                                persist_deferred_update(&runtime, &update.version);
                                            dialog(
                                                    "An active LIVE session, open paper orders, or a pending halt prevents a safe update. The update will install on next launch.",
                                                    MB_OK | MB_ICONWARNING,
                                                );
                                        }
                                    },
                                    Err(_) => {}
                                },
                                Ok(false) => {
                                    let _ = persist_deferred_update(&runtime, &update.version);
                                    dialog(
                                        "An active LIVE session, open paper orders, or a pending halt prevents a safe update. The update will install on next launch.",
                                        MB_OK | MB_ICONWARNING,
                                    );
                                }
                                Err(_) => {
                                    let _ = persist_deferred_update(&runtime, &update.version);
                                    dialog(
                                        "Update readiness could not be verified. The update will install on next launch after a safe readiness check.",
                                        MB_OK | MB_ICONWARNING,
                                    );
                                }
                            }
                        }
                    }
                }
            }
            if !has_connection {
                thread::sleep(Duration::from_millis(250));
                continue;
            }
            for _ in 0..(6 * 60 * 60) {
                if runtime.closing.load(Ordering::SeqCst) {
                    return;
                }
                thread::sleep(Duration::from_secs(1));
            }
        }
    });
}

fn pipe_log<R: std::io::Read + Send + 'static>(
    input: R,
    log: PathBuf,
    ready: Option<mpsc::Sender<u16>>,
) {
    thread::spawn(move || {
        for line in BufReader::new(input).lines() {
            match line {
                Ok(line) => {
                    append_log(&log, &line);
                    if let Some(sender) = &ready {
                        if let Some(port) = line
                            .strip_prefix("LEVIATHAN_READY port=")
                            .and_then(|value| value.trim().parse::<u16>().ok())
                        {
                            let _ = sender.send(port);
                        }
                    }
                }
                Err(_) => break,
            }
        }
    });
}

fn supervise(
    app: tauri::AppHandle,
    runtime: Arc<Runtime>,
    executable: PathBuf,
    log: PathBuf,
    capability: String,
    license_state: &'static str,
    license_features: String,
    session_principal_id: String,
    session_entitlement_digest: String,
    profile_evidence: ProfileEvidence,
    startup_gate: mpsc::Receiver<()>,
) {
    if startup_gate.recv_timeout(Duration::from_secs(15)).is_err() {
        dialog(
            "Update readiness could not be checked before startup. The application will not start the local server.",
            MB_OK | MB_ICONERROR,
        );
        app.exit(1);
        return;
    }
    loop {
        if runtime.closing.load(Ordering::SeqCst) {
            return;
        }
        append_log(&log, "Starting local sidecar");
        if let Some(path) = runtime
            .shutdown_file
            .lock()
            .ok()
            .and_then(|path| path.clone())
        {
            let _ = fs::remove_file(path);
        }
        let mut command = Command::new(&executable);
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("LEVIATHAN_DESKTOP_CAPABILITY", &capability)
            .env("LEVIATHAN_LICENSE_STATE", license_state)
            .env("LEVIATHAN_LICENSE_FEATURES", &license_features)
            .env("LEVIATHAN_SESSION_PRINCIPAL", &session_principal_id)
            .env(
                "LEVIATHAN_SESSION_ENTITLEMENT_SHA256",
                &session_entitlement_digest,
            )
            .env(
                "LEVIATHAN_DESKTOP_SHUTDOWN_FILE",
                runtime
                    .shutdown_file
                    .lock()
                    .expect("shutdown path lock")
                    .as_ref()
                    .expect("shutdown path configured")
                    .as_os_str(),
            )
            .env(
                "LEVIATHAN_DATA_ROOT_PREEXISTED",
                if profile_evidence.data_dir_preexisted {
                    "1"
                } else {
                    "0"
                },
            )
            .env(
                "LEVIATHAN_DATA_ROOT_ENTRY_SHA256",
                &profile_evidence.entries_sha256,
            );
        platform::configure_sidecar(&mut command);
        let mut guard = runtime.child.lock().expect("sidecar lock");
        if runtime.closing.load(Ordering::SeqCst) {
            return;
        }
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                drop(guard);
                dialog(
                    &format!(
                        "Could not start the local server: {error}\nLog: {}",
                        log.display()
                    ),
                    MB_OK | MB_ICONERROR,
                );
                app.exit(1);
                return;
            }
        };
        let (sender, receiver) = mpsc::channel();
        if let Some(stdout) = child.stdout.take() {
            pipe_log(stdout, log.clone(), Some(sender));
        }
        if let Some(stderr) = child.stderr.take() {
            pipe_log(stderr, log.clone(), None);
        }
        *guard = Some(child);
        drop(guard);

        let port = match receiver.recv_timeout(Duration::from_secs(20)) {
            Ok(port) => port,
            Err(_) => {
                kill_sidecar(&runtime);
                if runtime.closing.load(Ordering::SeqCst) {
                    return;
                }
                dialog(
                    &format!(
                        "The local server did not become ready within 20 seconds.\nLog: {}",
                        log.display()
                    ),
                    MB_OK | MB_ICONERROR,
                );
                app.exit(1);
                return;
            }
        };
        *runtime.connection.lock().expect("connection lock") = Some((port, capability.clone()));
        if runtime.closing.load(Ordering::SeqCst) {
            kill_sidecar(&runtime);
            return;
        }
        let url = match url::Url::parse(&format!("http://127.0.0.1:{port}/")) {
            Ok(url) => url,
            Err(error) => {
                append_log(&log, &format!("Invalid local URL: {error}"));
                kill_sidecar(&runtime);
                app.exit(1);
                return;
            }
        };
        append_log(&log, &format!("Local UI: {url}"));
        let navigation = match app.get_webview_window("main") {
            Some(window) => window.navigate(url).map_err(|error| error.to_string()),
            None => Err("Desktop window is missing".to_string()),
        };
        if let Err(error) = navigation {
            append_log(&log, &error);
            kill_sidecar(&runtime);
            dialog(
                &format!(
                    "The desktop window could not load the local UI.\nLog: {}",
                    log.display()
                ),
                MB_OK | MB_ICONERROR,
            );
            app.exit(1);
            return;
        }

        let started = Instant::now();
        while !runtime.closing.load(Ordering::SeqCst) {
            let exited = {
                let mut guard = runtime.child.lock().expect("sidecar lock");
                matches!(
                    guard.as_mut().map(|child| child.try_wait()),
                    Some(Ok(Some(_)))
                )
            };
            if exited {
                break;
            }
            thread::sleep(Duration::from_millis(200));
        }
        if runtime.closing.load(Ordering::SeqCst) {
            kill_sidecar(&runtime);
            return;
        }
        *runtime.child.lock().expect("sidecar lock") = None;
        *runtime.connection.lock().expect("connection lock") = None;
        append_log(
            &log,
            &format!(
                "Sidecar exited after {} seconds",
                started.elapsed().as_secs()
            ),
        );
        let choice = dialog(
            &format!(
                "The local server stopped. Restart it?\nLog: {}",
                log.display()
            ),
            MB_YESNO | MB_ICONWARNING,
        );
        if choice != IDYES {
            app.exit(1);
            return;
        }
    }
}

fn main() {
    let runtime = Arc::new(Runtime {
        child: Mutex::new(None),
        closing: AtomicBool::new(false),
        connection: Mutex::new(None),
        shutdown_file: Mutex::new(None),
        deferred_update_file: Mutex::new(None),
    });
    let setup_runtime = runtime.clone();
    let window_runtime = runtime.clone();
    let exit_runtime = runtime.clone();
    tauri::Builder::default()
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .manage(PendingTotpEnrollment::default())
        .manage(VerifiedOnlineGate::default())
        .invoke_handler(tauri::generate_handler![
            opener::open_external_url,
            license::license_sign_in,
            license::license_google_sign_in,
            license::license_google_enroll_totp,
            license::license_enroll_totp,
            license::license_status,
            license::license_sign_out,
        ])
        .setup(move |app| {
            #[cfg(windows)]
            let sidecar_relative = "resources/sidecar/leviathan-desktop.exe";
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            let sidecar_relative = "resources/sidecar/leviathan-desktop-aarch64-apple-darwin";
            #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
            let sidecar_relative = "resources/sidecar/leviathan-desktop-x86_64-apple-darwin";
            let executable = app.path().resolve(
                sidecar_relative,
                tauri::path::BaseDirectory::Resource,
            )?;
            let data = platform::data_root()?;
            let profile_evidence = match observe_profile(&data) {
                Ok(evidence) => evidence,
                Err(_) => {
                    dialog(
                        "The local profile could not be verified. Check its data directory and contact support before restarting.",
                        MB_OK | MB_ICONERROR,
                    );
                    return Err("local profile verification failed".into());
                }
            };
            fs::create_dir_all(&data)?;
            let data_dir = data.join("data");
            fs::create_dir_all(&data_dir)?;
            let shutdown_file = data_dir.join("desktop-shutdown.request");
            let _ = fs::remove_file(&shutdown_file);
            *setup_runtime.shutdown_file.lock().expect("shutdown path lock") =
                Some(shutdown_file);
            *setup_runtime
                .deferred_update_file
                .lock()
                .expect("update marker lock") = Some(data_dir.join("desktop-update-deferred"));
            let scope_lock = platform::open_instance_lock(&data.join("desktop-instance.lock"))?;
            app.manage(DataScopeLock { _file: scope_lock });
            let log = data.join("desktop-sidecar.log");
            let (startup_sender, startup_receiver) = mpsc::channel();
            let startup_receiver = Arc::new(Mutex::new(Some(startup_receiver)));
            let capability = new_capability();
            let bridge = include_str!("bridge.js").replace("__CAPABILITY__", &capability);
            let launch_once = Arc::new(AtomicBool::new(false));
            let active_session_binding = Arc::new(Mutex::new(None::<(String, String)>));
            let listener_app = app.handle().clone();
            let listener_runtime = setup_runtime.clone();
            let listener_executable = executable.clone();
            let listener_log = log.clone();
            let listener_capability = capability.clone();
            let listener_profile = profile_evidence.clone();
            let listener_receiver = startup_receiver.clone();
            let listener_launch_once = launch_once.clone();
            let listener_session_binding = active_session_binding.clone();
            let listener_sender = startup_sender.clone();
            WebviewWindowBuilder::new(app, "signin", WebviewUrl::App("signin.html".into()))
                .title("Leviathan AI — Sign in")
                .initialization_script(include_str!("../../src/bridge_license.js"))
                .build()?;
            app.listen("license-unlocked", move |event| {
                let payload: serde_json::Value =
                    serde_json::from_str(event.payload()).unwrap_or_default();
                let state = payload.get("state").and_then(serde_json::Value::as_str);
                let unlocked = payload
                    .get("unlocked")
                    .and_then(serde_json::Value::as_bool)
                    == Some(true);
                let read_only = payload
                    .get("readOnly")
                    .and_then(serde_json::Value::as_bool)
                    == Some(true);
                let Some(principal_id) = payload
                    .get("principalId")
                    .and_then(serde_json::Value::as_str)
                    .filter(|value| license::valid_principal_id(value))
                    .map(str::to_owned)
                else {
                    return;
                };
                let Some(entitlement_digest) = payload
                    .get("entitlementDigest")
                    .and_then(serde_json::Value::as_str)
                    .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
                    .map(str::to_owned)
                else {
                    return;
                };
                let Some(features) = payload
                    .get("features")
                    .and_then(serde_json::Value::as_object)
                    .and_then(|features| {
                        features
                            .iter()
                            .map(|(name, enabled)| {
                                enabled.as_bool().map(|enabled| (name.clone(), enabled))
                            })
                            .collect::<Option<BTreeMap<_, _>>>()
                    })
                else {
                    return;
                };
                let Some(state) = state else {
                    return;
                };
                if !unlocked
                    || (state == "GRACE" && !license::GRACE_UNLOCK_ENABLED)
                    || !matches!(
                        (state, read_only),
                        ("VERIFIED_ONLINE", false) | ("GRACE", true)
                    )
                    || !license::consume_verified_online_unlock(
                        &listener_app,
                        state,
                        read_only,
                        &features,
                        &principal_id,
                        &entitlement_digest,
                    )
                {
                    return;
                }
                if listener_launch_once.swap(true, Ordering::SeqCst) {
                    let changed = listener_session_binding
                        .lock()
                        .map(|binding| {
                            binding.as_ref().is_none_or(|(active_principal, active_digest)| {
                                active_principal != &principal_id
                                    || active_digest != &entitlement_digest
                            })
                        })
                        .unwrap_or(true);
                    if changed {
                        // The sidecar principal is immutable for its process lifetime.
                        listener_app.exit(0);
                    }
                    return;
                }
                if let Ok(mut binding) = listener_session_binding.lock() {
                    *binding = Some((principal_id.clone(), entitlement_digest.clone()));
                } else {
                    listener_app.exit(1);
                    return;
                }
                let sidecar_license_state = match state {
                    "VERIFIED_ONLINE" => "VERIFIED_ONLINE",
                    "GRACE" => "GRACE_READ_ONLY",
                    _ => return,
                };
                let sidecar_license_features = license::enabled_feature_csv(&features);
                let Some(startup_receiver) = listener_receiver
                    .lock()
                    .ok()
                    .and_then(|mut receiver| receiver.take())
                else {
                    listener_app.exit(1);
                    return;
                };
                if WebviewWindowBuilder::new(
                    &listener_app,
                    "main",
                    WebviewUrl::App("index.html".into()),
                )
                .title("Leviathan AI")
                .inner_size(1440.0, 900.0)
                .initialization_script(bridge.clone())
                .build()
                .is_err()
                {
                    listener_app.exit(1);
                    return;
                }
                if let Some(signin) = listener_app.get_webview_window("signin") {
                    let _ = signin.close();
                }
                let supervise_app = listener_app.clone();
                let supervise_runtime = listener_runtime.clone();
                let supervise_executable = listener_executable.clone();
                let supervise_log = listener_log.clone();
                let supervise_capability = listener_capability.clone();
                let supervise_profile = listener_profile.clone();
                let supervise_features = sidecar_license_features;
                let supervise_principal_id = principal_id;
                let supervise_entitlement_digest = entitlement_digest;
                thread::spawn(move || {
                    supervise(
                        supervise_app,
                        supervise_runtime,
                        supervise_executable,
                        supervise_log,
                        supervise_capability,
                        sidecar_license_state,
                        supervise_features,
                        supervise_principal_id,
                        supervise_entitlement_digest,
                        supervise_profile,
                        startup_receiver,
                    );
                });
                updater_worker(
                    listener_app.clone(),
                    listener_runtime.clone(),
                    listener_executable.clone(),
                    listener_sender.clone(),
                );
            });
            Ok(())
        })
        .on_window_event(move |window, event| {
            if window.label() == "main"
                && matches!(event, tauri::WindowEvent::CloseRequested { .. })
            {
                window_runtime.closing.store(true, Ordering::SeqCst);
                kill_sidecar(&window_runtime);
            }
        })
        .build(tauri::generate_context!())
        .expect("failed to create Leviathan AI shell")
        .run(move |_app, event| {
            if matches!(event, tauri::RunEvent::Exit) {
                exit_runtime.closing.store(true, Ordering::SeqCst);
                kill_sidecar(&exit_runtime);
            }
        });
}

#[cfg(test)]
mod tests {
    use super::observe_profile;
    use std::fs;

    #[test]
    fn observes_data_directory_before_shell_creates_it() {
        let unique = format!(
            "leviathan-profile-evidence-{}-{}",
            std::process::id(),
            rand_suffix()
        );
        let root = std::env::temp_dir().join(unique);
        let fresh = observe_profile(&root).expect("observe absent profile");
        assert!(!fresh.data_dir_preexisted);
        fs::create_dir_all(root.join("data")).expect("create data directory");
        fs::write(root.join("data").join("leviathan.db"), b"test").expect("write sample entry");
        let existing = observe_profile(&root).expect("observe existing profile");
        assert!(existing.data_dir_preexisted);
        assert_ne!(fresh.entries_sha256, existing.entries_sha256);
        fs::remove_dir_all(root).expect("remove isolated test directory");
    }

    fn rand_suffix() -> String {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes).expect("random test directory suffix");
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
