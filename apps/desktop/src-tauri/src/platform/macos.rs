use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command};

use super::{IDYES, MB_ICONERROR, MB_ICONINFORMATION, MB_ICONWARNING, MB_YESNO};

const LOCK_EX: i32 = 2;
const SIGTERM: i32 = 15;
const SIGKILL: i32 = 9;
unsafe extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
    fn kill(pid: i32, signal: i32) -> i32;
}

pub fn dialog(message: &str, flags: u32) -> i32 {
    let escaped = message.replace('\\', "\\\\").replace('"', "\\\"");
    let script = if flags & MB_YESNO != 0 {
        format!("display dialog \"{escaped}\" buttons {{\"No\", \"Yes\"}} default button \"Yes\" with icon caution")
    } else if flags & MB_ICONERROR != 0 {
        format!("display alert \"Leviathan AI\" message \"{escaped}\" as critical")
    } else if flags & MB_ICONINFORMATION != 0 {
        format!("display alert \"Leviathan AI\" message \"{escaped}\" as informational")
    } else if flags & MB_ICONWARNING != 0 {
        format!("display alert \"Leviathan AI\" message \"{escaped}\" as warning")
    } else {
        format!("display dialog \"{escaped}\"")
    };
    match Command::new("/usr/bin/osascript")
        .args(["-e", &script])
        .output()
    {
        Ok(output) if output.status.success() && flags & MB_YESNO != 0 => {
            if String::from_utf8_lossy(&output.stdout).contains("button returned:Yes") {
                IDYES
            } else {
                7
            }
        }
        Ok(output) if output.status.success() => 1,
        _ => 0,
    }
}

pub fn configure_child(_: &mut Command) {}

pub fn kill_tree(child: &mut Child) {
    let group = -(child.id() as i32);
    unsafe { kill(group, SIGTERM) };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    if child.try_wait().ok().flatten().is_none() {
        unsafe { kill(group, SIGKILL) };
        let _ = child.wait();
    }
}

pub fn configure_sidecar(command: &mut Command) {
    command.process_group(0);
}

pub fn open_instance_lock(options: OpenOptions, path: &Path) -> io::Result<File> {
    let file = options.open(path)?;
    let result = unsafe { flock(file.as_raw_fd(), LOCK_EX | 4) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}
