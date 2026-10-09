use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command};

use super::{MB_ICONERROR, MB_ICONINFORMATION, MB_ICONWARNING, MB_YESNO};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, MB_ICONERROR as W_MB_ICONERROR, MB_ICONINFORMATION as W_MB_ICONINFORMATION,
    MB_ICONWARNING as W_MB_ICONWARNING, MB_OK as W_MB_OK, MB_YESNO as W_MB_YESNO,
};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

pub fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

pub fn dialog(message: &str, flags: u32) -> i32 {
    let title: Vec<u16> = "Leviathan AI".encode_utf16().chain(Some(0)).collect();
    let body: Vec<u16> = message.encode_utf16().chain(Some(0)).collect();
    let native_flags = (if flags & MB_YESNO != 0 {
        W_MB_YESNO
    } else {
        W_MB_OK
    }) | if flags & MB_ICONERROR != 0 {
        W_MB_ICONERROR
    } else if flags & MB_ICONWARNING != 0 {
        W_MB_ICONWARNING
    } else if flags & MB_ICONINFORMATION != 0 {
        W_MB_ICONINFORMATION
    } else {
        0
    };
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            body.as_ptr(),
            title.as_ptr(),
            native_flags,
        )
    }
}

pub fn configure_child(command: &mut Command) {
    command.creation_flags(CREATE_NO_WINDOW);
}

pub fn kill_tree(child: &mut Child) {
    let pid = child.id();
    let _ = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    let _ = child.wait();
}

pub fn open_instance_lock(mut options: OpenOptions, path: &Path) -> io::Result<File> {
    options.share_mode(0).open(path)
}
