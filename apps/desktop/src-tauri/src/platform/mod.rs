use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

pub const IDYES: i32 = 6;
pub const MB_OK: u32 = 0;
pub const MB_ICONERROR: u32 = 1;
pub const MB_ICONINFORMATION: u32 = 2;
pub const MB_ICONWARNING: u32 = 4;
pub const MB_YESNO: u32 = 8;

fn validated_base(path: PathBuf, error: &'static str) -> Result<PathBuf, &'static str> {
    if path.as_os_str().is_empty()
        || path.as_os_str().to_string_lossy().contains('\0')
        || !path.is_absolute()
        || path
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return Err(error);
    }
    Ok(path)
}

pub fn data_root() -> Result<PathBuf, &'static str> {
    #[cfg(windows)]
    {
        return std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .map(|path| validated_base(path, "LOCALAPPDATA is missing"))
            .transpose()?
            .map(|path| path.join("LeviathanAI"))
            .ok_or("LOCALAPPDATA is missing");
    }
    #[cfg(target_os = "macos")]
    {
        return std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|path| validated_base(path, "HOME is missing"))
            .transpose()?
            .map(|path| path.join("Library/Application Support/LeviathanAI"))
            .ok_or("HOME is missing");
    }
    #[allow(unreachable_code)]
    Err("unsupported desktop platform")
}

#[cfg(test)]
mod data_root_tests {
    use super::validated_base;
    use std::path::PathBuf;

    #[test]
    fn rejects_relative_traversal_and_empty_bases() {
        for candidate in [
            PathBuf::new(),
            PathBuf::from("relative"),
            PathBuf::from("../outside"),
        ] {
            assert_eq!(
                validated_base(candidate, "base is invalid"),
                Err("base is invalid")
            );
        }
    }

    #[test]
    fn accepts_absolute_base_without_normalizing_it() {
        let candidate = std::env::temp_dir().join("pkg-mac-base");
        assert_eq!(
            validated_base(candidate.clone(), "base is invalid"),
            Ok(candidate)
        );
    }
}

pub fn checked_metadata(path: &Path) -> io::Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(io::Error::other("profile path contains a symbolic link"))
        }
        #[cfg(windows)]
        Ok(metadata) if windows::is_reparse_point(&metadata) => {
            Err(io::Error::other("profile path contains a reparse point"))
        }
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

pub fn encode_name(name: &std::ffi::OsStr) -> Vec<u8> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        return name.encode_wide().flat_map(u16::to_le_bytes).collect();
    }
    #[cfg(not(windows))]
    name.as_encoded_bytes().to_vec()
}

pub fn dialog(message: &str, flags: u32) -> i32 {
    #[cfg(windows)]
    {
        return windows::dialog(message, flags);
    }
    #[cfg(target_os = "macos")]
    {
        return macos::dialog(message, flags);
    }
    #[allow(unreachable_code)]
    0
}

pub fn configure_child(command: &mut Command) {
    #[cfg(windows)]
    windows::configure_child(command);
    #[cfg(target_os = "macos")]
    macos::configure_child(command);
}

pub fn configure_sidecar(command: &mut Command) {
    configure_child(command);
    #[cfg(target_os = "macos")]
    macos::configure_sidecar(command);
}

pub fn kill_tree(child: &mut Child) {
    #[cfg(windows)]
    windows::kill_tree(child);
    #[cfg(target_os = "macos")]
    macos::kill_tree(child);
}

pub fn open_instance_lock(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(windows)]
    return windows::open_instance_lock(options, path);
    #[cfg(target_os = "macos")]
    return macos::open_instance_lock(options, path);
    #[allow(unreachable_code)]
    options.open(path)
}
