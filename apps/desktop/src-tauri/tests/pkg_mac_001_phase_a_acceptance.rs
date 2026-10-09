#[path = "../src/platform/mod.rs"]
mod platform;

#[cfg(windows)]
#[test]
fn windows_rust_data_root_uses_local_app_data_and_rejects_missing_or_relative_roots() {
    use std::ffi::OsString;
    use std::path::PathBuf;

    struct RestoreLocalAppData(Option<OsString>);

    impl Drop for RestoreLocalAppData {
        fn drop(&mut self) {
            if let Some(value) = self.0.take() {
                std::env::set_var("LOCALAPPDATA", value);
            } else {
                std::env::remove_var("LOCALAPPDATA");
            }
        }
    }

    let _restore = RestoreLocalAppData(std::env::var_os("LOCALAPPDATA"));
    std::env::set_var("LOCALAPPDATA", r"C:\PKG-MAC-ACCEPTANCE\Local");
    assert_eq!(
        platform::data_root().expect("configured Windows root"),
        PathBuf::from(r"C:\PKG-MAC-ACCEPTANCE\Local\LeviathanAI")
    );

    std::env::remove_var("LOCALAPPDATA");
    assert!(
        platform::data_root().is_err(),
        "missing root must fail closed"
    );

    std::env::set_var("LOCALAPPDATA", r"..\outside");
    assert!(
        platform::data_root().is_err(),
        "relative or traversal root must fail closed"
    );
}
