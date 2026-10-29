pub(in crate::local_command_linux) fn record(stage: &'static str) {
    #[cfg(feature = "test-support")]
    {
        use std::io::Write;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        if std::env::var_os("RUNNE_TEST_TERMINAL_AGENT_FIXTURE").as_deref()
            != Some(std::ffi::OsStr::new("1"))
        {
            return;
        }
        let Some(root) = std::env::var_os("RUNNE_TEST_PROTECTED_RUNTIME_ROOT") else {
            return;
        };
        let root = std::path::Path::new(&root);
        let Ok(meta) = std::fs::symlink_metadata(root) else {
            return;
        };
        if !root.is_absolute()
            || !meta.is_dir()
            || meta.file_type().is_symlink()
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.permissions().mode() & 0o077 != 0
        {
            return;
        }
        let allowed = [
            "helper.request",
            "helper.target",
            "helper.image",
            "helper.descriptors",
            "helper.filesystem",
            "helper.ruleset",
            "helper.stdio",
            "helper.consume",
            "helper.spawn",
            "child.clone",
            "child.map",
            "child.ready",
            "child.stop",
            "child.area",
        ];
        if !allowed.contains(&stage) {
            return;
        }
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(root.join(".runne-test-native-helper-stage"))
        {
            let _ = writeln!(file, "{stage}");
        }
    }
    #[cfg(not(feature = "test-support"))]
    let _ = stage;
}
