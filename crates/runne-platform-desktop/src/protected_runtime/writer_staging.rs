#[cfg(unix)]
impl ActivationStateStore {
    fn stage_provider_writer(
        &self,
        daemon_path: &Path,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        let source = daemon_path
            .parent()
            .map(|directory| directory.join("runne"))
            .ok_or(ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
        let source = validate_executable_path(&source)?;
        let trusted = ExecutableIdentityV1::measure(&source)
            .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
        let (staged, _) = self.stage_trusted_executable(&source, &trusted)?;
        let directory = staged
            .parent()
            .ok_or(ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
        let alias = directory.join("runne");
        let target = staged
            .file_name()
            .ok_or(ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;

        match std::os::unix::fs::symlink(target, &alias) {
            Ok(()) => sync_directory(directory)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = std::fs::canonicalize(&alias).ok();
                if existing.as_deref() != Some(staged.as_path()) {
                    // Forward refresh: the alias still names a writer from a
                    // previous bundle generation. Replace it atomically with
                    // the just-staged, digest-verified writer; readers see
                    // either the old or the new alias, never a partial state.
                    let temporary =
                        directory.join(format!(".runne.{}.tmp", uuid::Uuid::now_v7()));
                    std::os::unix::fs::symlink(target, &temporary)
                        .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
                    let result = std::fs::rename(&temporary, &alias);
                    if result.is_err() {
                        let _ = std::fs::remove_file(&temporary);
                        return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch);
                    }
                    sync_directory(directory)?;
                    let refreshed = std::fs::canonicalize(&alias)
                        .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
                    if refreshed != staged {
                        return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch);
                    }
                }
            }
            Err(_) => return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch),
        }
        validate_staged_executable(&staged, &trusted)
    }
}

#[cfg(all(test, unix))]
mod writer_alias_refresh_tests {
    use std::os::unix::fs::PermissionsExt as _;

    fn write_private_executable(path: &std::path::Path, content: &[u8]) {
        std::fs::write(path, content).expect("write executable fixture");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o500))
            .expect("private executable mode");
    }

    #[test]
    fn stale_writer_alias_refreshes_to_the_current_staged_writer() {
        let temporary = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))
            .expect("owner-private tempdir");
        let runtime_root = temporary.path().join("runtime");
        std::fs::create_dir(&runtime_root).expect("runtime root");
        std::fs::set_permissions(&runtime_root, std::fs::Permissions::from_mode(0o700))
            .expect("owner-private runtime root");
        // macOS tempdirs live behind the /var -> /private/var symlink; the
        // production runtime root is already canonical, so canonicalize here
        // to keep staged-path comparisons exact.
        let runtime_root = std::fs::canonicalize(&runtime_root).expect("canonical runtime root");
        let macos = temporary.path().join("MacOS");
        std::fs::create_dir(&macos).expect("bundle macos directory");
        let daemon = macos.join("runned");
        write_private_executable(&daemon, b"daemon-generation-a");
        let writer = macos.join("runne");
        write_private_executable(&writer, b"writer-generation-a");

        let store = super::ActivationStateStore::open(&runtime_root).expect("state store");
        store
            .stage_provider_writer(&daemon)
            .expect("initial writer staging");
        let alias = runtime_root
            .join(".desktop-protected-activation")
            .join("executables-v1")
            .join("runne");
        let first_target = std::fs::canonicalize(&alias).expect("initial alias target");

        std::fs::remove_file(&writer).expect("drop generation-a writer");
        write_private_executable(&writer, b"writer-generation-b");
        store
            .stage_provider_writer(&daemon)
            .expect("stale alias must refresh forward");
        let refreshed_target = std::fs::canonicalize(&alias).expect("refreshed alias target");
        assert_ne!(
            refreshed_target, first_target,
            "the alias must move to the freshly staged writer generation"
        );
        let refreshed_bytes = std::fs::read(&refreshed_target).expect("refreshed writer bytes");
        assert_eq!(refreshed_bytes, b"writer-generation-b");

        store
            .stage_provider_writer(&daemon)
            .expect("unchanged writer keeps the exact alias");
        assert_eq!(
            std::fs::canonicalize(&alias).expect("stable alias target"),
            refreshed_target
        );
    }
}
