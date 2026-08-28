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
                let existing = std::fs::canonicalize(&alias)
                    .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
                if existing != staged {
                    return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch);
                }
            }
            Err(_) => return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch),
        }
        validate_staged_executable(&staged, &trusted)
    }
}
