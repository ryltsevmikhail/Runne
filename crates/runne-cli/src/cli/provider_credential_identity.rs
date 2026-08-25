const fn resolve_authenticated_packaged_credential_access(
    current_writer: &std::path::Path,
) -> Result<ProviderCredentialAccessPolicy, CliError> {
    let _ = current_writer;
    Err(CliError::CredentialOperation)
}

#[cfg(test)]
#[allow(dead_code)]
fn resolve_packaged_credential_access(
    current_writer: &std::path::Path,
) -> Result<ProviderCredentialAccessPolicy, CliError> {
    resolve_packaged_credential_access_with_hook(current_writer, || {})
}

#[cfg(test)]
#[allow(dead_code)]
fn resolve_packaged_credential_access_with_hook(
    current_writer: &std::path::Path,
    hook: impl FnOnce(),
) -> Result<ProviderCredentialAccessPolicy, CliError> {
    let writer = fixture_executable(current_writer, "runne")?;
    let directory = writer.parent().ok_or(CliError::CredentialOperation)?;
    let reader = fixture_executable(&directory.join(native_executable_name("runned")), "runned")?;
    let writer_identity = fixture_file_identity(&writer)?;
    let reader_identity = fixture_file_identity(&reader)?;
    let access = ProviderCredentialAccessPolicy::new(&writer, &reader)
        .map_err(|_| CliError::CredentialOperation)?;
    hook();
    let writer_identity_matches = writer_identity == fixture_file_identity(&writer)?;
    let reader_identity_matches = reader_identity == fixture_file_identity(&reader)?;
    let remeasured = ProviderCredentialAccessPolicy::new(&writer, &reader)
        .map_err(|_| CliError::CredentialOperation)?;
    (access == remeasured && writer_identity_matches && reader_identity_matches)
        .then_some(access)
        .ok_or(CliError::CredentialOperation)
}

#[cfg(test)]
#[allow(dead_code)]
fn fixture_executable(path: &std::path::Path, name: &str) -> Result<std::path::PathBuf, CliError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| CliError::CredentialOperation)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || path.file_name() != Some(std::ffi::OsStr::new(&native_executable_name(name)))
    {
        return Err(CliError::CredentialOperation);
    }
    #[cfg(unix)]
    if std::os::unix::fs::MetadataExt::nlink(&metadata) != 1 {
        return Err(CliError::CredentialOperation);
    }
    #[cfg(windows)]
    if std::os::windows::fs::MetadataExt::file_attributes(&metadata) & 0x400 != 0
        || std::os::windows::fs::MetadataExt::number_of_links(&metadata) != Some(1)
    {
        return Err(CliError::CredentialOperation);
    }
    std::fs::canonicalize(path).map_err(|_| CliError::CredentialOperation)
}

#[cfg(test)]
#[allow(dead_code)]
fn fixture_file_identity(path: &std::path::Path) -> Result<FixtureFileIdentity, CliError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| CliError::CredentialOperation)?;
    Ok(FixtureFileIdentity {
        #[cfg(unix)]
        device: std::os::unix::fs::MetadataExt::dev(&metadata),
        #[cfg(unix)]
        inode: std::os::unix::fs::MetadataExt::ino(&metadata),
        #[cfg(windows)]
        volume_serial_number: std::os::windows::fs::MetadataExt::volume_serial_number(&metadata),
        #[cfg(windows)]
        file_index: std::os::windows::fs::MetadataExt::file_index(&metadata),
        #[cfg(not(any(unix, windows)))]
        length: metadata.len(),
    })
}

#[cfg(test)]
#[derive(PartialEq, Eq)]
struct FixtureFileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    volume_serial_number: Option<u32>,
    #[cfg(windows)]
    file_index: Option<u64>,
    #[cfg(not(any(unix, windows)))]
    length: u64,
}

#[cfg(test)]
#[allow(dead_code)]
fn native_executable_name(name: &str) -> String {
    format!("{name}{}", std::env::consts::EXE_SUFFIX)
}
