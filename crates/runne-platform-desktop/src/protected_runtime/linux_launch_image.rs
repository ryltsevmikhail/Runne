fn open_launch_image(
    path: &Path,
    expected: &ExecutableIdentityV1,
) -> Result<File, ProtectedBundledRuntimeError> {
    let file = OpenOptions::new().read(true).custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path).map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
    let before = file.metadata().map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
    if !before.is_file() || before.len() != expected.byte_length() || before.nlink() != 1
        || before.uid() != rustix::process::geteuid().as_raw() || before.mode() & 0o022 != 0
    { return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch); }
    let mut reader = file.try_clone().map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer).map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
        if read == 0 { break; }
        digest.update(&buffer[..read]);
    }
    let after = file.metadata().map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
    if before.dev() != after.dev() || before.ino() != after.ino() || before.ctime() != after.ctime()
        || before.mtime() != after.mtime() || digest.finalize().as_slice() != expected.executable_sha256()
    { return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch); }
    Ok(file)
}
