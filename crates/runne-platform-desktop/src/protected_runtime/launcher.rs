
#[cfg(unix)]
impl ActivationStateStore {
    fn open(runtime_root: &Path) -> Result<Self, ProtectedBundledRuntimeError> {
        let directory = runtime_root.join(ACTIVATION_STATE_DIRECTORY);
        match std::fs::symlink_metadata(&directory) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&directory)
                    .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
                std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
                    .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
            }
            Err(_) => return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable),
        }
        validate_owner_private_directory(&directory)?;
        Ok(Self { directory })
    }

    fn load_stable(&self) -> Result<Option<StableRuntimeBindingV1>, ProtectedBundledRuntimeError> {
        self.read_record::<StoredStableV1>(STABLE_RECORD_FILE)?
            .map(StoredStableV1::into_contract)
            .transpose()
    }

    fn load_pending(
        &self,
    ) -> Result<Option<PendingFirstActivationV1>, ProtectedBundledRuntimeError> {
        self.read_record::<StoredPendingV1>(PENDING_RECORD_FILE)?
            .map(StoredPendingV1::into_contract)
            .transpose()
    }

    fn persist_stable_exact(
        &self,
        stable: &StableRuntimeBindingV1,
        controls: &mut LaunchTestControls,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        self.persist_record_exact(
            STABLE_RECORD_FILE,
            &StoredStableV1::from_contract(stable),
            ActivationCheckpoint::AfterFinalPinFileSync,
            controls,
        )
    }

    fn persist_pending_exact(
        &self,
        pending: &PendingFirstActivationV1,
        controls: &mut LaunchTestControls,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        self.persist_record_exact(
            PENDING_RECORD_FILE,
            &StoredPendingV1::from_contract(pending),
            ActivationCheckpoint::AfterPrepareFileSync,
            controls,
        )
    }

    fn remove_pending(&self) -> Result<(), ProtectedBundledRuntimeError> {
        let path = self.directory.join(PENDING_RECORD_FILE);
        match std::fs::remove_file(path) {
            Ok(()) => sync_directory(&self.directory),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(ProtectedBundledRuntimeError::ActivationStateUnavailable),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn stage_trusted_executable(
        &self,
        source_path: &Path,
        trusted_source: &ExecutableIdentityV1,
    ) -> Result<(PathBuf, ExecutableIdentityV1), ProtectedBundledRuntimeError> {
        let staging_directory = self.directory.join(STAGED_EXECUTABLE_DIRECTORY);
        match std::fs::symlink_metadata(&staging_directory) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&staging_directory)
                    .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
                std::fs::set_permissions(
                    &staging_directory,
                    std::fs::Permissions::from_mode(0o700),
                )
                .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
            }
            Err(_) => return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch),
        }
        validate_owner_private_directory(&staging_directory)
            .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;

        let final_name = format!(
            "{}-{}.runned",
            hex::encode(trusted_source.executable_sha256()),
            trusted_source.byte_length()
        );
        let final_path = staging_directory.join(final_name);
        if final_path.exists() {
            validate_staged_executable(&final_path, trusted_source)?;
            let identity = ExecutableIdentityV1::measure(&final_path)
                .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
            return Ok((final_path, identity));
        }

        let temporary_path = staging_directory.join(format!(".{}.tmp", uuid::Uuid::now_v7()));
        let result = (|| {
            let mut source = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(source_path)
                .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
            validate_trusted_source_file(&source)?;
            let source_metadata = source
                .metadata()
                .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
            if source_metadata.len() != trusted_source.byte_length() {
                return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch);
            }

            let mut staged = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&temporary_path)
                .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
            let mut digest = Sha256::new();
            let mut length = 0_u64;
            let mut buffer = vec![0_u8; 64 * 1024];
            loop {
                let read = source
                    .read(&mut buffer)
                    .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
                if read == 0 {
                    break;
                }
                digest.update(&buffer[..read]);
                length =
                    length
                        .checked_add(u64::try_from(read).map_err(|_| {
                            ProtectedBundledRuntimeError::ExecutableIdentityMismatch
                        })?)
                        .ok_or(ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
                staged
                    .write_all(&buffer[..read])
                    .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
            }
            let measured_digest: [u8; 32] = digest.finalize().into();
            if length != trusted_source.byte_length()
                || &measured_digest != trusted_source.executable_sha256()
            {
                return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch);
            }
            staged
                .sync_all()
                .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
            std::fs::set_permissions(&temporary_path, std::fs::Permissions::from_mode(0o500))
                .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
            drop(staged);
            match std::fs::hard_link(&temporary_path, &final_path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch),
            }
            std::fs::remove_file(&temporary_path)
                .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
            sync_directory(&staging_directory)
                .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
            validate_staged_executable(&final_path, trusted_source)?;
            let identity = ExecutableIdentityV1::measure(&final_path)
                .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
            Ok((final_path.clone(), identity))
        })();
        if temporary_path.exists() {
            let _ = std::fs::remove_file(&temporary_path);
        }
        result
    }

    fn read_record<T>(&self, name: &str) -> Result<Option<T>, ProtectedBundledRuntimeError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let path = self.directory.join(name);
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable),
        };
        validate_owner_private_file(&file)?;
        let length = file
            .metadata()
            .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?
            .len();
        if length == 0 || length > MAX_STATE_BYTES {
            return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
        }
        let capacity = usize::try_from(length)
            .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
        let mut bytes = Vec::with_capacity(capacity);
        file.take(MAX_STATE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
        if bytes.len() as u64 != length {
            return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
        }
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)
    }

    fn persist_record_exact<T>(
        &self,
        name: &str,
        expected: &T,
        after_file_sync: ActivationCheckpoint,
        controls: &mut LaunchTestControls,
    ) -> Result<(), ProtectedBundledRuntimeError>
    where
        T: for<'de> Deserialize<'de> + Eq + Serialize,
    {
        if let Some(existing) = self.read_record::<T>(name)? {
            return if &existing == expected {
                Ok(())
            } else {
                Err(ProtectedBundledRuntimeError::ActivationStateUnavailable)
            };
        }

        let encoded = serde_json::to_vec(expected)
            .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
        if encoded.is_empty() || encoded.len() as u64 > MAX_STATE_BYTES {
            return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
        }
        let temporary_name = format!(".{name}.{}.tmp", uuid::Uuid::now_v7());
        let temporary_path = self.directory.join(temporary_name);
        let final_path = self.directory.join(name);
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&temporary_path)
                .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
            file.write_all(&encoded)
                .and_then(|()| file.sync_all())
                .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
            controls.checkpoint(after_file_sync)?;
            drop(file);
            match std::fs::hard_link(&temporary_path, &final_path) {
                Ok(()) => {
                    std::fs::remove_file(&temporary_path)
                        .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
                    sync_directory(&self.directory)
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    std::fs::remove_file(&temporary_path)
                        .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
                    let existing = self
                        .read_record::<T>(name)?
                        .ok_or(ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
                    if &existing == expected {
                        Ok(())
                    } else {
                        Err(ProtectedBundledRuntimeError::ActivationStateUnavailable)
                    }
                }
                Err(_) => Err(ProtectedBundledRuntimeError::ActivationStateUnavailable),
            }
        })();
        if temporary_path.exists() {
            let _ = std::fs::remove_file(&temporary_path);
        }
        result
    }
}
