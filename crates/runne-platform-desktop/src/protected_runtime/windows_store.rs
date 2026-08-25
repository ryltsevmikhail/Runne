// Crash-safe activation records and staged executable storage on Windows.

#[cfg(windows)]
impl ActivationStateStore {
    fn open(runtime_root: &Path) -> Result<Self, ProtectedBundledRuntimeError> {
        let directory = runtime_root.join(ACTIVATION_STATE_DIRECTORY);
        match std::fs::symlink_metadata(&directory) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&directory)
                    .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
            }
            Err(_) => return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable),
        }
        validate_private_path(&directory)
            .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
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
        match std::fs::remove_file(self.directory.join(PENDING_RECORD_FILE)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(ProtectedBundledRuntimeError::ActivationStateUnavailable),
        }
    }

    fn stage_trusted_executable(
        &self,
        source_path: &Path,
        trusted_source: &ExecutableIdentityV1,
    ) -> Result<(PathBuf, ExecutableIdentityV1), ProtectedBundledRuntimeError> {
        let staging_directory = self.directory.join(STAGED_EXECUTABLE_DIRECTORY);
        if !staging_directory.exists() {
            std::fs::create_dir(&staging_directory)
                .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
        }
        validate_private_path(&staging_directory)
            .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
        validate_owner_private_directory(&staging_directory)
            .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
        let final_path = staging_directory.join(format!(
            "{}-{}.exe",
            hex::encode(trusted_source.executable_sha256()),
            trusted_source.byte_length()
        ));
        if final_path.exists() {
            validate_staged_executable(&final_path, trusted_source)?;
            return Ok((
                final_path.clone(),
                ExecutableIdentityV1::measure(&final_path)
                    .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?,
            ));
        }
        let temporary_path = staging_directory.join(format!(".{}.tmp", uuid::Uuid::now_v7()));
        let result = (|| {
            let mut source = File::open(source_path)
                .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
            validate_trusted_source_file(&source)?;
            if source
                .metadata()
                .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?
                .len()
                != trusted_source.byte_length()
            {
                return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch);
            }
            let mut staged = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary_path)
                .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
            let mut digest = Sha256::new();
            let mut length = 0_u64;
            let mut buffer = vec![0_u8; 64 * 1024];
            loop {
                let read = source
                    .read(&mut buffer)
                    .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
                if read == 0 { break; }
                digest.update(&buffer[..read]);
                length = length.checked_add(read as u64).ok_or(
                    ProtectedBundledRuntimeError::ExecutableIdentityMismatch,
                )?;
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
            drop(staged);
            match std::fs::rename(&temporary_path, &final_path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch),
            }
            validate_staged_executable(&final_path, trusted_source)?;
            Ok((
                final_path.clone(),
                ExecutableIdentityV1::measure(&final_path)
                    .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?,
            ))
        })();
        if temporary_path.exists() { let _ = std::fs::remove_file(temporary_path); }
        result
    }

    fn read_record<T>(&self, name: &str) -> Result<Option<T>, ProtectedBundledRuntimeError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let path = self.directory.join(name);
        if path.exists() {
            validate_private_path(&path)
                .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
        }
        let file = match File::open(path) {
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
        let mut bytes = Vec::with_capacity(
            usize::try_from(length)
                .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?,
        );
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
        let temporary = self.directory.join(format!(".{name}.{}.tmp", uuid::Uuid::now_v7()));
        let final_path = self.directory.join(name);
        let result = (|| {
            let mut file = OpenOptions::new().create_new(true).write(true).open(&temporary)
                .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
            file.write_all(&encoded).and_then(|()| file.sync_all())
                .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
            controls.checkpoint(after_file_sync)?;
            drop(file);
            match std::fs::rename(&temporary, &final_path) {
                Ok(()) => validate_private_path(&final_path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let existing = self.read_record::<T>(name)?.ok_or(
                        ProtectedBundledRuntimeError::ActivationStateUnavailable,
                    )?;
                    if &existing == expected { Ok(()) } else {
                        Err(ProtectedBundledRuntimeError::ActivationStateUnavailable)
                    }
                }
                Err(_) => Err(ProtectedBundledRuntimeError::ActivationStateUnavailable),
            }
        })();
        if temporary.exists() { let _ = std::fs::remove_file(temporary); }
        result
    }
}
