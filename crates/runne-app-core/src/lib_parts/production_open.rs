const DESKTOP_SECURITY_PROFILE_ID_V1: &str = "runne-desktop-profile/v1";

impl AppCore {
    /// Opens the mutation-capable native desktop core with its OS secure anchor.
    ///
    /// # Errors
    ///
    /// Returns a closed error when the native secure store or anchored database
    /// cannot be admitted.
    pub fn open_production(path: &Path, runtime_mode: RuntimeMode) -> Result<Self, AppCoreError> {
        let profile = desktop_security_profile_digest();
        #[cfg(target_os = "macos")]
        let secure: Arc<dyn SecureStore> = Arc::new(
            runne_secure_store::MacOsKeychainStore::for_security_profile(
                DESKTOP_SECURITY_PROFILE_ID_V1,
                profile,
            ),
        );
        #[cfg(not(target_os = "macos"))]
        let secure: Arc<dyn SecureStore> = Arc::new(runne_secure_store::StubStore::new());
        Self::open_production_anchored(path, runtime_mode, secure, profile)
    }

    #[cfg(test)]
    fn open_production_with_secure(
        path: &Path,
        runtime_mode: RuntimeMode,
        secure: Arc<dyn SecureStore>,
    ) -> Result<Self, AppCoreError> {
        Self::open_production_anchored(path, runtime_mode, secure, desktop_security_profile_digest())
    }

    fn open_production_anchored(
        path: &Path,
        runtime_mode: RuntimeMode,
        secure: Arc<dyn SecureStore>,
        profile: [u8; 32],
    ) -> Result<Self, AppCoreError> {
        let store = LocalStore::open_anchored(path, secure.as_ref(), profile)
            .map_err(|_| AppCoreError::MutationUnavailable)?;
        let runtime_profile_path = match runtime_mode {
            RuntimeMode::ExternalLocal => Some(
                default_local_profile_path().map_err(|_| AppCoreError::RuntimeUnavailable)?,
            ),
            RuntimeMode::Bundled => None,
        };
        Ok(Self::open_store(
            store,
            runtime_mode,
            runtime_profile_path,
            Some(MutationSecurityContext { secure }),
        ))
    }
}

fn desktop_security_profile_digest() -> [u8; 32] {
    use sha2::Digest;

    let mut digest = sha2::Sha256::new();
    digest.update(b"runne/runne-app-core/desktop-security-profile/v1\0");
    digest.update(
        u64::try_from(DESKTOP_SECURITY_PROFILE_ID_V1.len())
            .expect("fixed desktop profile identity length")
            .to_be_bytes(),
    );
    digest.update(DESKTOP_SECURITY_PROFILE_ID_V1.as_bytes());
    digest.finalize().into()
}
