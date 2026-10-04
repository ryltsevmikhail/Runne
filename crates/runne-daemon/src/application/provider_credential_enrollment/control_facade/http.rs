#[cfg(all(
    feature = "desktop-protected",
    any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"))
))]
use std::sync::Arc;

use rand::{RngCore as _, rngs::OsRng};
use runne_api::ProviderCredentialEnrollmentHostError;
#[cfg(all(
    feature = "desktop-protected",
    any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"))
))]
use runne_api::ProviderCredentialProviderV2;
#[cfg(all(
    feature = "desktop-protected",
    any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"))
))]
use runne_api::{
    ProviderCredentialBaseRequestAuthority, ProviderCredentialOperationHandleV2,
    ProviderCredentialOperationSnapshotV2, ProviderCredentialRequestAuthorityVerifier,
    ProviderCredentialSafeSnapshotV2,
};

#[cfg(any(
    any(test, unix),
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
use super::DaemonProviderCredentialEnrollmentControl;
#[cfg(any(
    all(test, unix),
    all(feature = "desktop-protected", target_os = "linux"),
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
use super::ProtectedEnrollmentSessionFacts;

pub(super) fn generate_handle_key() -> Result<[u8; 32], ProviderCredentialEnrollmentHostError> {
    let mut key = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut key)
        .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
    if key == [0; 32] {
        return Err(ProviderCredentialEnrollmentHostError::Unavailable);
    }
    Ok(key)
}

#[cfg(any(
    any(test, unix),
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
impl DaemonProviderCredentialEnrollmentControl {
    #[cfg(all(
        target_os = "macos",
        target_arch = "aarch64",
        feature = "desktop-protected"
    ))]
    pub(crate) fn publish_verified_v2_status(
        &self,
        owned: &runne_api::ProtectedOwnedLaunchV2,
        installation: [u8; 32],
        release: [u8; 32],
        peer: [u8; 32],
        supervisor: u64,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        self.publish_http_facts(ProtectedEnrollmentSessionFacts::from_verified_v2_status(
            owned,
            installation,
            release,
            peer,
            supervisor,
            self.runtime_authority,
            self.database_generation,
        )?)
    }

    #[cfg(all(
        feature = "desktop-protected",
        any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"))
    ))]
    pub(crate) fn http_enrollment_router(
        self: &Arc<Self>,
        now_high_water: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> axum::Router {
        let host = super::super::DaemonProviderCredentialEnrollmentHttpHost::new(
            Arc::clone(self),
            self.http_authority_verifier.clone(),
            now_high_water,
        );
        let resolver =
            super::super::http_admission_resolver::LiveCredentialHttpAdmissionResolver::new(
                self.http_authority_issuer.clone(),
                Arc::clone(&self.http_facts),
            );
        runne_http::provider_credential_enrollment_router(
            runne_http::ProviderCredentialEnrollmentHttpState::with_admission_resolver(
                host, resolver,
            ),
        )
    }

    #[cfg(any(
        all(test, unix),
        all(feature = "desktop-protected", target_os = "linux"),
        all(
            feature = "desktop-protected",
            target_os = "macos",
            target_arch = "aarch64"
        )
    ))]
    pub(crate) fn publish_http_facts(
        &self,
        facts: ProtectedEnrollmentSessionFacts,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        let (session, installation, release, binding, supervisor, peer, database, daemon) =
            facts.http_authority_parts();
        if session == [0; 16]
            || installation == [0; 32]
            || release == [0; 32]
            || binding == [0; 32]
            || supervisor == 0
            || peer == [0; 32]
            || database == 0
            || daemon == [0; 32]
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        *self
            .http_facts
            .lock()
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)? = Some(facts);
        Ok(())
    }

    pub(crate) fn clear_http_facts(&self, session: [u8; 16]) {
        if let Ok(mut current) = self.http_facts.lock()
            && current
                .as_ref()
                .is_some_and(|facts| facts.http_authority_parts().0 == session)
        {
            *current = None;
        }
    }

    #[cfg(all(test, unix))]
    pub(crate) fn poison_http_facts_for_test(&self) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if let Ok(_guard) = self.http_facts.lock() {
                panic!("poison enrollment facts lock for rollback regression");
            }
        }));
    }

    #[cfg(all(
        test,
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    ))]
    pub(crate) fn test_status_is_unavailable(&self, session: [u8; 16]) -> bool {
        use runne_http::ProviderCredentialEnrollmentHttpAdmissionResolver as _;

        matches!(
            super::super::http_admission_resolver::LiveCredentialHttpAdmissionResolver::new(
                self.http_authority_issuer.clone(),
                Arc::clone(&self.http_facts),
            )
            .resolve_status(session, &ProviderCredentialProviderV2::DeepSeek),
            Err(ProviderCredentialEnrollmentHostError::Unavailable)
        )
    }

    #[cfg(all(
        feature = "desktop-protected",
        any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"))
    ))]
    pub(crate) fn status_http(
        &self,
        verifier: &ProviderCredentialRequestAuthorityVerifier,
        authority: &ProviderCredentialBaseRequestAuthority,
        provider: ProviderCredentialProviderV2,
        now_high_water: i64,
    ) -> Result<ProviderCredentialSafeSnapshotV2, ProviderCredentialEnrollmentHostError> {
        let current = self
            .http_facts
            .lock()
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        require_current_http_authority(current.as_ref(), authority)?;
        #[cfg(target_os = "linux")]
        let session = current
            .as_ref()
            .ok_or(ProviderCredentialEnrollmentHostError::Unavailable)?
            .http_authority_parts()
            .0;
        #[cfg(target_os = "linux")]
        self.linux_preadmission_for(session, self.runtime_authority)?
            .enforce(provider)?;
        let snapshot = super::super::ProviderCredentialEnrollmentStatus::new(
            super::super::ProviderCredentialAdmission::new(
                verifier.clone(),
                self.measurements.clone(),
            ),
            self.store.as_ref(),
            self.readback.as_ref(),
        )
        .load(authority, provider, now_high_water)?;
        drop(current);
        Ok(snapshot)
    }

    #[cfg(all(
        feature = "desktop-protected",
        any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"))
    ))]
    pub(crate) fn resume_http(
        &self,
        verifier: &ProviderCredentialRequestAuthorityVerifier,
        authority: &ProviderCredentialBaseRequestAuthority,
        handle: ProviderCredentialOperationHandleV2,
        now_high_water: i64,
    ) -> Result<ProviderCredentialOperationSnapshotV2, ProviderCredentialEnrollmentHostError> {
        let current = self
            .http_facts
            .lock()
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        require_current_http_authority(current.as_ref(), authority)?;
        #[cfg(target_os = "linux")]
        {
            let session = current
                .as_ref()
                .ok_or(ProviderCredentialEnrollmentHostError::Unavailable)?
                .http_authority_parts()
                .0;
            let resume = super::super::resume::ProviderCredentialEnrollmentResume::new(
                super::super::ProviderCredentialAdmission::new(
                    verifier.clone(),
                    self.measurements.clone(),
                ),
                self.handles.duplicate(),
                self.store.as_ref(),
                self.readback.as_ref(),
                self.rendezvous.clone(),
            );
            let provider = resume.provider_for_http(authority, handle)?;
            self.linux_preadmission_for(session, self.runtime_authority)?
                .enforce(provider)?;
        }
        let snapshot = super::super::resume::ProviderCredentialEnrollmentResume::new(
            super::super::ProviderCredentialAdmission::new(
                verifier.clone(),
                self.measurements.clone(),
            ),
            self.handles.duplicate(),
            self.store.as_ref(),
            self.readback.as_ref(),
            self.rendezvous.clone(),
        )
        .load(authority, handle, now_high_water)?;
        drop(current);
        Ok(snapshot)
    }
}

#[cfg(all(
    feature = "desktop-protected",
    any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"))
))]
fn require_current_http_authority(
    facts: Option<&ProtectedEnrollmentSessionFacts>,
    authority: &ProviderCredentialBaseRequestAuthority,
) -> Result<(), ProviderCredentialEnrollmentHostError> {
    let facts = facts.ok_or(ProviderCredentialEnrollmentHostError::Unavailable)?;
    let (_, installation, release, session, supervisor, peer, database, daemon) =
        facts.http_authority_parts();
    if authority.installation_identity() != &installation
        || authority.release_tuple_digest() != &release
        || authority.protected_session_id() != &session
        || authority.desktop_supervisor_generation() != supervisor
        || authority.daemon_authority_id() != &daemon
        || authority.database_generation() != database
        || authority.authenticated_tauri_peer_process() != &peer
    {
        return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
    }
    Ok(())
}
