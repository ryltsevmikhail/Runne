#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the qualified protected HTTP composition remains deliberately unmounted"
    )
)]

use std::sync::Arc;
#[cfg(any(
    any(test, unix),
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
use std::sync::Mutex;

#[cfg(any(
    any(test, unix),
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
use runne_api::{
    ApiActor, ApiPrincipalId, ProviderCredentialCommandContext,
    ProviderCredentialRequestAuthorityIssuer,
};
use runne_api::{
    BeginProviderCredentialEnrollment, ProviderCredentialEnrollmentHostError,
    ProviderCredentialOperationHandleV2, ProviderCredentialProviderV2, VerifyProviderCredential,
};
#[cfg(any(
    any(test, unix),
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
use runne_domain::id::{CommandId, IdempotencyKey};
use runne_http::{
    ProviderCredentialEnrollmentHttpAdmission, ProviderCredentialEnrollmentHttpAdmissionResolver,
};

use super::control_exchange::RegisteredCredentialHttpAdmissionExchange;
#[cfg(any(
    any(test, unix),
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
use super::control_facade::ProtectedEnrollmentSessionFacts;

#[cfg(any(
    any(test, unix),
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
pub(super) type LiveCredentialHttpFacts = Arc<Mutex<Option<ProtectedEnrollmentSessionFacts>>>;

#[cfg(any(
    any(test, unix),
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
pub(super) fn live_credential_http_facts() -> LiveCredentialHttpFacts {
    Arc::new(Mutex::new(None))
}

/// Status and resume admission derived only from verified, current live facts.
#[cfg(any(
    any(test, unix),
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
pub(super) struct LiveCredentialHttpAdmissionResolver {
    issuer: ProviderCredentialRequestAuthorityIssuer,
    facts: LiveCredentialHttpFacts,
}

#[cfg(any(
    any(test, unix),
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
impl LiveCredentialHttpAdmissionResolver {
    pub(super) const fn new(
        issuer: ProviderCredentialRequestAuthorityIssuer,
        facts: LiveCredentialHttpFacts,
    ) -> Self {
        Self { issuer, facts }
    }

    fn resolve_base(
        &self,
        protected_session_id: [u8; 16],
    ) -> Result<Arc<ProviderCredentialEnrollmentHttpAdmission>, ProviderCredentialEnrollmentHostError>
    {
        let facts = self
            .facts
            .lock()
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?
            .clone()
            .ok_or(ProviderCredentialEnrollmentHostError::Unavailable)?;
        let (session, installation, release, session_binding, supervisor, peer, database, daemon) =
            facts.http_authority_parts();
        if session != protected_session_id {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let authority = self.issuer.issue_base(
            installation,
            release,
            session_binding,
            supervisor,
            daemon,
            database,
            peer,
        )?;
        Ok(ProviderCredentialEnrollmentHttpAdmission::base(
            authority,
            read_only_context()?,
        ))
    }
}

#[cfg(any(
    any(test, unix),
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
fn read_only_context()
-> Result<ProviderCredentialCommandContext, ProviderCredentialEnrollmentHostError> {
    Ok(ProviderCredentialCommandContext {
        command_id: CommandId::from_bytes(*uuid::Uuid::now_v7().as_bytes()),
        idempotency_key: IdempotencyKey::new(uuid::Uuid::now_v7().to_string())
            .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?,
        principal: ApiPrincipalId::new("protected-desktop-owner")
            .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?,
        actor: ApiActor::new("runne-daemon-http")
            .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?,
    })
}

/// Daemon-owned bridge from one registered control exchange to HTTP handlers.
pub(super) struct DaemonCredentialHttpAdmissionResolver {
    exchange: RegisteredCredentialHttpAdmissionExchange,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl DaemonCredentialHttpAdmissionResolver {
    pub(super) fn new(
        exchange: RegisteredCredentialHttpAdmissionExchange,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        Self { exchange, clock }
    }
}

impl ProviderCredentialEnrollmentHttpAdmissionResolver for DaemonCredentialHttpAdmissionResolver {
    fn resolve_begin(
        &self,
        protected_session_id: [u8; 16],
        command: &BeginProviderCredentialEnrollment,
    ) -> Result<Arc<ProviderCredentialEnrollmentHttpAdmission>, ProviderCredentialEnrollmentHostError>
    {
        let (authority, proof, context) =
            self.exchange
                .resolve_begin(protected_session_id, command, (self.clock)())?;
        Ok(ProviderCredentialEnrollmentHttpAdmission::mutation(
            authority, proof, context,
        ))
    }

    fn resolve_verify(
        &self,
        protected_session_id: [u8; 16],
        command: &VerifyProviderCredential,
    ) -> Result<Arc<ProviderCredentialEnrollmentHttpAdmission>, ProviderCredentialEnrollmentHostError>
    {
        let (authority, proof, context) =
            self.exchange
                .resolve_verify(protected_session_id, command, (self.clock)())?;
        Ok(ProviderCredentialEnrollmentHttpAdmission::mutation(
            authority, proof, context,
        ))
    }

    fn resolve_status(
        &self,
        _: [u8; 16],
        _: &ProviderCredentialProviderV2,
    ) -> Result<Arc<ProviderCredentialEnrollmentHttpAdmission>, ProviderCredentialEnrollmentHostError>
    {
        Err(ProviderCredentialEnrollmentHostError::Unsupported)
    }

    fn resolve_resume(
        &self,
        _: [u8; 16],
        _: ProviderCredentialOperationHandleV2,
    ) -> Result<Arc<ProviderCredentialEnrollmentHttpAdmission>, ProviderCredentialEnrollmentHostError>
    {
        Err(ProviderCredentialEnrollmentHostError::Unsupported)
    }
}

#[cfg(any(
    any(test, unix),
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
impl ProviderCredentialEnrollmentHttpAdmissionResolver for LiveCredentialHttpAdmissionResolver {
    fn resolve_begin(
        &self,
        _: [u8; 16],
        _: &BeginProviderCredentialEnrollment,
    ) -> Result<Arc<ProviderCredentialEnrollmentHttpAdmission>, ProviderCredentialEnrollmentHostError>
    {
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    }

    fn resolve_verify(
        &self,
        _: [u8; 16],
        _: &VerifyProviderCredential,
    ) -> Result<Arc<ProviderCredentialEnrollmentHttpAdmission>, ProviderCredentialEnrollmentHostError>
    {
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    }

    fn resolve_status(
        &self,
        protected_session_id: [u8; 16],
        _: &ProviderCredentialProviderV2,
    ) -> Result<Arc<ProviderCredentialEnrollmentHttpAdmission>, ProviderCredentialEnrollmentHostError>
    {
        self.resolve_base(protected_session_id)
    }

    fn resolve_resume(
        &self,
        protected_session_id: [u8; 16],
        _: ProviderCredentialOperationHandleV2,
    ) -> Result<Arc<ProviderCredentialEnrollmentHttpAdmission>, ProviderCredentialEnrollmentHostError>
    {
        self.resolve_base(protected_session_id)
    }
}
