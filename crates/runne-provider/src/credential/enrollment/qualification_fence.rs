use super::{CredentialBindingDigest, CredentialEnrollmentError, CredentialOperationId};

/// Validated non-authorizing metadata for one durable qualification replay fence.
pub struct ProviderQualificationAdmissionFence {
    operation_id: CredentialOperationId,
    context_id: [u8; 32],
    context_nonce: [u8; 32],
    ticket_id: [u8; 32],
    ticket_nonce: [u8; 32],
    ticket_sha256: [u8; 32],
    scenario: &'static str,
    selector: &'static str,
    process_role: &'static str,
    candidate_sha256: [u8; 32],
    raw_v3_tuple_sha256: [u8; 32],
    source_revision: [u8; 20],
    workflow_run_id: String,
    namespace_sha256: [u8; 32],
    context_issued_at: i64,
    context_expires_at: i64,
    ticket_issued_at: i64,
    ticket_expires_at: i64,
    protected_session_digest: CredentialBindingDigest,
    runtime_authority_id: [u8; 16],
    database_generation: u64,
    launch_generation: u64,
    supervisor_generation: u64,
    verified_at: i64,
}

#[allow(missing_docs)]
impl ProviderQualificationAdmissionFence {
    /// Validates fixed-width identities, canonical role mapping and freshness ordering.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation_id: CredentialOperationId,
        context_id: [u8; 32],
        context_nonce: [u8; 32],
        ticket_id: [u8; 32],
        ticket_nonce: [u8; 32],
        ticket_sha256: [u8; 32],
        scenario: &str,
        selector: &str,
        process_role: &str,
        candidate_sha256: [u8; 32],
        raw_v3_tuple_sha256: [u8; 32],
        source_revision: [u8; 20],
        workflow_run_id: &str,
        namespace_sha256: [u8; 32],
        context_issued_at: i64,
        context_expires_at: i64,
        ticket_issued_at: i64,
        ticket_expires_at: i64,
        protected_session_digest: CredentialBindingDigest,
        runtime_authority_id: [u8; 16],
        database_generation: u64,
        launch_generation: u64,
        supervisor_generation: u64,
        verified_at: i64,
    ) -> Result<Self, CredentialEnrollmentError> {
        let (scenario, selector, process_role) = canonical_role(scenario, selector, process_role)?;
        let nonzero = context_id != [0; 32]
            && context_nonce != [0; 32]
            && ticket_id != [0; 32]
            && ticket_nonce != [0; 32]
            && ticket_sha256 != [0; 32]
            && candidate_sha256 != [0; 32]
            && raw_v3_tuple_sha256 != [0; 32]
            && source_revision != [0; 20]
            && namespace_sha256 != [0; 32];
        let workflow = !workflow_run_id.is_empty()
            && workflow_run_id.len() <= 128
            && workflow_run_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'));
        let time = context_issued_at >= 0
            && ticket_issued_at >= 0
            && context_expires_at > context_issued_at
            && ticket_expires_at > ticket_issued_at
            && context_expires_at - context_issued_at <= 900
            && ticket_expires_at - ticket_issued_at <= 900
            && context_expires_at <= ticket_expires_at
            && verified_at >= context_issued_at
            && verified_at >= ticket_issued_at
            && verified_at < context_expires_at
            && verified_at < ticket_expires_at;
        let generations = database_generation > 0
            && launch_generation > 0
            && supervisor_generation > 0
            && database_generation <= i64::MAX as u64
            && launch_generation <= i64::MAX as u64
            && supervisor_generation <= i64::MAX as u64;
        if !nonzero || runtime_authority_id == [0; 16] || !workflow || !time || !generations {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self {
            operation_id,
            context_id,
            context_nonce,
            ticket_id,
            ticket_nonce,
            ticket_sha256,
            scenario,
            selector,
            process_role,
            candidate_sha256,
            raw_v3_tuple_sha256,
            source_revision,
            workflow_run_id: workflow_run_id.to_owned(),
            namespace_sha256,
            context_issued_at,
            context_expires_at,
            ticket_issued_at,
            ticket_expires_at,
            protected_session_digest,
            runtime_authority_id,
            database_generation,
            launch_generation,
            supervisor_generation,
            verified_at,
        })
    }

    pub const fn operation_id(&self) -> CredentialOperationId {
        self.operation_id
    }
    pub const fn context_id(&self) -> [u8; 32] {
        self.context_id
    }
    pub const fn context_nonce(&self) -> [u8; 32] {
        self.context_nonce
    }
    pub const fn ticket_id(&self) -> [u8; 32] {
        self.ticket_id
    }
    pub const fn ticket_nonce(&self) -> [u8; 32] {
        self.ticket_nonce
    }
    pub const fn ticket_sha256(&self) -> [u8; 32] {
        self.ticket_sha256
    }
    pub const fn scenario(&self) -> &'static str {
        self.scenario
    }
    pub const fn selector(&self) -> &'static str {
        self.selector
    }
    pub const fn process_role(&self) -> &'static str {
        self.process_role
    }
    pub const fn candidate_sha256(&self) -> [u8; 32] {
        self.candidate_sha256
    }
    pub const fn raw_v3_tuple_sha256(&self) -> [u8; 32] {
        self.raw_v3_tuple_sha256
    }
    pub const fn source_revision(&self) -> [u8; 20] {
        self.source_revision
    }
    pub fn workflow_run_id(&self) -> &str {
        &self.workflow_run_id
    }
    pub const fn namespace_sha256(&self) -> [u8; 32] {
        self.namespace_sha256
    }
    pub const fn context_issued_at(&self) -> i64 {
        self.context_issued_at
    }
    pub const fn context_expires_at(&self) -> i64 {
        self.context_expires_at
    }
    pub const fn ticket_issued_at(&self) -> i64 {
        self.ticket_issued_at
    }
    pub const fn ticket_expires_at(&self) -> i64 {
        self.ticket_expires_at
    }
    pub const fn protected_session_digest(&self) -> CredentialBindingDigest {
        self.protected_session_digest
    }
    pub const fn runtime_authority_id(&self) -> [u8; 16] {
        self.runtime_authority_id
    }
    pub const fn database_generation(&self) -> u64 {
        self.database_generation
    }
    pub const fn launch_generation(&self) -> u64 {
        self.launch_generation
    }
    pub const fn supervisor_generation(&self) -> u64 {
        self.supervisor_generation
    }
    pub const fn verified_at(&self) -> i64 {
        self.verified_at
    }
    pub const fn effective_expires_at(&self) -> i64 {
        if self.context_expires_at < self.ticket_expires_at {
            self.context_expires_at
        } else {
            self.ticket_expires_at
        }
    }
}

fn canonical_role(
    scenario: &str,
    selector: &str,
    role: &str,
) -> Result<(&'static str, &'static str, &'static str), CredentialEnrollmentError> {
    if scenario != "macos-xpc-dpk-v1" {
        return Err(CredentialEnrollmentError::InvalidInput);
    }
    const DESKTOP: &[&str] = &["kill_desktop_process"];
    const WRITER: &[&str] = &["kill_writer_process"];
    const RUNTIME: &[&str] = &[
        "kill_before_lifecycle_cas",
        "kill_after_lifecycle_cas",
        "kill_runtime_process",
    ];
    const SERVICE: &[&str] = &[
        "kill_before_service_consume",
        "kill_after_service_consume",
        "kill_before_native_effect",
        "kill_after_native_effect",
        "kill_before_readback",
        "kill_after_readback",
        "kill_before_reply",
        "kill_after_reply",
        "kill_service_launchd_restart",
        "kill_registration_ack_loss",
    ];
    let expected = if DESKTOP.contains(&selector) {
        "desktop"
    } else if WRITER.contains(&selector) {
        "writer"
    } else if RUNTIME.contains(&selector) {
        "runtime"
    } else if SERVICE.contains(&selector) {
        "service"
    } else {
        return Err(CredentialEnrollmentError::InvalidInput);
    };
    if role != expected {
        return Err(CredentialEnrollmentError::InvalidInput);
    }
    let canonical_selector = DESKTOP
        .iter()
        .chain(WRITER)
        .chain(RUNTIME)
        .chain(SERVICE)
        .copied()
        .find(|value| *value == selector)
        .ok_or(CredentialEnrollmentError::InvalidInput)?;
    Ok(("macos-xpc-dpk-v1", canonical_selector, expected))
}
