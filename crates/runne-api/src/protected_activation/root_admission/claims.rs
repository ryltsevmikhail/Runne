/// Closed current security bindings required to verify a root admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootAdmissionVerificationContext {
    authority_digest: [u8; 32],
    session_id: [u8; 16],
    launch_generation: u64,
    principal_digest: [u8; 32],
    capability_version: u64,
    policy_version: u64,
    now_unix_millis: u64,
}
impl RootAdmissionVerificationContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authority_digest: [u8; 32],
        session_id: [u8; 16],
        launch_generation: u64,
        principal_digest: [u8; 32],
        capability_version: u64,
        policy_version: u64,
        now_unix_millis: u64,
    ) -> Result<Self, RootAdmissionValidationError> {
        if is_zero(&authority_digest)
            || is_zero(&session_id)
            || launch_generation == 0
            || is_zero(&principal_digest)
            || capability_version != 3
            || policy_version == 0
            || now_unix_millis == 0
        {
            return Err(RootAdmissionValidationError::ZeroBinding);
        }
        Ok(Self {
            authority_digest,
            session_id,
            launch_generation,
            principal_digest,
            capability_version,
            policy_version,
            now_unix_millis,
        })
    }
    pub fn authority_digest(&self) -> [u8; 32] {
        self.authority_digest
    }
    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }
    pub fn launch_generation(&self) -> u64 {
        self.launch_generation
    }
    pub fn principal_digest(&self) -> [u8; 32] {
        self.principal_digest
    }
    pub fn capability_version(&self) -> u64 {
        self.capability_version
    }
    pub fn policy_version(&self) -> u64 {
        self.policy_version
    }
    pub fn now_unix_millis(&self) -> u64 {
        self.now_unix_millis
    }
    /// Domain-separated digest for the authenticated API principal.
    pub fn principal_digest_for(principal: &str) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"gocode-root-admission-principal\x01");
        digest.update((principal.len() as u64).to_be_bytes());
        digest.update(principal.as_bytes());
        digest.finalize().into()
    }
    /// Domain-separated digest for the runtime authority identity.
    pub fn authority_digest_for(authority: &str) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"gocode-root-admission-authority\x01");
        digest.update((authority.len() as u64).to_be_bytes());
        digest.update(authority.as_bytes());
        digest.finalize().into()
    }
}
/// Fixed action authorized by a root admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootAdmissionAction {
    WorkspaceBindRoot,
}
/// Verified, non-serializable and non-cloneable root-admission claims.
pub struct VerifiedRootAdmissionClaims {
    context: RootAdmissionVerificationContext,
    action: RootAdmissionAction,
    workspace_id: WorkspaceId,
    expected_version: u64,
    filesystem_identity_digest: [u8; 32],
    offer_digest: [u8; 32],
    nonce: [u8; 16],
    expires_at_unix_millis: u64,
    admission_digest: [u8; 32],
}
impl VerifiedRootAdmissionClaims {
    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        context: RootAdmissionVerificationContext,
        action: RootAdmissionAction,
        workspace_id: WorkspaceId,
        expected_version: u64,
        filesystem_identity_digest: [u8; 32],
        offer_digest: [u8; 32],
        nonce: [u8; 16],
        expires_at_unix_millis: u64,
        admission_digest: [u8; 32],
    ) -> Result<Self, RootAdmissionValidationError> {
        if expected_version == 0
            || is_zero(&filesystem_identity_digest)
            || is_zero(&offer_digest)
            || is_zero(&nonce)
            || expires_at_unix_millis == 0
            || is_zero(&admission_digest)
        {
            return Err(RootAdmissionValidationError::ZeroBinding);
        }
        Ok(Self {
            context,
            action,
            workspace_id,
            expected_version,
            filesystem_identity_digest,
            offer_digest,
            nonce,
            expires_at_unix_millis,
            admission_digest,
        })
    }
    pub fn context(&self) -> &RootAdmissionVerificationContext {
        &self.context
    }
    pub fn action(&self) -> RootAdmissionAction {
        self.action
    }
    pub fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }
    pub fn expected_version(&self) -> u64 {
        self.expected_version
    }
    pub fn filesystem_identity_digest(&self) -> [u8; 32] {
        self.filesystem_identity_digest
    }
    pub fn offer_digest(&self) -> [u8; 32] { self.offer_digest }
    pub fn nonce(&self) -> [u8; 16] {
        self.nonce
    }
    pub fn expires_at_unix_millis(&self) -> u64 {
        self.expires_at_unix_millis
    }
    pub fn admission_digest(&self) -> [u8; 32] {
        self.admission_digest
    }
}
/// Stable validation failure without root-handle material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootAdmissionValidationError {
    ZeroBinding,
}
fn is_zero(value: &[u8]) -> bool {
    value.iter().all(|byte| *byte == 0)
}
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support {
    use super::*;
    /// Downgrades a sealed issuer result for verifier-bound integration tests.
    pub fn into_untrusted_admission(admission: IssuedRootHandleAdmission) -> RootHandleAdmission {
        admission.into_admission()
    }
    pub fn admission() -> RootHandleAdmission {
        RootHandleAdmission::from_verified_bytes(vec![1; ROOT_HANDLE_ADMISSION_V3_BYTES])
            .expect("fixed test admission")
    }
    /// Extracts signed claims of an untrusted admission for verifier-bound tests.
    pub fn verify_untrusted(
        authenticator: &RootAdmissionAuthenticator,
        admission: &RootHandleAdmission,
    ) -> VerifiedRootAdmissionClaims {
        authenticator
            .verify_ref(admission)
            .expect("signed test admission")
    }
    #[allow(clippy::too_many_arguments)]
    pub fn claims(
        context: RootAdmissionVerificationContext,
        workspace_id: WorkspaceId,
        expected_version: u64,
        nonce: [u8; 16],
        expiry: u64,
        digest: [u8; 32],
    ) -> VerifiedRootAdmissionClaims {
        VerifiedRootAdmissionClaims::new(
            context,
            RootAdmissionAction::WorkspaceBindRoot,
            workspace_id,
            expected_version,
            [9; 32],
            [10; 32],
            nonce,
            expiry,
            digest,
        )
        .expect("valid fixed test claims")
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn root_admission_context_rejects_zero_security_bindings() {
        let result = RootAdmissionVerificationContext::new([0; 32], [1; 16], 1, [2; 32], 1, 1, 1);
        assert!(matches!(
            result,
            Err(RootAdmissionValidationError::ZeroBinding)
        ));
    }
    #[test]
    fn root_admission_context_rejects_v2_capability() {
        assert!(RootAdmissionVerificationContext::new([1; 32], [2; 16], 1, [3; 32], 2, 1, 1).is_err());
    }
    #[test]
    fn root_admission_debug_never_exposes_opaque_material() {
        let admission =
            RootHandleAdmission::from_verified_bytes(vec![0x5a; ROOT_HANDLE_ADMISSION_V3_BYTES])
                .unwrap();
        assert_eq!(format!("{admission:?}"), "RootHandleAdmission([REDACTED])");
    }
    #[test]
    fn root_admission_v3_transport_rejects_v2_and_oversized_tokens() {
        assert!(RootHandleAdmission::from_transport_token("gocode-root-admission-v2.AA").is_err());
        assert!(RootHandleAdmission::from_transport_token(&"a".repeat(MAX_ROOT_HANDLE_ADMISSION_TOKEN_BYTES + 1)).is_err());
    }
    #[test]
    fn verified_claims_reject_zero_nonce_and_digest() {
        let context =
            RootAdmissionVerificationContext::new([1; 32], [2; 16], 1, [3; 32], 3, 1, 1).unwrap();
        let result = VerifiedRootAdmissionClaims::new(
            context,
            RootAdmissionAction::WorkspaceBindRoot,
            WorkspaceId::from_bytes([4; 16]),
            1,
            [5; 32],
            [6; 32],
            [0; 16],
            2,
            [0; 32],
        );
        assert!(matches!(
            result,
            Err(RootAdmissionValidationError::ZeroBinding)
        ));
    }
}
