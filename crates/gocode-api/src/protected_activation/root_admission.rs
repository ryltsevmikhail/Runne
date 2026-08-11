use gocode_domain::id::WorkspaceId;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

/// Maximum serialized size accepted for a verified root admission claim.
pub const MAX_ROOT_HANDLE_ADMISSION_BYTES: usize = 4096;
const ROOT_HANDLE_ADMISSION_TOKEN_PREFIX: &str = "gocode-root-admission-v2.";
/// Exact maximum byte length of the ASCII v2 root-admission transport token.
pub const MAX_ROOT_HANDLE_ADMISSION_TOKEN_BYTES: usize =
    ROOT_HANDLE_ADMISSION_TOKEN_PREFIX.len() + (MAX_ROOT_HANDLE_ADMISSION_BYTES * 4).div_ceil(3);

/// Stable failure for malformed opaque root-admission transport tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootHandleAdmissionTokenError { Invalid }

/// Opaque admission for a transferred native directory handle.
pub struct RootHandleAdmission {
    bytes: Box<[u8]>,
}

impl RootHandleAdmission {
    /// Encodes the opaque authenticated claim in the fixed ASCII v2 transport form.
    pub fn encode_token(&self) -> Result<String, RootHandleAdmissionTokenError> {
        let encoded = URL_SAFE_NO_PAD.encode(&self.bytes);
        let token = format!("{ROOT_HANDLE_ADMISSION_TOKEN_PREFIX}{encoded}");
        (token.len() <= MAX_ROOT_HANDLE_ADMISSION_TOKEN_BYTES)
            .then_some(token)
            .ok_or(RootHandleAdmissionTokenError::Invalid)
    }

    /// Decodes a bounded opaque v2 token without authenticating its contents.
    ///
    /// Authentication is deliberately performed only by the protected verifier.
    pub fn decode_token(token: &str) -> Result<Self, RootHandleAdmissionTokenError> {
        if !token.is_ascii() || token.len() > MAX_ROOT_HANDLE_ADMISSION_TOKEN_BYTES {
            return Err(RootHandleAdmissionTokenError::Invalid);
        }
        let encoded = token
            .strip_prefix(ROOT_HANDLE_ADMISSION_TOKEN_PREFIX)
            .ok_or(RootHandleAdmissionTokenError::Invalid)?;
        if encoded.is_empty() {
            return Err(RootHandleAdmissionTokenError::Invalid);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| RootHandleAdmissionTokenError::Invalid)?;
        Self::from_verified_bytes(bytes).ok_or(RootHandleAdmissionTokenError::Invalid)
    }

    #[allow(dead_code)]
    pub(crate) fn from_verified_bytes(bytes: Vec<u8>) -> Option<Self> {
        if bytes.is_empty() || bytes.len() > MAX_ROOT_HANDLE_ADMISSION_BYTES {
            return None;
        }
        Some(Self { bytes: bytes.into_boxed_slice() })
    }
}

impl std::fmt::Debug for RootHandleAdmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let _ = self.bytes.len();
        formatter.write_str("RootHandleAdmission([REDACTED])")
    }
}

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
        authority_digest: [u8; 32], session_id: [u8; 16], launch_generation: u64,
        principal_digest: [u8; 32], capability_version: u64, policy_version: u64,
        now_unix_millis: u64,
    ) -> Result<Self, RootAdmissionValidationError> {
        if is_zero(&authority_digest) || is_zero(&session_id) || launch_generation == 0
            || is_zero(&principal_digest) || capability_version == 0 || policy_version == 0
            || now_unix_millis == 0 {
            return Err(RootAdmissionValidationError::ZeroBinding);
        }
        Ok(Self { authority_digest, session_id, launch_generation, principal_digest,
            capability_version, policy_version, now_unix_millis })
    }

    pub fn authority_digest(&self) -> [u8; 32] { self.authority_digest }
    pub fn session_id(&self) -> [u8; 16] { self.session_id }
    pub fn launch_generation(&self) -> u64 { self.launch_generation }
    pub fn principal_digest(&self) -> [u8; 32] { self.principal_digest }
    pub fn capability_version(&self) -> u64 { self.capability_version }
    pub fn policy_version(&self) -> u64 { self.policy_version }
    pub fn now_unix_millis(&self) -> u64 { self.now_unix_millis }

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
pub enum RootAdmissionAction { WorkspaceBindRoot }

/// Verified, non-serializable and non-cloneable root-admission claims.
pub struct VerifiedRootAdmissionClaims {
    context: RootAdmissionVerificationContext,
    action: RootAdmissionAction,
    workspace_id: WorkspaceId,
    expected_version: u64,
    filesystem_identity_digest: [u8; 32],
    nonce: [u8; 16],
    expires_at_unix_millis: u64,
    admission_digest: [u8; 32],
}

impl VerifiedRootAdmissionClaims {
    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        context: RootAdmissionVerificationContext, action: RootAdmissionAction,
        workspace_id: WorkspaceId, expected_version: u64, filesystem_identity_digest: [u8; 32],
        nonce: [u8; 16], expires_at_unix_millis: u64, admission_digest: [u8; 32],
    ) -> Result<Self, RootAdmissionValidationError> {
        if expected_version == 0 || is_zero(&filesystem_identity_digest) || is_zero(&nonce)
            || expires_at_unix_millis == 0 || is_zero(&admission_digest) {
            return Err(RootAdmissionValidationError::ZeroBinding);
        }
        Ok(Self { context, action, workspace_id, expected_version, filesystem_identity_digest,
            nonce, expires_at_unix_millis, admission_digest })
    }

    pub fn context(&self) -> &RootAdmissionVerificationContext { &self.context }
    pub fn action(&self) -> RootAdmissionAction { self.action }
    pub fn workspace_id(&self) -> WorkspaceId { self.workspace_id }
    pub fn expected_version(&self) -> u64 { self.expected_version }
    pub fn filesystem_identity_digest(&self) -> [u8; 32] { self.filesystem_identity_digest }
    pub fn nonce(&self) -> [u8; 16] { self.nonce }
    pub fn expires_at_unix_millis(&self) -> u64 { self.expires_at_unix_millis }
    pub fn admission_digest(&self) -> [u8; 32] { self.admission_digest }
}

/// Stable validation failure without root-handle material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootAdmissionValidationError { ZeroBinding }

fn is_zero(value: &[u8]) -> bool { value.iter().all(|byte| *byte == 0) }

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support {
    use super::*;

    pub fn admission() -> RootHandleAdmission {
        RootHandleAdmission::from_verified_bytes(vec![1]).expect("fixed test admission")
    }

    #[allow(clippy::too_many_arguments)]
    pub fn claims(
        context: RootAdmissionVerificationContext, workspace_id: WorkspaceId,
        expected_version: u64, nonce: [u8; 16], expiry: u64, digest: [u8; 32],
    ) -> VerifiedRootAdmissionClaims {
        VerifiedRootAdmissionClaims::new(context, RootAdmissionAction::WorkspaceBindRoot,
            workspace_id, expected_version, [9; 32], nonce, expiry, digest)
            .expect("valid fixed test claims")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_admission_context_rejects_zero_security_bindings() {
        let result = RootAdmissionVerificationContext::new(
            [0; 32], [1; 16], 1, [2; 32], 1, 1, 1,
        );
        assert!(matches!(result, Err(RootAdmissionValidationError::ZeroBinding)));
    }

    #[test]
    fn root_admission_debug_never_exposes_opaque_material() {
        let admission = RootHandleAdmission::from_verified_bytes(vec![0x5a]).unwrap();
        assert_eq!(format!("{admission:?}"), "RootHandleAdmission([REDACTED])");
    }

    #[test]
    fn root_admission_v2_codec_is_bounded_ascii_and_round_trips() {
        let admission = RootHandleAdmission::from_verified_bytes(vec![0x5a; 32]).unwrap();
        let token = admission.encode_token().unwrap();
        assert!(token.is_ascii());
        assert!(token.starts_with("gocode-root-admission-v2."));
        assert_eq!(
            RootHandleAdmission::decode_token(&token)
                .unwrap()
                .encode_token()
                .unwrap(),
            token
        );
        assert!(RootHandleAdmission::decode_token("gocode-root-admission-v2.\u{80}").is_err());
        assert!(RootHandleAdmission::decode_token(&"a".repeat(MAX_ROOT_HANDLE_ADMISSION_BYTES * 2)).is_err());
    }

    #[test]
    fn verified_claims_reject_zero_nonce_and_digest() {
        let context = RootAdmissionVerificationContext::new(
            [1; 32], [2; 16], 1, [3; 32], 1, 1, 1,
        ).unwrap();
        let result = VerifiedRootAdmissionClaims::new(
            context, RootAdmissionAction::WorkspaceBindRoot,
            WorkspaceId::from_bytes([4; 16]), 1, [5; 32], [0; 16], 2, [0; 32],
        );
        assert!(matches!(result, Err(RootAdmissionValidationError::ZeroBinding)));
    }
}
