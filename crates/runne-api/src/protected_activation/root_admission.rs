use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use runne_domain::id::WorkspaceId;

/// Exact serialized size of an authenticated v3 root-admission envelope.
pub const ROOT_HANDLE_ADMISSION_V3_BYTES: usize = 289;
/// Maximum serialized size accepted before the HTTP host is called.
pub const MAX_ROOT_HANDLE_ADMISSION_BYTES: usize = ROOT_HANDLE_ADMISSION_V3_BYTES;
const ROOT_HANDLE_ADMISSION_TOKEN_PREFIX: &str = "gocode-root-admission-v3.";
/// Exact maximum byte length of the ASCII v3 root-admission transport token.
pub const MAX_ROOT_HANDLE_ADMISSION_TOKEN_BYTES: usize =
    ROOT_HANDLE_ADMISSION_TOKEN_PREFIX.len() + (MAX_ROOT_HANDLE_ADMISSION_BYTES * 4).div_ceil(3);

/// Stable failure for malformed opaque root-admission transport tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootHandleAdmissionTokenError { Invalid }
impl std::fmt::Display for RootHandleAdmissionTokenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { formatter.write_str("invalid root admission") }
}

/// Opaque admission for a transferred native directory handle.
pub struct RootHandleAdmission { bytes: Box<[u8]> }

/// Sealed daemon-issued admission, consumable only by the outbound control result.
pub struct IssuedRootHandleAdmission(RootHandleAdmission);

impl IssuedRootHandleAdmission {
    pub(crate) fn into_admission(self) -> RootHandleAdmission { self.0 }
    #[must_use]
    pub fn admission_digest(&self) -> [u8; 32] { self.0.admission_digest() }
}

/// Redacted failure for admission conversion without root-handle material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootHandleAdmissionValidationError { Invalid }
impl std::fmt::Display for RootHandleAdmissionValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { formatter.write_str("invalid root admission") }
}

/// Provenance-carrying admission created only from a verified protected result.
pub struct ProtectedRootHandleAdmission {
    admission: RootHandleAdmission,
    _offer_digest: [u8; 32],
    admission_digest: [u8; 32],
    workspace_id: WorkspaceId,
    expected_version: u64,
}

impl ProtectedRootHandleAdmission {
    pub(crate) fn from_verified_transfer(
        admission: RootHandleAdmission,
        claims: VerifiedRootAdmissionClaims,
        context: &RootHandleTransferContext,
        result_offer_digest: [u8; 32],
        expected_offer_digest: [u8; 32],
        result_admission_digest: [u8; 32],
    ) -> Result<Self, RootHandleAdmissionValidationError> {
        let valid = wrapper_equality_holds(
            &admission, &claims, context, result_offer_digest, expected_offer_digest, result_admission_digest,
        );
        if !valid { return Err(RootHandleAdmissionValidationError::Invalid); }
        Ok(Self {
            admission,
            _offer_digest: result_offer_digest,
            admission_digest: result_admission_digest,
            workspace_id: claims.workspace_id(),
            expected_version: claims.expected_version(),
        })
    }
    #[must_use]
    pub const fn workspace_id(&self) -> WorkspaceId { self.workspace_id }
    #[must_use]
    pub const fn expected_version(&self) -> u64 { self.expected_version }
    #[must_use]
    pub const fn admission_digest(&self) -> [u8; 32] { self.admission_digest }
    /// Consumes this verified wrapper into the only root-bind client carrier.
    pub fn into_root_bind_transport(self) -> Result<ProtectedRootBindTransport, RootHandleAdmissionTokenError> {
        ProtectedRootBindTransport::new(self.admission, self.admission_digest)
    }
}

/// Single central typed/digest equality gate evaluated before any wrapper allocation.
fn wrapper_equality_holds(
    admission: &RootHandleAdmission,
    claims: &VerifiedRootAdmissionClaims,
    context: &RootHandleTransferContext,
    result_offer_digest: [u8; 32],
    expected_offer_digest: [u8; 32],
    result_admission_digest: [u8; 32],
) -> bool {
    claims.workspace_id() == context.workspace_id()
        && claims.expected_version() == context.expected_version()
        && result_offer_digest == expected_offer_digest
        && claims.offer_digest() == result_offer_digest
        && admission.offer_digest() == result_offer_digest
        && claims.admission_digest() == result_admission_digest
        && admission.admission_digest() == result_admission_digest
}

impl RootHandleAdmission {
    pub(crate) fn from_verified_bytes(bytes: Vec<u8>) -> Option<Self> {
        (bytes.len() == ROOT_HANDLE_ADMISSION_V3_BYTES).then_some(Self { bytes: bytes.into_boxed_slice() })
    }
    fn from_transport_token(token: &str) -> Result<Self, RootHandleAdmissionTokenError> {
        if !token.is_ascii() || token.len() > MAX_ROOT_HANDLE_ADMISSION_TOKEN_BYTES { return Err(RootHandleAdmissionTokenError::Invalid); }
        let encoded = token.strip_prefix(ROOT_HANDLE_ADMISSION_TOKEN_PREFIX).ok_or(RootHandleAdmissionTokenError::Invalid)?;
        let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| RootHandleAdmissionTokenError::Invalid)?;
        Self::from_verified_bytes(bytes).ok_or(RootHandleAdmissionTokenError::Invalid)
    }
    fn into_transport_token(self) -> Result<String, RootHandleAdmissionTokenError> {
        let token = format!("{ROOT_HANDLE_ADMISSION_TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(&self.bytes));
        (token.len() <= MAX_ROOT_HANDLE_ADMISSION_TOKEN_BYTES).then_some(token).ok_or(RootHandleAdmissionTokenError::Invalid)
    }
    #[must_use]
    pub fn admission_digest(&self) -> [u8; 32] {
        self.bytes[225..257].try_into().expect("fixed v3 envelope")
    }
    pub(crate) fn offer_digest(&self) -> [u8; 32] {
        self.bytes[169..201].try_into().expect("fixed v3 envelope")
    }
}

impl std::fmt::Debug for RootHandleAdmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { formatter.write_str("RootHandleAdmission([REDACTED])") }
}
impl std::fmt::Debug for IssuedRootHandleAdmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { formatter.write_str("IssuedRootHandleAdmission([REDACTED])") }
}
impl std::fmt::Debug for ProtectedRootHandleAdmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { formatter.write_str("ProtectedRootHandleAdmission([REDACTED])") }
}

#[cfg(test)]
mod root_admission_wrapper_tests {
    use super::*;

    fn verified_transfer_material() -> (
        RootHandleAdmission, VerifiedRootAdmissionClaims, RootHandleTransferContext, [u8; 32],
    ) {
        let context = RootHandleTransferContext::new(
            [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1],
            [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 2],
            1, 10, 11, 1_000,
            WorkspaceId::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 3]),
            1, [4; 16], 100, 30_100,
        ).expect("transfer context");
        let transfer_keys = RootHandleTransferAuthenticator::from_protected_activation(
            &LaunchSecret::from_bytes([7; 32]).expect("secret").derive_keys(),
        );
        let offer = RootHandleTransferOffer::new(context.clone(), 1, &transfer_keys).expect("offer");
        let admission_authenticator = RootAdmissionAuthenticator::from_protected_activation(
            &LaunchSecret::from_bytes([8; 32]).expect("secret").derive_keys(),
        );
        let raw = admission_authenticator.issue(RootAdmissionRequest::new(
            RootAdmissionVerificationContext::new([1; 32], [2; 16], 1, [3; 32], 3, 1, 100).expect("admission context"),
            context.workspace_id(), 1, [4; 32], offer.digest(), [5; 16], 30_100,
        ).expect("request")).expect("raw admission");
        let admission = raw.into_admission();
        let claims = admission_authenticator.verify_ref(&admission).expect("verified claims");
        (admission, claims, context, offer.digest())
    }

    #[test]
    fn protected_admission_rejects_wrong_admission_digest_before_allocation() {
        let (admission, claims, context, offer_digest) = verified_transfer_material();
        let mut wrong = admission.admission_digest();
        wrong[0] ^= 1;
        let error = ProtectedRootHandleAdmission::from_verified_transfer(
            admission, claims, &context, offer_digest, offer_digest, wrong,
        ).expect_err("wrong admission digest must not yield a wrapper");
        assert_eq!(error.to_string(), "invalid root admission");
        assert_eq!(format!("{error:?}"), "Invalid");
    }

    #[test]
    fn protected_admission_rejects_internal_claims_against_transfer_context() {
        let (admission, claims, _context, offer_digest) = verified_transfer_material();
        let admission_digest = claims.admission_digest();
        let foreign = RootHandleTransferContext::new(
            [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1],
            [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 2],
            1, 10, 11, 1_000,
            WorkspaceId::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 4]),
            1, [4; 16], 100, 30_100,
        ).expect("transfer context");
        let error = ProtectedRootHandleAdmission::from_verified_transfer(
            admission, claims, &foreign, offer_digest, offer_digest, admission_digest,
        ).expect_err("foreign transfer context must not yield a wrapper");
        assert_eq!(format!("{error:?}"), "Invalid");
    }

    #[test]
    fn protected_admission_carries_typed_metadata_after_all_equality_checks() {
        let (admission, claims, context, offer_digest) = verified_transfer_material();
        let admission_digest = claims.admission_digest();
        let wrapper = ProtectedRootHandleAdmission::from_verified_transfer(
            admission, claims, &context, offer_digest, offer_digest, admission_digest,
        ).expect("consistent transfer material");
        assert_eq!(wrapper.workspace_id(), context.workspace_id());
        assert_eq!(wrapper.expected_version(), context.expected_version());
        assert_eq!(wrapper.admission_digest(), admission_digest);
    }
}

include!("root_admission/claims.rs");
