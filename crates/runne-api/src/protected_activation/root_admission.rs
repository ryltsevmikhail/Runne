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

/// Provenance-carrying admission created only from a verified protected result.
pub struct ProtectedRootHandleAdmission {
    admission: RootHandleAdmission,
    _offer_digest: [u8; 32],
    admission_digest: [u8; 32],
}

impl ProtectedRootHandleAdmission {
    pub(crate) fn from_verified_transfer(
        admission: RootHandleAdmission,
        offer_digest: [u8; 32],
        admission_digest: [u8; 32],
    ) -> Option<Self> {
        (admission.admission_digest() == admission_digest && admission.offer_digest() == offer_digest)
            .then_some(Self { admission, _offer_digest: offer_digest, admission_digest })
    }
    #[must_use]
    pub const fn admission_digest(&self) -> [u8; 32] { self.admission_digest }
    /// Consumes this verified wrapper into the only root-bind client carrier.
    pub fn into_root_bind_transport(self) -> Result<ProtectedRootBindTransport, RootHandleAdmissionTokenError> {
        ProtectedRootBindTransport::new(self.admission, self.admission_digest)
    }
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

include!("root_admission/claims.rs");
