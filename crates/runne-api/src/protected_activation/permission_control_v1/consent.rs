#[derive(Clone, PartialEq, Eq)]
pub enum ModeOsAttestationV1 {
    NotRequired,
    Fresh {
        qualified_fingerprint: [u8; 32],
        authenticated_at_unix_ms: u64,
    },
}

/// Claims and fixed attestation slots are opaque transport content until a native verifier runs.
#[derive(Clone, PartialEq, Eq)]
pub struct PermissionControlModeConsentV1 {
    pub challenge_id: [u8; 16],
    pub public_request_digest: [u8; 32],
    pub issued_challenge_binding_digest: [u8; 32],
    pub native_warning_version: u16,
    pub requested_mode: super::PermissionModeSelectionV1,
    pub confirmed_binding_digest: [u8; 32],
    pub warning_attestation: [u8; 32],
    pub os_attestation: ModeOsAttestationV1,
}

/// Managed consent carries one composite native proof under its own key purpose.
/// A later platform-native owner may issue it only after consuming private
/// warning confirmation and fresh OS authentication; the fingerprint and time
/// fields alone are transport claims and do not prove PAM authentication.
#[derive(Clone, PartialEq, Eq)]
pub struct PermissionControlManagedConsentV1 {
    pub challenge_id: [u8; 16],
    pub public_request_digest: [u8; 32],
    pub issued_challenge_binding_digest: [u8; 32],
    pub native_warning_version: u16,
    pub confirmed_binding_digest: [u8; 32],
    pub warning_attestation: [u8; 32],
    pub qualified_fingerprint: [u8; 32],
    pub authenticated_at_unix_ms: u64,
}
