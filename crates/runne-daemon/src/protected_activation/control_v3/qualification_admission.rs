//! Platform-neutral carrier for the one qualified writer admission bundle.
//!
//! The bundle holds the DPK-signed qualification context/fault members exactly
//! as relayed through the protected activation flow; it adds no authority of
//! its own. Extracted from the macOS `control_v3` qualification fence so the
//! Linux desktop-protected broker channel consumes the SAME signed admission
//! material without compiling the macOS control exchange.

/// One qualified admission bundle: signed member bytes plus their digests.
pub(crate) struct WriterAdmissionBundle {
    /// Exact signed members encoding (context then fault ticket).
    bytes: Vec<u8>,
    /// SHA-256 of the signed qualification context member.
    context_sha256: [u8; 32],
    /// SHA-256 of the signed qualification fault ticket member.
    ticket_sha256: [u8; 32],
}

impl WriterAdmissionBundle {
    /// Sole construction shape: digests must describe `bytes`' signed members.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(super) const fn from_signed_members(
        _permit: crate::application::provider_credential_enrollment::PostcommitAdmissionPermit,
        bytes: Vec<u8>,
        context_sha256: [u8; 32],
        ticket_sha256: [u8; 32],
    ) -> Self {
        Self {
            bytes,
            context_sha256,
            ticket_sha256,
        }
    }

    pub(crate) fn into_qualified_signing_material(self) -> ([u8; 32], [u8; 32], Vec<u8>) {
        (self.context_sha256, self.ticket_sha256, self.bytes)
    }
}
