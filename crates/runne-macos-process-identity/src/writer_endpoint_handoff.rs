//! Bounded ingress for a deliberately untrusted native writer handoff.

mod ingress;
mod raw_recvmsg_macos;

use std::os::fd::OwnedFd;
use std::time::Duration;

use sha2::{Digest as _, Sha256};

const HANDOFF_DOMAIN: &[u8] = b"GOCODE_WRITER_ENDPOINT_HANDOFF_V1\0";
const PRODUCTION_DEADLINE: Duration = Duration::from_secs(1);

/// An untrusted macOS writer-endpoint handoff that grants no authority.
///
/// It is deliberately move-only, opaque, and not a descriptor escape hatch.
///
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<runne_macos_process_identity::MacOsUntrustedWriterEndpointHandoffV1>();
/// ```
///
/// ```compile_fail
/// fn require_copy<T: Copy>() {}
/// require_copy::<runne_macos_process_identity::MacOsUntrustedWriterEndpointHandoffV1>();
/// ```
///
/// ```compile_fail
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<runne_macos_process_identity::MacOsUntrustedWriterEndpointHandoffV1>();
/// ```
///
/// ```compile_fail
/// fn require_default<T: Default>() {}
/// require_default::<runne_macos_process_identity::MacOsUntrustedWriterEndpointHandoffV1>();
/// ```
///
/// ```compile_fail
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<runne_macos_process_identity::MacOsUntrustedWriterEndpointHandoffV1>();
/// ```
///
/// ```compile_fail
/// fn require_deserialize<T: for<'de> serde::Deserialize<'de>>() {}
/// require_deserialize::<runne_macos_process_identity::MacOsUntrustedWriterEndpointHandoffV1>();
/// ```
///
/// ```compile_fail
/// fn require_as_fd<T: std::os::fd::AsFd>() {}
/// require_as_fd::<runne_macos_process_identity::MacOsUntrustedWriterEndpointHandoffV1>();
/// ```
///
/// ```compile_fail
/// fn require_as_raw_fd<T: std::os::fd::AsRawFd>() {}
/// require_as_raw_fd::<runne_macos_process_identity::MacOsUntrustedWriterEndpointHandoffV1>();
/// ```
///
/// ```compile_fail
/// fn require_into_raw_fd<T: std::os::fd::IntoRawFd>() {}
/// require_into_raw_fd::<runne_macos_process_identity::MacOsUntrustedWriterEndpointHandoffV1>();
/// ```
///
/// ```compile_fail
/// let _ = runne_macos_process_identity::MacOsUntrustedWriterEndpointHandoffV1 {};
/// ```
///
/// ```compile_fail
/// let value = runne_macos_process_identity::MacOsUntrustedWriterEndpointHandoffV1::from_parts();
/// ```
///
/// ```compile_fail
/// fn raw_getters(value: &runne_macos_process_identity::MacOsUntrustedWriterEndpointHandoffV1) {
///     let _ = value.frame();
///     let _ = value.control();
///     let _ = value.channel_binding();
///     let _ = value.publication_public_key();
///     let _ = value.handoff_digest();
/// }
/// ```
///
/// ```compile_fail
/// fn mint(value: runne_macos_process_identity::MacOsUntrustedWriterEndpointHandoffV1) {
///     let _ = value.into_authority();
/// }
/// ```
#[doc(hidden)]
pub struct MacOsUntrustedWriterEndpointHandoffV1 {
    #[allow(dead_code)]
    control: OwnedFd,
    #[allow(dead_code)]
    frame: [u8; ingress::FRAME_BYTES],
    #[allow(dead_code)]
    channel_binding: [u8; 32],
    #[allow(dead_code)]
    publication_public_key: [u8; 32],
    #[allow(dead_code)]
    handoff_digest: [u8; 32],
}

impl MacOsUntrustedWriterEndpointHandoffV1 {
    pub(super) const fn observation_control(&self) -> &OwnedFd {
        &self.control
    }

    /// Receives one fixed untrusted handoff from this process's stdin.
    ///
    /// # Errors
    ///
    /// Fails closed unless stdin is a connected macOS Unix stream carrying one
    /// exact, bounded record and exactly one close-on-exec descriptor.
    #[doc(hidden)]
    pub fn receive_from_stdin() -> std::io::Result<Self> {
        let stdin = std::io::stdin();
        Self::receive(&stdin, PRODUCTION_DEADLINE)
    }

    fn receive(transport: &impl std::os::fd::AsFd, budget: Duration) -> std::io::Result<Self> {
        let received = ingress::receive(transport, budget)?;
        let channel_binding = received.frame[..32]
            .try_into()
            .map_err(std::io::Error::other)?;
        let publication_public_key = received.frame[96..128]
            .try_into()
            .map_err(std::io::Error::other)?;
        let mut digest = Sha256::new();
        digest.update(HANDOFF_DOMAIN);
        digest.update(received.frame);
        Ok(Self {
            control: received.control,
            frame: received.frame,
            channel_binding,
            publication_public_key,
            handoff_digest: digest.finalize().into(),
        })
    }

    #[cfg(test)]
    pub(crate) const fn test_only_frame(&self) -> &[u8; ingress::FRAME_BYTES] {
        &self.frame
    }

    #[cfg(test)]
    pub(crate) const fn test_only_channel_binding(&self) -> &[u8; 32] {
        &self.channel_binding
    }

    #[cfg(test)]
    pub(crate) const fn test_only_publication_public_key(&self) -> &[u8; 32] {
        &self.publication_public_key
    }

    #[cfg(test)]
    pub(crate) const fn test_only_digest(&self) -> &[u8; 32] {
        &self.handoff_digest
    }

    #[cfg(test)]
    pub(crate) fn test_only_has_cloexec(&self) -> bool {
        use nix::fcntl::{FcntlArg, FdFlag, fcntl};

        fcntl(&self.control, FcntlArg::F_GETFD)
            .is_ok_and(|flags| FdFlag::from_bits_retain(flags).contains(FdFlag::FD_CLOEXEC))
    }
}

#[cfg(test)]
pub fn receive_for_test(
    transport: &impl std::os::fd::AsFd,
    budget: Duration,
) -> std::io::Result<MacOsUntrustedWriterEndpointHandoffV1> {
    MacOsUntrustedWriterEndpointHandoffV1::receive(transport, budget)
}

#[cfg(test)]
pub fn test_only_receive_raw_segment(
    transport: &impl std::os::fd::AsFd,
    budget: Duration,
) -> std::io::Result<()> {
    ingress::test_receive_raw_segment(transport, budget)
}

#[cfg(test)]
pub fn test_only_receive_with_tiny_control(transport: &impl std::os::fd::AsFd) {
    ingress::test_receive_with_tiny_control(transport);
}

#[cfg(test)]
pub const fn test_only_control_buffer_covers_xnu_ceiling() -> bool {
    raw_recvmsg_macos::test_control_buffer_covers_xnu_ceiling()
}

#[cfg(test)]
pub fn test_only_parse_unknown_then_rights(descriptor: OwnedFd) -> std::io::Result<()> {
    raw_recvmsg_macos::test_parse_unknown_then_rights(descriptor)
}

#[cfg(test)]
pub fn test_only_parse_rights_then_malformed(descriptor: OwnedFd) -> std::io::Result<()> {
    raw_recvmsg_macos::test_parse_rights_then_malformed(descriptor)
}

#[cfg(test)]
pub fn test_only_parse_negative_then_rights(descriptor: OwnedFd) -> std::io::Result<()> {
    raw_recvmsg_macos::test_parse_negative_then_rights(descriptor)
}

#[cfg(test)]
pub fn test_only_parse_duplicate_rights(descriptor: OwnedFd) -> std::io::Result<()> {
    raw_recvmsg_macos::test_parse_duplicate_rights(descriptor)
}

#[cfg(test)]
pub fn test_only_parse_partial_rights(descriptor: OwnedFd) -> std::io::Result<()> {
    raw_recvmsg_macos::test_parse_partial_rights(descriptor)
}

#[cfg(test)]
pub fn test_only_parse_rights_then_trailing(descriptor: OwnedFd) -> std::io::Result<()> {
    raw_recvmsg_macos::test_parse_rights_then_trailing(descriptor)
}

#[cfg(test)]
pub fn test_only_send_with_descriptors(
    transport: &impl std::os::fd::AsFd,
    bytes: &[u8],
    descriptors: &[std::os::fd::BorrowedFd<'_>],
) -> std::io::Result<usize> {
    raw_recvmsg_macos::test_send_with_descriptors(transport.as_fd(), bytes, descriptors)
}
