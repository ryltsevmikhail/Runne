//! Live code-signing and identity verification of one retained writer.

use std::num::NonZeroU32;
use std::str::FromStr as _;

use runne_platform_ports::provider_credential_broker::BrokerHandoffError;
use security_framework::os::macos::code_signing::{
    Flags, GuestAttributes, SecCode, SecRequirement,
};

use super::{
    RetainedMacOsWriterImage, RetainedWriterProcess, UnixRetainedWriterProcess,
    WriterProcessEvidence,
};
use crate::VerifiedMacOsWriterLaunch;
use crate::provider_credential_broker::handoff_trace::{step, step_failed};

pub fn verify_live_writer(
    process: &UnixRetainedWriterProcess,
    launch: &VerifiedMacOsWriterLaunch,
    image: &RetainedMacOsWriterImage,
    channel_binding: [u8; 32],
    publication_public_key: [u8; 32],
    writer_kill_public_key: [u8; 32],
) -> Result<WriterProcessEvidence, BrokerHandoffError> {
    if channel_binding == [0; 32] || publication_public_key == [0; 32] {
        return Err(BrokerHandoffError::Rejected);
    }
    step("admit-start-identity");
    let start = process
        .writer_start_identity()
        .inspect_err(|_| step_failed("admit-start-identity"))?;
    let pid = process.pid();
    let mut attributes = GuestAttributes::new();
    attributes.set_pid(pid);
    step("admit-guest");
    let code = SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE)
        .inspect_err(|_| step_failed("admit-guest"))
        .map_err(|_| BrokerHandoffError::Rejected)?;
    step("admit-requirement");
    let requirement = SecRequirement::from_str(&launch.code_requirement())
        .inspect_err(|_| step_failed("admit-requirement"))
        .map_err(|_| BrokerHandoffError::Rejected)?;
    let flags = Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS;
    step("admit-validity");
    code.check_validity(flags, &requirement)
        .inspect_err(|_| step_failed("admit-validity"))
        .map_err(|_| BrokerHandoffError::Rejected)?;
    step("admit-live-path");
    let live_path = code
        .path(Flags::NONE)
        .ok()
        .and_then(|value| value.to_path())
        .ok_or(BrokerHandoffError::Rejected)?;
    let live_path = std::fs::canonicalize(live_path)
        .inspect_err(|_| step_failed("admit-live-path"))
        .map_err(|_| BrokerHandoffError::Rejected)?;
    let pid = NonZeroU32::new(pid.cast_unsigned()).ok_or(BrokerHandoffError::Rejected)?;
    step("admit-observe");
    let executable =
        runne_macos_process_identity::MacOsProcessExecutableIdentity::observe(pid, &live_path)
            .inspect_err(|_| step_failed("admit-observe"))
            .map_err(|_| BrokerHandoffError::Rejected)?;
    step("admit-compare");
    if live_path != image.path || !executable.matches_file(&image.metadata) {
        step_failed("admit-compare-path");
        return Err(BrokerHandoffError::Rejected);
    }
    step("admit-redigest");
    if !image.matches_current_path_and_digest()? {
        step_failed("admit-redigest");
        return Err(BrokerHandoffError::Rejected);
    }
    step("admit-re-identity");
    if process
        .writer_start_identity()
        .inspect_err(|_| step_failed("admit-re-identity"))?
        != start
    {
        step_failed("admit-compare-re-identity");
        return Err(BrokerHandoffError::Rejected);
    }
    WriterProcessEvidence::from_verified_macos_writer(
        start,
        image.digest,
        launch.launch().artifact().release_tuple_digest(),
        channel_binding,
        publication_public_key,
        writer_kill_public_key,
    )
}
