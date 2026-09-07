use runne_provider::{
    CredentialWriterSessionAttestationCodec, CredentialWriterSessionAttestationV2Codec,
    PendingCredentialIssueTicketV1,
};

use super::{
    BootstrapAttestation, BootstrapPrefix, BootstrapPrefixVersion,
    MacOsPendingWriterBootstrapTranscriptV1, PrefixBudget,
};
use crate::packaged_writer_observation::{CapturedPackagedWriterObservationV1, map_peer_error};
use crate::writer_bootstrap_transcript::deadline::DeadlineReader;
use crate::{
    MacOsLocalPeerProcessIdentity, MacOsPackagedWriterObservationError,
    MacOsUntrustedWriterEndpointHandoffV1,
};

pub(super) fn observe_any(
    handoff: MacOsUntrustedWriterEndpointHandoffV1,
    budget: &PrefixBudget,
) -> Result<MacOsPendingWriterBootstrapTranscriptV1, MacOsPackagedWriterObservationError> {
    let expected_public_key = *handoff.observation_publication_public_key();
    let peer = MacOsLocalPeerProcessIdentity::capture(handoff.observation_control())
        .map_err(map_peer_error)?;
    let prefix = {
        let mut reader = DeadlineReader::new(handoff.observation_control(), budget.duration())
            .map_err(|_| MacOsPackagedWriterObservationError::Rejected)?;
        let prefix = read_versioned_prefix(&mut reader, expected_public_key)?;
        reader
            .reject_queued_input()
            .map_err(|_| MacOsPackagedWriterObservationError::Rejected)?;
        prefix
    };
    let observation =
        CapturedPackagedWriterObservationV1::capture_with_retained_peer(&handoff, peer)?;
    let (attestation, issue_ticket, release) = match prefix {
        BootstrapPrefixVersion::V1(prefix) => (
            BootstrapAttestation::V1(prefix.attestation),
            prefix.issue_ticket,
            prefix.release,
        ),
        BootstrapPrefixVersion::Qualified {
            attestation,
            issue_ticket,
            release,
        } => (
            BootstrapAttestation::Qualified(attestation),
            issue_ticket,
            release,
        ),
    };
    Ok(MacOsPendingWriterBootstrapTranscriptV1 {
        handoff,
        attestation,
        issue_ticket,
        release,
        observation,
    })
}

fn read_versioned_prefix<R: std::io::Read>(
    reader: &mut R,
    expected_public_key: [u8; 32],
) -> Result<BootstrapPrefixVersion, MacOsPackagedWriterObservationError> {
    let mut version = [0; 1];
    reader
        .read_exact(&mut version)
        .map_err(|_| MacOsPackagedWriterObservationError::Rejected)?;
    match version[0] {
        1 => {
            let mut bytes = [0; CredentialWriterSessionAttestationCodec::BYTES];
            bytes[0] = version[0];
            reader
                .read_exact(&mut bytes[1..])
                .map_err(|_| MacOsPackagedWriterObservationError::Rejected)?;
            Ok(BootstrapPrefixVersion::V1(BootstrapPrefix {
                attestation: CredentialWriterSessionAttestationCodec::decode_and_verify(
                    &bytes,
                    expected_public_key,
                )
                .map_err(|_| MacOsPackagedWriterObservationError::Rejected)?,
                issue_ticket: PendingCredentialIssueTicketV1::read_from(reader)
                    .map_err(|_| MacOsPackagedWriterObservationError::Rejected)?,
                release: runne_api::PendingSignedInstalledReleaseMetadataV2::read_from(reader)
                    .map_err(|_| MacOsPackagedWriterObservationError::Rejected)?,
            }))
        }
        2 => {
            let mut bytes = [0; CredentialWriterSessionAttestationV2Codec::BYTES];
            bytes[0] = version[0];
            reader
                .read_exact(&mut bytes[1..])
                .map_err(|_| MacOsPackagedWriterObservationError::Rejected)?;
            Ok(BootstrapPrefixVersion::Qualified {
                attestation: CredentialWriterSessionAttestationV2Codec::decode_and_verify(
                    &bytes,
                    expected_public_key,
                )
                .map_err(|_| MacOsPackagedWriterObservationError::Rejected)?,
                issue_ticket: PendingCredentialIssueTicketV1::read_from(reader)
                    .map_err(|_| MacOsPackagedWriterObservationError::Rejected)?,
                release: runne_api::PendingSignedInstalledReleaseMetadataV2::read_from(reader)
                    .map_err(|_| MacOsPackagedWriterObservationError::Rejected)?,
            })
        }
        _ => Err(MacOsPackagedWriterObservationError::Rejected),
    }
}
