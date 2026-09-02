use super::super::{
    CredentialMetadataReadbackRequest, CredentialServiceCorrelation, CredentialServiceDeadline,
    CredentialServiceEpoch, CredentialServiceProtocolCodec, CredentialServiceRequest,
    CredentialServiceRequestSequence,
};
use super::support::{authorities, digest};
use crate::credential::enrollment::{CredentialFence, CredentialLifecycleRevision};
use crate::{CredentialVersionRef, ProviderId};

#[allow(clippy::too_many_arguments)]
pub(super) fn encoded_read(
    epoch: u8,
    session: u8,
    generation: u64,
    release: u8,
    provider: &str,
    version: u64,
    revision: u64,
    fence: u64,
    sequence: u64,
    issued: u64,
    expires: u64,
    correlation: u8,
    point: bool,
) -> Vec<u8> {
    let (_, store) = authorities();
    let reads = store.runtime_read_authority();
    let provider = ProviderId::new(provider).unwrap();
    let binding = reads
        .issue_binding(
            CredentialServiceEpoch::from_bytes([epoch; 16]).unwrap(),
            [session; 16],
            generation,
            digest(release),
            provider.clone(),
            CredentialVersionRef::new(provider, version).unwrap(),
            CredentialLifecycleRevision::new(revision).unwrap(),
            CredentialFence::new(fence).unwrap(),
            CredentialServiceRequestSequence::new(sequence).unwrap(),
            CredentialServiceCorrelation::from_bytes([correlation; 16]).unwrap(),
            CredentialServiceDeadline::new(issued, expires).unwrap(),
        )
        .unwrap();
    let request = if point {
        CredentialServiceRequest::PointOfUseRead(
            store
                .dispatch_effect_receipt_authority()
                .issue_point_of_use_read(binding, digest(77))
                .unwrap(),
        )
    } else {
        CredentialServiceRequest::MetadataReadback(reads.issue_metadata_readback(binding).unwrap())
    };
    CredentialServiceProtocolCodec::encode_request(request)
        .unwrap()
        .test_bytes()
        .to_vec()
}

pub(super) fn read_requests(
    provider: &str,
    version: u64,
) -> (
    CredentialMetadataReadbackRequest,
    super::super::CredentialPointOfUseReadRequest,
) {
    let provider = ProviderId::new(provider).unwrap();
    let (_, store) = authorities();
    let reads = store.runtime_read_authority();
    let binding = reads
        .issue_binding(
            CredentialServiceEpoch::from_bytes([1; 16]).unwrap(),
            [2; 16],
            3,
            digest(4),
            provider.clone(),
            CredentialVersionRef::new(provider, version).unwrap(),
            CredentialLifecycleRevision::new(1).unwrap(),
            CredentialFence::new(1).unwrap(),
            CredentialServiceRequestSequence::new(1).unwrap(),
            CredentialServiceCorrelation::from_bytes([6; 16]).unwrap(),
            CredentialServiceDeadline::new(10, 20).unwrap(),
        )
        .unwrap();
    let metadata = reads.issue_metadata_readback(binding.clone()).unwrap();
    let point = store
        .dispatch_effect_receipt_authority()
        .issue_point_of_use_read(binding, digest(77))
        .unwrap();
    (metadata, point)
}
