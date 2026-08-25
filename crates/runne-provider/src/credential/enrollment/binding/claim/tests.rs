use super::*;
use crate::credential::enrollment::{
    BrokerChannelBinding, CandidateSourceIdentity, ContinuationBindingDigest, ContractBundleDigest,
    CredentialFence, CredentialLifecycleRevision, CredentialMeasurementSnapshot,
    CredentialTicketAttempt, DaemonAuthorityId, DesktopExecutableIdentity, ProtectedSessionId,
    ReaderExecutableIdentity, ReleaseManifestDigest, WriterExecutableIdentity, WriterLaunchId,
    WriterProcessHandleIdentity, WriterProcessStartIdentity,
};

#[test]
fn credential_enrollment_claim_binding_changes_for_each_approved_field() {
    let binding = claim_binding();
    let digest = binding.digest();
    macro_rules! changed {
        ($field:ident, $value:expr) => {{
            let mut candidate = binding.clone();
            candidate.$field = $value;
            assert_ne!(candidate.digest(), digest, stringify!($field));
        }};
    }
    changed!(candidate_source_identity, measured(101));
    changed!(release_manifest_digest, measured(102));
    changed!(desktop_executable_identity, measured(103));
    changed!(writer_executable_identity, measured(104));
    changed!(reader_executable_identity, measured(105));
    changed!(contract_bundle_digest, measured(106));
    changed!(daemon_authority_id, measured(107));
    changed!(database_generation, 2);
    changed!(protected_session_id, measured(108));
    changed!(desktop_supervisor_generation, 2);
    changed!(writer_launch_id, measured(109));
    changed!(writer_process_start_identity, measured(110));
    changed!(writer_process_handle_identity, measured(111));
    changed!(broker_channel_binding, measured(112));
    changed!(continuation_binding_digest, measured(113));
    changed!(
        operation_id,
        CredentialOperationId::from_bytes([114; 16]).unwrap()
    );
    changed!(ticket_attempt, CredentialTicketAttempt::new(2).unwrap());
    changed!(ticket_digest, measured(115));
    changed!(provider_id, ProviderId::new("anthropic").unwrap());
    changed!(action, CredentialOperationAction::Revoke);
    changed!(credential_version, version("openai", 2));
    changed!(
        expected_lifecycle_revision,
        CredentialLifecycleRevision::new(2).unwrap()
    );
    changed!(expected_prior_fence, CredentialFence::new(2).unwrap());
    changed!(issued_at_high_water, 2);
    changed!(expires_at_high_water, 3);
}

fn claim_binding() -> CredentialClaimBinding {
    let measurements = CredentialMeasurementSnapshot::new(
        CandidateSourceIdentity::from_measured([1; 32]).unwrap(),
        ReleaseManifestDigest::from_measured([2; 32]).unwrap(),
        DesktopExecutableIdentity::from_measured([3; 32]).unwrap(),
        WriterExecutableIdentity::from_measured([4; 32]).unwrap(),
        ReaderExecutableIdentity::from_measured([5; 32]).unwrap(),
        ContractBundleDigest::from_measured([6; 32]).unwrap(),
        DaemonAuthorityId::from_measured([7; 32]).unwrap(),
        ProtectedSessionId::from_measured([8; 32]).unwrap(),
        WriterLaunchId::from_measured([9; 32]).unwrap(),
        WriterProcessStartIdentity::from_measured([10; 32]).unwrap(),
        WriterProcessHandleIdentity::from_measured([11; 32]).unwrap(),
        BrokerChannelBinding::from_measured([12; 32]).unwrap(),
        ContinuationBindingDigest::from_measured([13; 32]).unwrap(),
    )
    .unwrap();
    let claim = ClaimCredentialOperation::new(
        CredentialOperationId::from_bytes([14; 16]).unwrap(),
        CredentialTicketAttempt::new(1).unwrap(),
        measured(15),
        ProviderId::new("openai").unwrap(),
        CredentialOperationAction::Pair,
        version("openai", 1),
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        1,
        1,
        1,
        2,
    )
    .unwrap();
    CredentialClaimBinding::new(measurements, claim).unwrap()
}

fn measured(value: u8) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([value; 32]).unwrap()
}

fn version(provider: &str, value: u64) -> CredentialVersionRef {
    CredentialVersionRef::new(ProviderId::new(provider).unwrap(), value).unwrap()
}
