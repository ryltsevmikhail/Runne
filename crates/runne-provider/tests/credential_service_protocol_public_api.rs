use runne_provider::{
    CredentialDispatchEffectReceipt, CredentialDispatchEffectReceiptAuthority, CredentialMaterial,
    CredentialMetadataReadbackAdmission, CredentialMetadataReadbackRequest,
    CredentialMutationGrant, CredentialMutationGrantDigest, CredentialPointOfUseReadAdmission,
    CredentialPointOfUseReadRequest, CredentialRuntimeArmAuthority,
    CredentialRuntimeMutationAdmission, CredentialRuntimeMutationArmRequest,
    CredentialRuntimeMutationPlan, CredentialRuntimeReadAuthority, CredentialRuntimeReadBinding,
    CredentialServiceCorrelation, CredentialServiceDeadline, CredentialServiceDisposition,
    CredentialServiceEndpointRole, CredentialServiceEpoch, CredentialServiceIngressRequest,
    CredentialServiceProtocolCodec, CredentialServiceReconciliationRequired,
    CredentialServiceReply, CredentialServiceReplyFrame, CredentialServiceRequest,
    CredentialServiceRequestContext, CredentialServiceRequestFrame, CredentialServiceRequestKind,
    CredentialServiceRequestSequence, CredentialWriterBrokerHandoffFrame,
    CredentialWriterConsumeRequest, CredentialWriterIngressRequest,
    CredentialWriterServiceBindingHandoff,
};
use zeroize::Zeroizing;

#[test]
fn credential_service_protocol_is_visible_from_the_crate_root() {
    macro_rules! visible {
        ($($ty:ty),+ $(,)?) => { $(let _ = std::any::type_name::<$ty>();)+ };
    }
    visible!(
        CredentialDispatchEffectReceipt,
        CredentialDispatchEffectReceiptAuthority,
        CredentialMaterial,
        CredentialMetadataReadbackAdmission,
        CredentialMetadataReadbackRequest,
        CredentialMutationGrant,
        CredentialMutationGrantDigest,
        CredentialPointOfUseReadAdmission,
        CredentialPointOfUseReadRequest,
        CredentialRuntimeArmAuthority,
        CredentialRuntimeMutationAdmission,
        CredentialRuntimeMutationArmRequest,
        CredentialRuntimeMutationPlan,
        CredentialRuntimeReadAuthority,
        CredentialRuntimeReadBinding,
        CredentialServiceCorrelation,
        CredentialServiceDeadline,
        CredentialServiceDisposition,
        CredentialServiceEndpointRole,
        CredentialServiceEpoch,
        CredentialServiceIngressRequest,
        CredentialServiceProtocolCodec,
        CredentialServiceReconciliationRequired,
        CredentialServiceReply,
        CredentialServiceReplyFrame,
        CredentialServiceRequest,
        CredentialServiceRequestContext,
        CredentialServiceRequestFrame,
        CredentialServiceRequestKind,
        CredentialServiceRequestSequence,
        CredentialWriterBrokerHandoffFrame,
        CredentialWriterConsumeRequest,
        CredentialWriterIngressRequest,
        CredentialWriterServiceBindingHandoff,
    );
}

#[test]
fn runtime_read_authority_and_material_consumer_are_externally_usable() {
    use runne_provider::{
        CredentialBindingDigest, CredentialEnrollmentAuthorityPair, CredentialFence,
        CredentialLifecycleRevision, CredentialServiceDeadline, CredentialServiceEpoch,
        CredentialServiceRequestSequence, CredentialVersionRef, ProviderId,
    };

    let (store, _) = CredentialEnrollmentAuthorityPair::new().split();
    let reads = store.runtime_read_authority();
    let provider = ProviderId::new("openai").unwrap();
    let binding = reads
        .issue_binding(
            CredentialServiceEpoch::from_bytes([1; 16]).unwrap(),
            [5; 32],
            [2; 16],
            3,
            CredentialBindingDigest::from_measured([4; 32]).unwrap(),
            provider.clone(),
            CredentialVersionRef::new(provider, 1).unwrap(),
            CredentialLifecycleRevision::new(1).unwrap(),
            CredentialFence::new(1).unwrap(),
            CredentialServiceRequestSequence::new(1).unwrap(),
            CredentialServiceCorrelation::from_bytes([6; 16]).unwrap(),
            CredentialServiceDeadline::new(10, 20).unwrap(),
        )
        .unwrap();
    assert!(reads.issue_metadata_readback(binding).is_ok());

    let mut observed = false;
    CredentialMaterial::from_bytes(b"secret".to_vec())
        .unwrap()
        .consume(|bytes| observed = bytes == b"secret");
    assert!(observed);
}

#[test]
fn credential_service_material_zeroizing_transfer_is_public_and_move_only() {
    let source = Zeroizing::new(b"runne-d1-1c-public-transfer-canary".to_vec());
    let allocation = source.as_ptr();
    let material = CredentialMaterial::from_zeroizing(source).unwrap();
    let recovered: Zeroizing<Vec<u8>> = material.into_zeroizing();

    assert_eq!(recovered.as_ptr(), allocation);
    assert_eq!(recovered.as_slice(), b"runne-d1-1c-public-transfer-canary");
}
