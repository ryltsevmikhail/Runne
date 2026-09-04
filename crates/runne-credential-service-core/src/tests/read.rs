use runne_provider::{
    CredentialServiceDisposition, CredentialServiceEndpointRole, CredentialServiceReply,
};

use super::super::{
    CredentialRuntimeReadEffect, CredentialRuntimeReadObservation, CredentialServiceCore,
};
use super::support::{
    EPOCH, MemoryBackend, binding, read_frame, read_frame_at, register, runtime_reply,
};

#[test]
fn metadata_reply_preserves_import_revision_and_rejects_zero_revision() {
    let mut core = registered_core();
    let request = read_frame(1, false, 77, 7);
    assert!(
        matches!(runtime_reply(&mut core, &request, 7, 10, |effect| {
        assert!(matches!(effect, CredentialRuntimeReadEffect::Metadata(_)));
        CredentialRuntimeReadObservation::LegacyMetadata(
            crate::CredentialBackendResult::Observed([9; 16]))
    }), Ok(CredentialServiceReply::LegacyMetadata { source_revision }) if source_revision == [9; 16])
    );
    let request = read_frame(2, false, 77, 7);
    assert!(matches!(
        runtime_reply(&mut core, &request, 7, 10, |_| {
            CredentialRuntimeReadObservation::LegacyMetadata(
                crate::CredentialBackendResult::Observed([0; 16]),
            )
        }),
        Ok(CredentialServiceReply::Rejected(
            CredentialServiceDisposition::Unavailable
        ))
    ));
}

#[test]
fn metadata_and_dispatch_bound_read_use_real_backend_state() {
    let mut core = registered_core();
    let mut backend = MemoryBackend::new();
    backend
        .items
        .insert(("provider".into(), 1), b"secret".to_vec());
    let metadata = read_frame(1, false, 77, 7);
    assert!(matches!(
        runtime_reply(&mut core, &metadata, 7, 10, |effect| match effect {
            CredentialRuntimeReadEffect::Metadata(version) =>
                CredentialRuntimeReadObservation::Metadata(backend.metadata(version)),
            CredentialRuntimeReadEffect::PointOfUse(_) => panic!(),
        }),
        Ok(CredentialServiceReply::Metadata { present: true })
    ));
    let point = read_frame(2, true, 88, 7);
    let reply = runtime_reply(&mut core, &point, 7, 10, |effect| match effect {
        CredentialRuntimeReadEffect::PointOfUse(version) => {
            CredentialRuntimeReadObservation::PointOfUse(backend.read(version))
        }
        CredentialRuntimeReadEffect::Metadata(_) => panic!(),
    })
    .unwrap();
    let CredentialServiceReply::Material(material) = reply else {
        panic!("expected material")
    };
    let mut observed = false;
    material.consume(|bytes| observed = bytes == b"secret");
    assert!(observed);
    let replayed_receipt = read_frame(3, true, 88, 7);
    assert!(matches!(
        runtime_reply(&mut core, &replayed_receipt, 7, 10, |effect| match effect {
            CredentialRuntimeReadEffect::PointOfUse(version) =>
                CredentialRuntimeReadObservation::PointOfUse(backend.read(version)),
            CredentialRuntimeReadEffect::Metadata(_) => panic!(),
        }),
        Ok(CredentialServiceReply::Rejected(
            CredentialServiceDisposition::Denied
        ))
    ));
}

#[test]
fn active_read_receipts_are_bounded_and_only_expired_entries_are_reclaimed() {
    let mut core = registered_core();
    let backend = MemoryBackend::new();
    for sequence in 1..=64 {
        let frame = read_frame_at(sequence, true, u8::try_from(sequence).unwrap(), 7, 10, 20);
        assert!(matches!(
            runtime_reply(&mut core, &frame, 7, 10, |effect| match effect {
                CredentialRuntimeReadEffect::PointOfUse(version) =>
                    CredentialRuntimeReadObservation::PointOfUse(backend.read(version)),
                CredentialRuntimeReadEffect::Metadata(_) => panic!(),
            }),
            Ok(CredentialServiceReply::Rejected(
                CredentialServiceDisposition::Denied
            ))
        ));
    }
    let full = read_frame_at(65, true, 65, 7, 10, 20);
    assert!(matches!(
        runtime_reply(&mut core, &full, 7, 10, |effect| match effect {
            CredentialRuntimeReadEffect::PointOfUse(version) =>
                CredentialRuntimeReadObservation::PointOfUse(backend.read(version)),
            CredentialRuntimeReadEffect::Metadata(_) => panic!(),
        }),
        Ok(CredentialServiceReply::Rejected(
            CredentialServiceDisposition::Unavailable
        ))
    ));
    let after_expiry = read_frame_at(65, true, 66, 7, 21, 30);
    assert!(matches!(
        runtime_reply(&mut core, &after_expiry, 7, 21, |effect| match effect {
            CredentialRuntimeReadEffect::PointOfUse(version) =>
                CredentialRuntimeReadObservation::PointOfUse(backend.read(version)),
            CredentialRuntimeReadEffect::Metadata(_) => panic!(),
        }),
        Ok(CredentialServiceReply::Rejected(
            CredentialServiceDisposition::Denied
        ))
    ));
}

#[test]
fn poll_removes_expired_read_receipt_before_parent_session_expiry() {
    let mut core = registered_core();
    let backend = MemoryBackend::new();
    let frame = read_frame_at(1, true, 77, 7, 10, 20);
    let _ = runtime_reply(&mut core, &frame, 7, 10, |effect| match effect {
        CredentialRuntimeReadEffect::PointOfUse(version) => {
            CredentialRuntimeReadObservation::PointOfUse(backend.read(version))
        }
        CredentialRuntimeReadEffect::Metadata(_) => panic!(),
    });
    assert_eq!(core.poll(19).next_deadline_unix_millis(), Some(20));
    let after_receipt_expiry = core.poll(20);
    assert!(after_receipt_expiry.prevents_idle());
    assert_eq!(after_receipt_expiry.next_deadline_unix_millis(), Some(100));
}

#[test]
fn runtime_read_panic_maps_to_authenticated_unavailable_after_sequence_consume() {
    let mut core = registered_core();
    let frame = read_frame(1, false, 77, 7);
    assert!(matches!(
        runtime_reply(&mut core, &frame, 7, 10, |_| panic!("native read panic")),
        Ok(CredentialServiceReply::Rejected(
            CredentialServiceDisposition::Unavailable
        ))
    ));
    assert!(matches!(
        runtime_reply(&mut core, &frame, 7, 10, |_| panic!()),
        Ok(CredentialServiceReply::Rejected(
            CredentialServiceDisposition::Denied
        ))
    ));
}

fn registered_core() -> CredentialServiceCore {
    let mut core = CredentialServiceCore::with_test_epoch(EPOCH).unwrap();
    register(
        &mut core,
        7,
        binding(2, 12, 14, 100),
        CredentialServiceEndpointRole::Desktop,
    )
    .unwrap();
    core
}
