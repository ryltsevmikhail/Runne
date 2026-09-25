use runne_provider::{
    CredentialOperationAction, CredentialServiceDisposition, CredentialServiceReply,
};

use super::super::{CredentialRuntimeReadEffect, CredentialRuntimeReadObservation};
use super::admission::registered_core;
use super::support::{MemoryBackend, mutation_frames, read_frame, runtime_reply, writer_reply};

#[test]
fn revoke_commit_then_reply_loss_is_uncertain_one_use_and_secretlessly_reconciled() {
    let mut core = registered_core();
    let (arm, writer, _) = mutation_frames(1, 1, 7, CredentialOperationAction::Revoke);
    assert!(matches!(
        runtime_reply(&mut core, &arm, 7, 10, |_| panic!()),
        Ok(CredentialServiceReply::Armed)
    ));
    let mut backend = MemoryBackend::new();
    backend
        .items
        .insert(("provider".into(), 1), b"secret".to_vec());
    backend.panic_after_write = true;

    assert!(matches!(
        writer_reply(&mut core, &writer, 10, |effect| backend.mutate(effect)),
        Ok(CredentialServiceReply::Rejected(
            CredentialServiceDisposition::Uncertain
        ))
    ));
    assert!(backend.items.is_empty());
    assert!(matches!(
        writer_reply(&mut core, &writer, 10, |_| panic!("replayed delete")),
        Ok(CredentialServiceReply::Rejected(
            CredentialServiceDisposition::Denied
        ))
    ));

    let mut restarted = registered_core();
    let readback = read_frame(1, false, 77, 7);
    assert!(matches!(
        runtime_reply(&mut restarted, &readback, 7, 10, |effect| match effect {
            CredentialRuntimeReadEffect::Metadata(version) => {
                CredentialRuntimeReadObservation::Metadata(backend.metadata(version))
            }
            CredentialRuntimeReadEffect::PointOfUse(_) => panic!(),
        }),
        Ok(CredentialServiceReply::Metadata { present: false })
    ));
}
