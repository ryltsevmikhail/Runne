use runne_provider::{
    CredentialMutationGrant, CredentialOperationAction, CredentialServiceDisposition,
    CredentialServiceEndpointRole, CredentialServiceReply,
};

use super::super::{CredentialBackendResult, CredentialServiceCore};
use super::support::{
    EPOCH, MemoryBackend, OWNER, arm_frame, arm_frame_with_grant_for_owner, binding,
    binding_for_owner, mutation_frames, register, runtime_reply, runtime_reply_for_owner,
    writer_reply,
};

#[test]
fn lower_out_of_order_sequence_is_denied_without_reaching_admission() {
    let mut core = registered_core();
    let (second, _, _) = mutation_frames(2, 2, 7, CredentialOperationAction::Pair);
    let (first, _, _) = mutation_frames(1, 1, 7, CredentialOperationAction::Pair);
    assert!(matches!(
        runtime_reply(&mut core, &second, 7, 10, |_| panic!()),
        Ok(CredentialServiceReply::Armed)
    ));
    assert!(matches!(
        runtime_reply(&mut core, &first, 7, 10, |_| panic!()),
        Ok(CredentialServiceReply::Rejected(
            CredentialServiceDisposition::Denied
        ))
    ));
}

#[test]
fn one_grant_digest_cannot_arm_two_admissions() {
    let mut core = registered_core();
    let grant = CredentialMutationGrant::generate().unwrap();
    let first = arm_frame(1, 1, 7, grant.digest());
    let second = arm_frame(2, 2, 7, grant.digest());
    assert!(matches!(
        runtime_reply(&mut core, &first, 7, 10, |_| panic!()),
        Ok(CredentialServiceReply::Armed)
    ));
    assert!(matches!(
        runtime_reply(&mut core, &second, 7, 10, |_| panic!()),
        Ok(CredentialServiceReply::Rejected(
            CredentialServiceDisposition::Denied
        ))
    ));
}

#[test]
fn one_grant_digest_is_unique_across_installation_owners() {
    let mut core = registered_core();
    let other = [8_u8; 32];
    register(
        &mut core,
        8,
        binding_for_owner(other, [8; 16], 2, 12, 14, 100),
        CredentialServiceEndpointRole::Desktop,
    )
    .unwrap();
    let grant = CredentialMutationGrant::generate().unwrap();
    let first = arm_frame_with_grant_for_owner(OWNER, OWNER, 1, 7, grant.digest());
    let duplicate = arm_frame_with_grant_for_owner(other, other, 1, 8, grant.digest());
    assert!(matches!(
        runtime_reply(&mut core, &first, 7, 10, |_| panic!()),
        Ok(CredentialServiceReply::Armed)
    ));
    assert!(matches!(
        runtime_reply_for_owner(&mut core, &duplicate, other, 8, 10, |_| panic!()),
        Ok(CredentialServiceReply::Rejected(
            CredentialServiceDisposition::Denied
        ))
    ));
    let distinct = arm_frame_with_grant_for_owner(
        other,
        other,
        1,
        8,
        CredentialMutationGrant::generate().unwrap().digest(),
    );
    assert!(matches!(
        runtime_reply_for_owner(&mut core, &distinct, other, 8, 10, |_| panic!()),
        Ok(CredentialServiceReply::Armed)
    ));
}

#[test]
fn ledger_rejects_sixty_fifth_without_evicting_first() {
    let mut core = registered_core();
    let mut first_writer = None;
    for sequence in 1..=64 {
        let (arm, writer, _) = mutation_frames(
            u8::try_from(sequence).unwrap(),
            sequence,
            7,
            CredentialOperationAction::Pair,
        );
        assert!(matches!(
            runtime_reply(&mut core, &arm, 7, 10, |_| panic!()),
            Ok(CredentialServiceReply::Armed)
        ));
        if sequence == 1 {
            first_writer = Some(writer);
        }
    }
    let (sixty_fifth, _, _) = mutation_frames(65, 65, 7, CredentialOperationAction::Pair);
    assert!(matches!(
        runtime_reply(&mut core, &sixty_fifth, 7, 10, |_| panic!()),
        Ok(CredentialServiceReply::Rejected(
            CredentialServiceDisposition::Unavailable
        ))
    ));
    let mut backend = MemoryBackend::new();
    assert!(matches!(
        writer_reply(&mut core, &first_writer.unwrap(), 10, |effect| backend
            .mutate(effect)),
        Ok(CredentialServiceReply::Consumed)
    ));
}

#[test]
fn grant_is_one_use_and_consumed_before_success_failure_and_panic() {
    for mode in 0..3 {
        let mut core = registered_core();
        let (arm, writer, _) = mutation_frames(1, 1, 7, CredentialOperationAction::Pair);
        assert!(matches!(
            runtime_reply(&mut core, &arm, 7, 10, |_| panic!()),
            Ok(CredentialServiceReply::Armed)
        ));
        let mut backend = MemoryBackend::new();
        if mode == 1 {
            backend.next = CredentialBackendResult::AccessDenied;
        }
        if mode == 2 {
            backend.panic_after_write = true;
        }
        let result = writer_reply(&mut core, &writer, 10, |effect| backend.mutate(effect));
        assert!(match mode {
            0 => matches!(result, Ok(CredentialServiceReply::Consumed)),
            1 => matches!(
                result,
                Ok(CredentialServiceReply::Rejected(
                    CredentialServiceDisposition::Denied
                ))
            ),
            _ => matches!(
                result,
                Ok(CredentialServiceReply::Rejected(
                    CredentialServiceDisposition::Uncertain
                ))
            ),
        });
        assert!(matches!(
            writer_reply(&mut core, &writer, 10, |effect| backend.mutate(effect)),
            Ok(CredentialServiceReply::Rejected(
                CredentialServiceDisposition::Denied
            ))
        ));
        assert_eq!(
            backend.items.get(&("provider".into(), 1)).unwrap(),
            b"secret"
        );
    }
}

#[test]
fn wrong_raw_grant_is_denied_and_crash_outcome_requires_reconciliation() {
    let mut core = registered_core();
    let (arm, writer, _) = mutation_frames(1, 1, 7, CredentialOperationAction::Pair);
    let (_, wrong_writer, _) = mutation_frames(1, 1, 9, CredentialOperationAction::Pair);
    assert!(matches!(
        runtime_reply(&mut core, &arm, 7, 10, |_| panic!()),
        Ok(CredentialServiceReply::Armed)
    ));
    let mut backend = MemoryBackend::new();
    assert!(matches!(
        writer_reply(&mut core, &wrong_writer, 10, |effect| backend
            .mutate(effect)),
        Ok(CredentialServiceReply::Rejected(
            CredentialServiceDisposition::Denied
        ))
    ));
    assert!(backend.items.is_empty());
    backend.next = CredentialBackendResult::Uncertain;
    assert!(matches!(
        writer_reply(&mut core, &writer, 10, |effect| backend.mutate(effect)),
        Ok(CredentialServiceReply::Rejected(
            CredentialServiceDisposition::Uncertain
        ))
    ));
}

#[test]
fn revoke_consumes_one_secretless_grant_and_deletes_the_exact_version() {
    let mut core = registered_core();
    let (arm, writer, _) = mutation_frames(1, 1, 7, CredentialOperationAction::Revoke);
    assert!(matches!(
        runtime_reply(&mut core, &arm, 7, 10, |_| panic!()),
        Ok(CredentialServiceReply::Armed)
    ));
    let mut backend = MemoryBackend::new();
    backend
        .items
        .insert(("provider".to_owned(), 1), b"secret".to_vec());

    assert!(matches!(
        writer_reply(&mut core, &writer, 10, |effect| backend.mutate(effect)),
        Ok(CredentialServiceReply::Consumed)
    ));
    assert!(backend.items.is_empty());
    assert!(matches!(
        writer_reply(&mut core, &writer, 10, |effect| backend.mutate(effect)),
        Ok(CredentialServiceReply::Rejected(
            CredentialServiceDisposition::Denied
        ))
    ));
}

#[test]
fn native_backend_results_map_to_the_closed_writer_reply_vocabulary() {
    for (mode, result) in [
        (0, CredentialBackendResult::Absent),
        (1, CredentialBackendResult::Unsupported),
        (2, CredentialBackendResult::Unavailable),
    ] {
        let mut core = registered_core();
        let (arm, writer, _) = mutation_frames(1, 1, 7, CredentialOperationAction::Pair);
        assert!(matches!(
            runtime_reply(&mut core, &arm, 7, 10, |_| panic!()),
            Ok(CredentialServiceReply::Armed)
        ));
        let reply = writer_reply(&mut core, &writer, 10, |_| result).unwrap();
        assert!(match mode {
            0 => matches!(
                reply,
                CredentialServiceReply::Rejected(CredentialServiceDisposition::Denied)
            ),
            1 => matches!(
                reply,
                CredentialServiceReply::Rejected(CredentialServiceDisposition::Unsupported)
            ),
            _ => matches!(
                reply,
                CredentialServiceReply::Rejected(CredentialServiceDisposition::Unavailable)
            ),
        });
    }
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

#[test]
fn legacy_import_preserves_source_revision_through_one_use_service_admission() {
    let mut core = registered_core();
    let (arm, writer, _) = mutation_frames(1, 1, 7, CredentialOperationAction::MigrateLegacy);
    assert!(matches!(
        runtime_reply(&mut core, &arm, 7, 10, |_| panic!()),
        Ok(CredentialServiceReply::Armed)
    ));
    let reply = writer_reply(&mut core, &writer, 10, |effect| {
        assert_eq!(effect.source_revision(), Some([73; 16]));
        effect
            .into_material()
            .unwrap()
            .consume(|bytes| assert_eq!(bytes, b"secret"));
        CredentialBackendResult::Observed(())
    })
    .unwrap();
    assert!(matches!(reply, CredentialServiceReply::Consumed));
    assert!(matches!(
        writer_reply(&mut core, &writer, 10, |_| panic!("replayed effect")),
        Ok(CredentialServiceReply::Rejected(
            CredentialServiceDisposition::Denied
        ))
    ));
}
