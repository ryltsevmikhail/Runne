use super::{
    approval, approval_flow, assertions, fault,
    lifecycle::OwnedFixture,
    owned::{Area, Child},
    target, terminal,
};
use crate::store::LocalCommandAttemptState;
use runne_application::ports::{CommitResult, EventStoreError};
use runne_platform::local_command_linux::LinuxLeaderExitKindV1;
use std::time::Duration;

pub(super) fn run(delete: bool) {
    // Future reviewed isolated Linux guest only; no install or bootstrap fallback.
    let shell = std::fs::read("/bin/sh").expect("NOTRUN: installed ELF shell required");
    assert!(shell.starts_with(b"\x7fELF"));
    let fixture = OwnedFixture::new();
    let f = fixture.get();
    assertions::absent(f);
    let argv = vec![
        "tool".into(),
        "-c".into(),
        "printf once > g2-corrupt-policy-marker".into(),
    ];
    let (b, prepared) = target::prepare_with_executable(f, argv, &shell);
    let observation = prepared.observation();
    assertions::binding(f, &b, observation);
    assertions::absent(f);
    let pending = f
        .store
        .capture_local_command_permission(&b, observation)
        .unwrap();
    assert_eq!(pending.state, LocalCommandAttemptState::ApprovalPending);
    assert_eq!(pending.canonical_binding_digest, *b.digest().as_bytes());
    assert_eq!(pending.native_owner_id, *observation.owner_id());
    assert_eq!(
        pending.native_owner_generation,
        observation.owner_generation()
    );
    assertions::absent(f);
    let id = approval_flow::confirm(f, &b);
    let receipt = f
        .store
        .admit_local_command_permission(&b, Some(id))
        .unwrap();
    let proof = approval::durable(f, &b, id);
    let approved = f
        .store
        .load_local_command_permission_capture(b.assignment().taskrun_id)
        .unwrap()
        .unwrap();
    assert_eq!(approved.state, LocalCommandAttemptState::Approved);
    assert_eq!(approved.binding, pending.binding);
    assert_eq!(approved.binding_digest, pending.binding_digest);
    assert_eq!(
        approved.canonical_binding_digest,
        pending.canonical_binding_digest
    );
    let original_rows = assertions::canonical(f, &b, id);
    assertions::live(f, &b);
    assertions::absent(f);
    let area = Area::new(&b);
    area.get().prove_empty().unwrap().revalidate().unwrap();
    // No fallible assertion between successful spawn and arming cleanup.
    let mut child = Child::new(
        prepared
            .bind(b.clone())
            .unwrap()
            .spawn(area.get(), receipt, &[])
            .unwrap(),
    );
    assert!(area.get().is_populated().unwrap());
    assert!(!child.child.was_released());
    assert_eq!(child.child.original_binding(), &b);
    assert_eq!(child.child.observation(), observation);
    assert_eq!(
        child.child.area_identity(),
        area.get().identity().to_bytes()
    );
    assertions::absent(f);
    fault::cut(f, delete);
    assertions::absent(f);
    assert_eq!(assertions::canonical(f, &b, id), original_rows);
    assertions::live(f, &b); // No current-policy lease; exact original claim/expiry.
    let result = f.store.release_local_command_permission(
        b.assignment(),
        b.claim_stream_version(),
        &b,
        area.get(),
        &mut child.child,
    );
    if delete {
        // New statements after GO, never a retained pre-GO read transaction.
        let after_rows = assertions::canonical(f, &b, id);
        assert_eq!(after_rows, original_rows);
        assert_eq!(
            f.store
                .load_local_command_permission_capture(b.assignment().taskrun_id)
                .unwrap()
                .unwrap(),
            approved
        );
        assert_eq!(approval::durable(f, &b, id), proof);
        assert!(matches!(result, Err(EventStoreError::Unavailable)));
        assert!(!child.child.was_released());
        assert_eq!(child.child.original_binding(), &b);
        assert_eq!(child.child.observation(), observation);
        assert_eq!(
            child.child.area_identity(),
            area.get().identity().to_bytes()
        );
        assertions::absent(f);
        child.stop_reap();
        let _observed_empty_output = child.drain();
        child.evidence(area.get());
        assert!(!child.child.was_released());
        assertions::absent(f);
    } else {
        result.unwrap();
        assert!(child.child.was_released());
        assert_eq!(
            child.child.wait_leader(Duration::from_secs(2)).unwrap(),
            LinuxLeaderExitKindV1::Exited { code: 0 }
        );
        let output = child.drain();
        child.evidence(area.get());
        assert_eq!(
            child.child.terminal_evidence().unwrap().leader_exit_kind(),
            LinuxLeaderExitKindV1::Exited { code: 0 }
        );
        assert_eq!(
            std::fs::read(f.root.path().join("workspace/g2-corrupt-policy-marker")).unwrap(),
            b"once"
        );
        let payload = terminal::success(f, b.assignment().taskrun_id);
        let version = payload.expected_version + 1;
        assert!(matches!(
            f.store
                .commit_local_command_permission_terminal(
                    payload,
                    b.assignment(),
                    &b,
                    &child.child,
                    output
                )
                .unwrap(),
            CommitResult::Committed { .. }
        ));
        terminal::assert_success(f, b.assignment().taskrun_id, version);
        let cleanup = f
            .store
            .scan_local_command_terminal_cleanup(None, 8)
            .unwrap();
        assert_eq!(cleanup.len(), 1);
        assert_eq!(cleanup[0].identity, *b.assignment());
        assert_eq!(cleanup[0].area_identity, area.get().identity().to_bytes());
    }
    child.disarm();
    drop(child);
    area.finish();
    if delete {
        assertions::absent(f);
    } else {
        assert_eq!(
            std::fs::read(f.root.path().join("workspace/g2-corrupt-policy-marker")).unwrap(),
            b"once"
        );
    }
    // fixture guard drops after child, area, prepared target and public Store clones.
}
