fn prepare_state(
    f: &fixture::Fixture,
    binding: &runne_application::permission_modes::LocalCommandPermissionBindingV1,
    capture: &crate::store::LocalCommandPermissionCaptureV1,
    state: &str,
) {
    if state == "pending" {
        return;
    }
    let id = binding.assignment();
    if state == "no_effect_terminal" {
        use runne_application::{ports::*, service::TaskRunService};
        let context = ApplicationCommandContext {
            command_id: fixture::command_id(),
            idempotency_key: fixture::key("migration-release"),
            principal_id: PrincipalId(f.principal.as_str().into()),
            actor: runne_domain::event::Actor::new("migration-data-test").unwrap(),
        };
        let service = TaskRunService::new(
            f.store.clone(),
            f.store.clone(),
            f.store.clone(),
            f.scope.runtime_authority_id.clone(),
        );
        let result = service
            .settle_taskrun_no_effect(
                &context,
                TaskRunNoEffectCandidate {
                    identity: id.clone(),
                    current_version: binding.claim_stream_version(),
                },
                &f.store,
            )
            .unwrap();
        let TaskRunNoEffectReleaseResult::Released(receipt) = result else {
            panic!("fresh release")
        };
        assert_eq!(receipt.taskrun_id, id.taskrun_id);
        // Existing no-effect path terminalizes the attempt and release receipt;
        // it does not mint an x2 native-effect terminal sidecar.
    } else {
        let writer = f.store.inner.writer.lock().unwrap();
        // Explicit migration-state data, NOT NativePermit/admitted/GO evidence.
        let mut area = [0u8; 100];
        area[..4].copy_from_slice(b"RMA1");
        area[4..20].fill(1);
        area[28..36].fill(2);
        area[44..52].fill(3);
        area[52..68].copy_from_slice(id.taskrun_id.as_bytes());
        area[68..84].copy_from_slice(id.attempt_id.as_bytes());
        area[84..].fill(5);
        writer.execute("UPDATE taskrun_local_command_attempts SET managed_area_identity=?1 WHERE taskrun_id=?2", rusqlite::params![area.as_slice(),id.taskrun_id.as_bytes()]).unwrap();
        writer.execute("INSERT INTO x2_permission_admission(taskrun_id,attempt_id,binding_digest,admission_kind,proof_digest,admitted_at) VALUES(?1,?2,?3,1,NULL,1)",rusqlite::params![id.taskrun_id.as_bytes(),id.attempt_id.as_bytes(),capture.binding_digest]).unwrap();
        writer.execute("INSERT INTO x2_permission_spent(taskrun_id,attempt_id,binding_digest,invocation_id,area_identity,owner_id,owner_generation,burn_id,burned_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,1)",rusqlite::params![id.taskrun_id.as_bytes(),id.attempt_id.as_bytes(),capture.binding_digest,binding.invocation_id().as_bytes(),area.as_slice(),capture.native_owner_id,capture.native_owner_generation.to_be_bytes(),uuid::Uuid::now_v7().as_bytes()]).unwrap();
    }
}
pub(crate) fn assert_state(c: &rusqlite::Connection, state: &str) {
    let counts: Vec<i64> = [
        "x2_permission_human",
        "x2_permission_admission",
        "x2_permission_spent",
        "x2_permission_terminal",
    ]
    .into_iter()
    .map(|t| {
        c.query_row(&format!("SELECT COUNT(*) FROM {t}"), [], |r| r.get(0))
            .unwrap()
    })
    .collect();
    assert_eq!(
        counts,
        match state {
            "pending" => vec![0, 0, 0, 0],
            "spent_data" => vec![0, 1, 1, 0],
            "no_effect_terminal" => vec![0, 0, 0, 0],
            _ => panic!("unknown data state"),
        }
    );
    let (attempt, released): (String, i64) = c.query_row("SELECT state,(SELECT COUNT(*) FROM taskrun_no_effect_release_receipts) FROM taskrun_local_command_attempts", [], |r| Ok((r.get(0)?,r.get(1)?))).unwrap();
    assert_eq!(
        attempt,
        if state == "no_effect_terminal" {
            "no_effect_terminal"
        } else {
            "approval_pending"
        }
    );
    assert_eq!(released, i64::from(state == "no_effect_terminal"));
}
