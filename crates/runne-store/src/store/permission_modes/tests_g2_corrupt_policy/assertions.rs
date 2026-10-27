use super::fixture::{Fixture, now};
use runne_application::permission_modes::*;
use runne_application::project_trust::{
    ManagedEffectDecision, ProjectTrustPersistence, ProjectTrustStatus,
    managed_effect_policy_digest_v2,
};
use runne_domain::id::ApprovalId;
use runne_platform::local_command_linux::{
    LinuxCompositeScopeAdmission, PermissionTargetObservationV1,
};
use rusqlite::{Connection, Params, types::Value};
use sha2::{Digest, Sha256};
use std::os::unix::fs::MetadataExt;

pub(super) fn absent(f: &Fixture) {
    match std::fs::symlink_metadata(f.root.path().join("workspace/g2-corrupt-policy-marker")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        other => panic!("marker must be exactly NotFound: {other:?}"),
    }
}

pub(super) fn binding(
    f: &Fixture,
    b: &LocalCommandPermissionBindingV1,
    o: PermissionTargetObservationV1,
) {
    assert_eq!(b.selection().scope, f.scope);
    assert_eq!(b.selection().selected_mode, PermissionMode::AskAlways);
    assert_eq!(b.selection().authorization_revision, 0);
    assert_eq!(b.selection().preset_version.as_u16(), 1);
    assert_eq!(b.selection().expires_at_unix_ms, None);
    assert_eq!(b.project_id(), f.project);
    assert_eq!(
        (
            b.project_version(),
            b.workspace_version(),
            b.admitted_root_version()
        ),
        // Project starts at 1; creating its workspace advances membership by 2.
        (3, 2, 2)
    );
    assert_eq!(
        b.held_root_identity_digest(),
        LinuxCompositeScopeAdmission::workspace_root_identity(&f.held).unwrap()
    );
    assert_eq!(b.command().cwd(), ".");
    assert!(matches!(b.command().executable(),
        runne_domain::task_run::TaskRunExecutable::WorkspaceRelative(p) if p == "tool"));
    assert!(b.command().env().is_empty());
    // Observation descriptor identity has its own domain; the root fence above does not.
    // Derive both exact observations from the actual held descriptor, not each other.
    let metadata = f.held.metadata().unwrap();
    let mut descriptor = Sha256::new();
    descriptor.update(b"runne:d21:x2-held-fd:v1\0");
    descriptor.update(metadata.dev().to_be_bytes());
    descriptor.update(metadata.ino().to_be_bytes());
    let expected_descriptor: [u8; 32] = descriptor.finalize().into();
    assert_eq!(o.workspace_identity(), &expected_descriptor);
    assert_eq!(o.cwd_identity(), &expected_descriptor);
    assert_eq!(
        b.command().argv(),
        &["tool", "-c", "printf once > g2-corrupt-policy-marker"]
    );
    assert_eq!(
        b.command_intent_digest().as_bytes(),
        &b.command().intent_digest()
    );
    let a = b.approval();
    assert_eq!(a.principal_id, f.principal);
    assert_eq!(a.invocation.task_run_id, b.assignment().taskrun_id);
    assert_eq!(a.invocation.attempt_id, b.assignment().attempt_id);
    assert_eq!(a.invocation.invocation_id, b.invocation_id());
    assert_eq!(
        a.normalized_arguments_digest.as_bytes(),
        o.normalized_arguments_digest()
    );
    assert_eq!(a.tool_schema_digest.as_bytes(), o.schema_digest());
    assert_eq!(a.target_identity_digest.as_bytes(), o.target_identity());
    assert_eq!(a.target_version, o.target_version());
    assert_eq!(a.environment_digest.as_bytes(), o.environment_digest());
    assert_eq!(a.cwd_identity_digest.as_bytes(), o.cwd_identity());
    assert_eq!(
        a.executable_digest.unwrap().as_bytes(),
        o.executable_digest()
    );
    let s = b.closed_rules_snapshot();
    assert_eq!(s.record.status, ProjectTrustStatus::Trusted);
    assert_eq!((s.record.managed_deny_mask, s.record.revision), (0, 1));
    assert_ne!(s.record.instance_epoch, 0);
    assert_eq!(s.record.instance_epoch, f.trust.registration_identity().1);
    assert_eq!(s.policy.version, 1);
    assert!(
        s.policy
            .decisions()
            .into_iter()
            .all(|d| d == ManagedEffectDecision::Allow)
    );
    assert_eq!(
        managed_effect_policy_digest_v2(f.trust_id(), &s).unwrap(),
        *b.closed_rules_digest().as_bytes()
    );
    assert_eq!(
        ManagedPolicyCoverage::from_closed_snapshot(f.trust_id(), &s).unwrap(),
        b.scope().managed_policy
    );
    {
        let lease = f.trust.acquire_effect_lease(f.trust_id()).unwrap();
        assert_eq!(lease.snapshot().unwrap(), s);
        let authority = crate::store::PermissionModeAuthorityContext::new(
            &f.principal,
            f.trust_id(),
            lease.as_ref(),
            None,
        );
        let current = f
            .store
            .load_permission_mode_selection_with_managed_identity(
                &f.scope,
                &f.principal,
                &authority,
            )
            .unwrap();
        assert_eq!(current.selection, *b.selection());
        let crate::store::ManagedIdentityMetadata::ClosedRulesV2(managed) = current.identity else {
            panic!("current ClosedRulesV2 required")
        };
        assert_eq!(managed.snapshot, s);
        assert_eq!(managed.canonical_digest, b.closed_rules_digest());
        assert_eq!(managed.project_version, b.project_version());
        assert_eq!(managed.project_id, *b.project_id().as_bytes());
    }
    // No policy lease survives this helper or the preparation helper.
    live(f, b);
}

pub(super) fn live(f: &Fixture, b: &LocalCommandPermissionBindingV1) {
    assert!(b.approval().expires_at_unix_ms > now());
    let r = f.store.inner.reader.lock().unwrap();
    assert!(r.is_autocommit());
    crate::store::taskrun_claim::verify_active_assignment(&r, b.assignment()).unwrap();
    let (expiry, version): (i64, u64) = r
        .query_row(
            "SELECT lease_expires_at_ms,new_version FROM taskrun_claim_receipts
         WHERE taskrun_id=?1 AND attempt_id=?2 AND fence=?3",
            rusqlite::params![
                b.assignment().taskrun_id.as_bytes(),
                b.assignment().attempt_id.as_bytes(),
                b.assignment().fence.0
            ],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert!(expiry > now());
    assert_eq!(version, b.claim_stream_version());
}

pub(super) fn rows(c: &Connection, sql: &str, p: impl Params) -> Vec<Vec<Value>> {
    let mut statement = c.prepare(sql).unwrap();
    let count = statement.column_count();
    statement
        .query_map(p, |r| (0..count).map(|i| r.get(i)).collect())
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

// Every call finishes all statements and drops its autocommit reader lock.
// Complete raw rows preserve encoded binding/context, proof, digests and timestamps.
pub(super) fn canonical(
    f: &Fixture,
    b: &LocalCommandPermissionBindingV1,
    approval: ApprovalId,
) -> Vec<Vec<Vec<Value>>> {
    let r = f.store.inner.reader.lock().unwrap();
    assert!(r.is_autocommit());
    let a = b.assignment();
    let spent: i64 = r
        .query_row(
            "SELECT COUNT(*) FROM x2_permission_spent
        WHERE taskrun_id=?1 AND attempt_id=?2",
            rusqlite::params![a.taskrun_id.as_bytes(), a.attempt_id.as_bytes()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(spent, 0);
    let state: (String, Option<Vec<u8>>) = r
        .query_row(
            "SELECT state,managed_area_identity FROM taskrun_local_command_attempts
         WHERE taskrun_id=?1 AND attempt_id=?2 AND fence=?3",
            rusqlite::params![a.taskrun_id.as_bytes(), a.attempt_id.as_bytes(), a.fence.0],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(state, ("approved".into(), None));
    let mut data = Vec::new();
    for sql in [
        "SELECT * FROM x2_permission_bindings WHERE taskrun_id=?1 AND attempt_id=?2",
        "SELECT * FROM x2_permission_admission WHERE taskrun_id=?1 AND attempt_id=?2",
        "SELECT * FROM x2_permission_human WHERE taskrun_id=?1 AND attempt_id=?2",
        "SELECT * FROM taskrun_local_command_attempts WHERE taskrun_id=?1 AND attempt_id=?2",
    ] {
        let values = rows(
            &r,
            sql,
            rusqlite::params![a.taskrun_id.as_bytes(), a.attempt_id.as_bytes()],
        );
        assert_eq!(values.len(), 1);
        data.push(values);
    }
    let approval_rows = rows(
        &r,
        "SELECT * FROM approvals WHERE approval_id=?1",
        [approval.to_string()],
    );
    assert_eq!(approval_rows.len(), 1);
    data.push(approval_rows);
    let version: (i64, i64, i64) = r
        .query_row(
            "SELECT request_version,state,expires_at FROM approvals WHERE approval_id=?1",
            [approval.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!((version.0, version.1), (2, 2));
    assert!(version.2 > now());
    data
}
