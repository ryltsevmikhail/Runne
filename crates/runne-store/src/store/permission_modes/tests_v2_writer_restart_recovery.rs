use std::path::Path;
use std::sync::Arc;

use runne_application::permission_modes::{ModeSelection, PermissionMode, PresetVersion};
use runne_application::project_trust::{ProjectTrustPersistence, ProjectTrustProjectId};
use runne_domain::id::ProjectId;

use super::history::{assert_issued, canonical_receipt, diagnostics};
use super::metadata;
use crate::schema::{self, ConnectionMode};
use crate::store::permission_modes::model::{
    PermissionModeAuthorityContext, PermissionModeCeremonyStatusV2 as Status,
    ProtectedNativeLaunchContext,
};
use crate::{ProjectTrustStore, store::StoreTransaction};

pub(super) fn recover(root: &Path, case: &str) {
    let mut saved = metadata::read(root, "checkpoint.json", case);
    assert!(saved.recovered_pid.is_none());
    let daemon = saved.daemon(root);
    let db = daemon.join("permission-modes.sqlite");
    metadata::regular(&db);
    // Check the exact retained sidecar BEFORE open, which otherwise may create it.
    metadata::regular(&daemon.join("trust-anchor.sqlite.project-trust"));
    let request = saved.request();
    let lineage = saved.lineage.parse().unwrap();
    let validate = |connection: &rusqlite::Connection| -> rusqlite::Result<()> {
        if schema::read_authority_id(connection)? != Some(saved.authority)
            || schema::read_event_log_lineage_id(connection)? != Some(lineage)
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        Ok(())
    };
    // Neither connection inherits admission from the other. No identity ensure/repair.
    let writer =
        schema::reopen_managed_connection_validated(&db, ConnectionMode::ValidatedReopen, validate)
            .unwrap();
    let reader =
        schema::reopen_managed_connection_validated(&db, ConnectionMode::Reader, validate).unwrap();
    let store = StoreTransaction::open_with_connections(
        db.to_str().unwrap(),
        writer,
        reader,
        request.scope.runtime_authority_id.clone(),
        Arc::new(runne_security::SecretBroker::new().prohibited_content_guard()),
    )
    .unwrap();
    let trust =
        ProjectTrustStore::open(&daemon.join("trust-anchor.sqlite"), saved.authority).unwrap();
    let project: ProjectId = saved.project.parse().unwrap();
    let project = ProjectTrustProjectId::from_bytes(project.into_bytes());
    let original = saved.trust_record();
    let retained = trust.load(project).unwrap();
    assert_eq!(retained, original);
    assert_eq!(retained.token(), original.token());
    // A fresh lease comes only after exact state/full epoch-scoped token comparison.
    let lease = trust.acquire_effect_lease(project).unwrap();
    let original_launch = ProtectedNativeLaunchContext::new(
        saved.launch_authority,
        saved.desktop_instance,
        saved.daemon_instance,
        saved.launch_generation,
        saved.key_epoch,
    )
    .unwrap()
    .with_protected_session_id(saved.session)
    .unwrap();
    let mut rotated_session = saved.session;
    rotated_session[15] ^= 1;
    let rotated = original_launch
        .with_protected_session_id(rotated_session)
        .unwrap();
    assert_ne!(
        rotated.protected_session_id(),
        original_launch.protected_session_id()
    );
    let authority = PermissionModeAuthorityContext::new(
        &request.scope.principal_id,
        project,
        lease.as_ref(),
        Some(&rotated),
    );
    let status = || {
        store
            .load_permission_mode_confirmation_status_v2(
                &request.scope,
                &request.scope.principal_id,
                request.command_id,
            )
            .unwrap()
    };
    if case == "pending" {
        let Some(Status::Pending(issued)) = status() else {
            panic!("reopened pending status required");
        };
        assert_issued(&issued, &request, &saved);
        diagnostics(&store, &request, &saved.challenge, (1, 1));
        assert_eq!(
            store
                .load_permission_mode_selection(&request.scope, &request.scope.principal_id,)
                .unwrap(),
            ModeSelection::missing(request.scope.clone())
        );
        assert!(super::super::unix_ms() < saved.challenge_expires);
        assert_eq!(
            store
                .begin_permission_mode_confirmation_v2(request.clone(), &authority,)
                .unwrap(),
            Status::Invalidated
        );
        assert!(
            super::super::unix_ms() < saved.challenge_expires,
            "expiry must not substitute for session invalidation"
        );
        assert_eq!(status(), Some(Status::Invalidated));
        diagnostics(&store, &request, &saved.challenge, (3, 3));
        assert_eq!(
            store
                .load_permission_mode_selection(&request.scope, &request.scope.principal_id,)
                .unwrap(),
            ModeSelection::missing(request.scope.clone())
        );
    } else {
        assert_eq!(case, "committed");
        let Some(Status::Committed(receipt)) = status() else {
            panic!("reopened committed status required");
        };
        assert_eq!(Some(canonical_receipt(&receipt)), saved.receipt);
        let selection = ModeSelection {
            scope: request.scope.clone(),
            selected_mode: PermissionMode::RiskBased,
            preset_version: PresetVersion::V1,
            authorization_revision: 1,
            expires_at_unix_ms: request.expires_at_unix_ms,
        };
        assert_eq!(receipt.selection, selection);
        assert_eq!(
            store
                .load_permission_mode_selection(&request.scope, &request.scope.principal_id,)
                .unwrap(),
            selection
        );
        diagnostics(&store, &request, &saved.challenge, (2, 2));
        // Idempotent begin, not commit retry or proof reconstruction.
        assert_eq!(
            store
                .begin_permission_mode_confirmation_v2(request.clone(), &authority,)
                .unwrap(),
            Status::Committed(receipt.clone())
        );
        assert_eq!(status(), Some(Status::Committed(receipt)));
        assert_eq!(
            store
                .load_permission_mode_selection(&request.scope, &request.scope.principal_id,)
                .unwrap(),
            selection
        );
        diagnostics(&store, &request, &saved.challenge, (2, 2));
    }
    assert_eq!(trust.load(project).unwrap(), original);
    saved.recovered_pid = Some(std::process::id());
    metadata::write(root, "result.json", &saved);
}
