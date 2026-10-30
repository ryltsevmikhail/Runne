//! Exact current admitted identity; verified rebind replaces the prior root map.
use super::*;
use rusqlite::Transaction;

pub(super) fn bind(
    tx: &Transaction<'_>,
    store: &StoreTransaction,
    principal: &str,
    workspace: WorkspaceId,
    version: u64,
    digest: [u8; 32],
) -> Result<(), Error> {
    if digest == [0; 32] {
        return Err(Error::Forbidden);
    }
    let changed = tx.execute(
        "INSERT INTO workspace_root_identities
         (runtime_authority_id, principal_id, workspace_id, filesystem_identity_digest, root_version)
         VALUES (?1,?2,?3,?4,?5)
         ON CONFLICT(runtime_authority_id, principal_id, workspace_id)
         DO UPDATE SET filesystem_identity_digest=excluded.filesystem_identity_digest,
                       root_version=excluded.root_version
         WHERE workspace_root_identities.root_version < excluded.root_version",
        params![store.runtime_authority_id().0, principal, workspace.as_bytes(), digest, version as i64],
    ).map_err(|_| Error::Conflict)?;
    if changed != 1 {
        return Err(Error::Conflict);
    }
    Ok(())
}

pub(super) fn find(
    store: &StoreTransaction,
    principal: &str,
    digest: [u8; 32],
) -> Result<Option<Workspace>, Error> {
    if digest == [0; 32] {
        return Err(Error::Forbidden);
    }
    store.with_project_workspace_reader(|connection| {
        let mut query = connection
            .prepare(
                "SELECT w.workspace_id, w.project_id, w.display_name, w.version, w.open
             FROM workspace_root_identities r JOIN workspaces w ON w.workspace_id=r.workspace_id
             JOIN projects p ON p.project_id=w.project_id
             WHERE r.runtime_authority_id=?1 AND r.principal_id=?2
               AND r.filesystem_identity_digest=?3 AND w.principal_id=?2 AND p.principal_id=?2
               AND w.live=1 AND p.archived=0 LIMIT 2",
            )
            .map_err(|_| Error::Unavailable)?;
        let mut values = query
            .query_map(
                params![store.runtime_authority_id().0, principal, digest],
                super::records::workspace_from_row,
            )
            .map_err(|_| Error::Unavailable)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::InvariantViolation)?;
        if values.len() > 1 {
            return Err(Error::Conflict);
        }
        Ok(values.pop())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use runne_application::ports::RuntimeAuthorityId;
    use runne_domain::project_workspace::ProjectWorkspaceDisplayName;
    use std::sync::Arc;

    #[test]
    fn verified_rebind_replaces_exact_lookup_and_rejects_stale_or_collision() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("runtime");
        std::fs::create_dir(&root).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = StoreTransaction::open(
            &root.join("event-log.db").to_string_lossy(),
            RuntimeAuthorityId("11".repeat(16)),
            Arc::new(runne_security::SecretBroker::new().prohibited_content_guard()),
        )
        .unwrap();
        let repository = ProjectWorkspaceStore::from_store(store.clone());
        let project = ProjectId::from_bytes(*uuid::Uuid::now_v7().as_bytes());
        let workspace = WorkspaceId::from_bytes(*uuid::Uuid::now_v7().as_bytes());
        let command = || CommandId::from_bytes(*uuid::Uuid::now_v7().as_bytes());
        repository
            .create_project(
                "owner",
                command(),
                &IdempotencyKey::new("project").unwrap(),
                Project::create(
                    project,
                    ProjectWorkspaceDisplayName::new("Project".into()).unwrap(),
                ),
            )
            .unwrap();
        repository
            .create_workspace(
                "owner",
                command(),
                &IdempotencyKey::new("workspace").unwrap(),
                Workspace::create(
                    workspace,
                    project,
                    ProjectWorkspaceDisplayName::new("Workspace".into()).unwrap(),
                ),
            )
            .unwrap();
        store
            .with_project_workspace_transaction(|tx| {
                bind(tx, &store, "owner", workspace, 2, [7; 32])
            })
            .unwrap();
        assert_eq!(
            find(&store, "owner", [7; 32]).unwrap().unwrap().id(),
            workspace
        );
        assert!(find(&store, "other", [7; 32]).unwrap().is_none());
        assert!(find(&store, "owner", [8; 32]).unwrap().is_none());
        store
            .with_project_workspace_transaction(|tx| {
                bind(tx, &store, "owner", workspace, 3, [8; 32])
            })
            .unwrap();
        assert!(find(&store, "owner", [7; 32]).unwrap().is_none());
        assert_eq!(
            find(&store, "owner", [8; 32]).unwrap().unwrap().id(),
            workspace
        );
        assert!(
            store
                .with_project_workspace_transaction(|tx| bind(
                    tx, &store, "owner", workspace, 3, [7; 32]
                ))
                .is_err()
        );
        store
            .with_project_workspace_transaction(|tx| {
                bind(tx, &store, "owner", workspace, 4, [7; 32])
            })
            .unwrap();
        let second = WorkspaceId::from_bytes(*uuid::Uuid::now_v7().as_bytes());
        repository
            .create_workspace(
                "owner",
                command(),
                &IdempotencyKey::new("second").unwrap(),
                Workspace::create(
                    second,
                    project,
                    ProjectWorkspaceDisplayName::new("Second".into()).unwrap(),
                ),
            )
            .unwrap();
        assert!(
            store
                .with_project_workspace_transaction(|tx| bind(
                    tx, &store, "owner", second, 2, [7; 32]
                ))
                .is_err()
        );
    }
}
