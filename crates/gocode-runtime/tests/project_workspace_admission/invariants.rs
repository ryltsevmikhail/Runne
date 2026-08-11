use super::*;

async fn bind(
    store: StoreTransaction,
    authority: barrier::MutableAuthority,
    keys: &gocode_api::ProtectedActivationKeys,
    workspace: WorkspaceId,
    command_value: u8,
    nonce: u8,
    digest: u8,
) -> Result<gocode_api::WorkspaceCommandAck, ProjectWorkspaceHostError> {
    let admission = barrier::issue(keys, admission_context(), workspace, nonce, 200, digest);
    barrier::authenticated_host(store, authority, keys, None)
        .bind_workspace_root(
            command("owner", command_value),
            BindWorkspaceRootCommand {
                workspace_id: workspace,
                expected_version: 1,
                root_admission: admission,
            },
        )
        .await
}

#[tokio::test]
async fn duplicate_nonce_for_a_different_workspace_rolls_back_all_three_admission_tables() {
    let (directory, store) = store();
    let path = directory.path().join("admission.sqlite");
    let first: WorkspaceId = WORKSPACE.parse().unwrap();
    let second = WorkspaceId::from_bytes([0x42; 16]);
    create_workspace(store.clone(), first).await;
    let keys = barrier::keys();
    let authority = barrier::MutableAuthority::new(admission_context());
    barrier::authenticated_host(store.clone(), authority.clone(), &keys, None)
        .create_workspace(
            command("owner", 41),
            CreateWorkspaceCommand {
                workspace_id: second,
                project_id: PROJECT.parse().unwrap(),
                display_name: "Other".into(),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        bind(store.clone(), authority.clone(), &keys, first, 42, 42, 52)
            .await
            .unwrap()
            .new_version,
        2
    );
    let before = barrier::database_state(&path);
    assert_eq!(
        bind(store, authority, &keys, second, 43, 42, 53).await,
        Err(ProjectWorkspaceHostError::Conflict)
    );
    assert_eq!(barrier::database_state(&path), before);
}

#[tokio::test]
async fn changed_admission_digest_for_the_same_command_is_not_an_exact_retry() {
    let (directory, store) = store();
    let path = directory.path().join("admission.sqlite");
    let workspace = WORKSPACE.parse().unwrap();
    create_workspace(store.clone(), workspace).await;
    let keys = barrier::keys();
    let authority = barrier::MutableAuthority::new(admission_context());
    assert_eq!(
        bind(
            store.clone(),
            authority.clone(),
            &keys,
            workspace,
            51,
            51,
            61
        )
        .await
        .unwrap()
        .new_version,
        2
    );
    let before = barrier::database_state(&path);
    assert_eq!(
        bind(store, authority, &keys, workspace, 51, 52, 62).await,
        Err(ProjectWorkspaceHostError::Conflict)
    );
    assert_eq!(barrier::database_state(&path), before);
}

#[tokio::test]
async fn exact_admission_retry_replays_without_consuming_the_nonce_again() {
    let (directory, store) = store();
    let path = directory.path().join("admission.sqlite");
    let workspace = WORKSPACE.parse().unwrap();
    create_workspace(store.clone(), workspace).await;
    let keys = barrier::keys();
    let authority = barrier::MutableAuthority::new(admission_context());
    assert_eq!(
        bind(
            store.clone(),
            authority.clone(),
            &keys,
            workspace,
            61,
            61,
            71
        )
        .await
        .unwrap()
        .new_version,
        2
    );
    let before = barrier::database_state(&path);
    assert_eq!(
        bind(store, authority, &keys, workspace, 61, 61, 71)
            .await
            .unwrap()
            .new_version,
        2
    );
    assert_eq!(barrier::database_state(&path), before);
}
