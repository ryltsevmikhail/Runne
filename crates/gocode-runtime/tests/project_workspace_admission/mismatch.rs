use super::*;

#[tokio::test]
async fn root_admission_rejects_every_stale_or_mismatched_binding() {
    let (_directory, store) = store();
    let workspace = WORKSPACE.parse().unwrap();
    create_workspace(store.clone(), workspace).await;
    let current = admission_context();
    assert!(
        RootAdmissionVerificationContext::new(
            [1; 32],
            [2; 16],
            1,
            current.principal_digest(),
            2,
            1,
            100,
        )
        .is_err()
    );
    let contexts = [
        RootAdmissionVerificationContext::new(
            [8; 32],
            [2; 16],
            1,
            current.principal_digest(),
            3,
            1,
            100,
        )
        .unwrap(),
        RootAdmissionVerificationContext::new(
            [1; 32],
            [8; 16],
            1,
            current.principal_digest(),
            3,
            1,
            100,
        )
        .unwrap(),
        RootAdmissionVerificationContext::new(
            [1; 32],
            [2; 16],
            2,
            current.principal_digest(),
            3,
            1,
            100,
        )
        .unwrap(),
        RootAdmissionVerificationContext::new(
            [1; 32],
            [2; 16],
            1,
            current.principal_digest(),
            3,
            2,
            100,
        )
        .unwrap(),
        RootAdmissionVerificationContext::new(
            [1; 32],
            [2; 16],
            1,
            current.principal_digest(),
            3,
            1,
            101,
        )
        .unwrap(),
    ];
    for (index, claim_context) in contexts.into_iter().enumerate() {
        let host = host(
            store.clone(),
            current.clone(),
            claims(claim_context, workspace, index as u8 + 10, 200),
        );
        let request = BindWorkspaceRootCommand {
            workspace_id: workspace,
            expected_version: 1,
            root_admission: gocode_api::test_support::admission(),
        };
        assert_eq!(
            host.bind_workspace_root(command("owner", index as u8 + 10), request)
                .await,
            Err(ProjectWorkspaceHostError::Forbidden)
        );
    }
    let expired = host(
        store.clone(),
        current.clone(),
        claims(current.clone(), workspace, 20, 100),
    );
    let request = BindWorkspaceRootCommand {
        workspace_id: workspace,
        expected_version: 1,
        root_admission: gocode_api::test_support::admission(),
    };
    assert_eq!(
        expired
            .bind_workspace_root(command("owner", 20), request)
            .await,
        Err(ProjectWorkspaceHostError::Forbidden)
    );
    let wrong_principal = host(
        store.clone(),
        current.clone(),
        claims(current, workspace, 21, 200),
    );
    let request = BindWorkspaceRootCommand {
        workspace_id: workspace,
        expected_version: 1,
        root_admission: gocode_api::test_support::admission(),
    };
    assert_eq!(
        wrong_principal
            .bind_workspace_root(command("other", 21), request)
            .await,
        Err(ProjectWorkspaceHostError::NotFound)
    );
    let wrong_workspace = WorkspaceId::from_bytes([0x71; 16]);
    let foreign_claim = host(
        store.clone(),
        admission_context(),
        gocode_api::test_support::claims(
            admission_context(),
            wrong_workspace,
            22,
            [22; 16],
            200,
            [22; 32],
        ),
    );
    let request = BindWorkspaceRootCommand {
        workspace_id: workspace,
        expected_version: 1,
        root_admission: gocode_api::test_support::admission(),
    };
    assert_eq!(
        foreign_claim
            .bind_workspace_root(command("owner", 22), request)
            .await,
        Err(ProjectWorkspaceHostError::Forbidden)
    );
    let wrong_version = host(
        store,
        admission_context(),
        claims(admission_context(), workspace, 23, 200),
    );
    let request = BindWorkspaceRootCommand {
        workspace_id: workspace,
        expected_version: 2,
        root_admission: gocode_api::test_support::admission(),
    };
    assert_eq!(
        wrong_version
            .bind_workspace_root(command("owner", 23), request)
            .await,
        Err(ProjectWorkspaceHostError::Forbidden)
    );
}
