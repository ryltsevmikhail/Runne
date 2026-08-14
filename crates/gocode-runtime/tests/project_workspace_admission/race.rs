use super::*;

#[tokio::test]
async fn root_admission_nonce_race_has_one_winner_and_no_partial_loser() {
    let (_directory, store) = store();
    let workspace = WORKSPACE.parse().unwrap();
    create_workspace(store.clone(), workspace).await;
    let one = host(
        store.clone(),
        admission_context(),
        claims(admission_context(), workspace, 31, 200),
    );
    let two = host(
        store.clone(),
        admission_context(),
        claims(admission_context(), workspace, 31, 200),
    );
    let one_request = BindWorkspaceRootCommand {
        workspace_id: workspace,
        expected_version: 1,
        root_admission: gocode_api::test_support::admission(),
    };
    let two_request = BindWorkspaceRootCommand {
        workspace_id: workspace,
        expected_version: 1,
        root_admission: gocode_api::test_support::admission(),
    };
    let (first, second) = tokio::join!(
        one.bind_workspace_root(command("owner", 31), one_request),
        two.bind_workspace_root(command("owner", 32), two_request)
    );
    assert_eq!(
        [first.is_ok(), second.is_ok()]
            .into_iter()
            .filter(|value| *value)
            .count(),
        1
    );
    let query = host(
        store,
        admission_context(),
        claims(admission_context(), workspace, 90, 200),
    );
    assert_eq!(
        query
            .get_workspace(
                ProjectQueryContext {
                    principal: ApiPrincipalId::new("owner").unwrap(),
                },
                workspace,
            )
            .await
            .unwrap()
            .version,
        2
    );
}
