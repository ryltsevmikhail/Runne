pub(super) async fn open_if_closed(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    workspace_id: runne_runtime_client::CanonicalId,
    is_open: bool,
    version: u64,
) {
    if is_open {
        return;
    }
    let identity = runne_runtime_client::CommandIdentity::new(
        runne_runtime_client::CanonicalId::now_v7(),
        format!("t1-open-{}", runne_runtime_client::CanonicalId::now_v7()),
    )
    .expect("open command identity");
    client
        .open_workspace(
            runne_runtime_client::ExistingWorkspaceRequest::new(identity, workspace_id, version)
                .expect("open request"),
        )
        .await
        .expect("open bound workspace");
}
