use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::{
    AppCore, AppCoreError, MAX_CANONICAL_PROJECT_PAGES, MAX_CANONICAL_WORKSPACE_PAGES,
    PROJECT_PAGE_LIMIT,
};

const PAGE_TEST_PROJECT: &str = "01890e00-0000-7000-8000-000000000001";

fn page_test_client(origin: &str) -> runne_runtime_client::AuthenticatedRuntimeClient {
    runne_runtime_client::mock_authenticated_runtime_client(
        origin,
        runne_runtime_client::RuntimeSessionInfo {
            profile_id: "gocode-ui-client/2".into(),
            schema_hash: runne_runtime_client::GOLDEN_BUNDLE_HASH.into(),
            runtime_version: "test".into(),
            capabilities: runne_runtime_client::REQUIRED_RUNTIME_CAPABILITIES
                .iter()
                .map(ToString::to_string)
                .collect(),
            authority_id: "authority".into(),
            principal_id: "principal".into(),
            event_log_lineage_id: "lineage".into(),
            daemon_instance_id: "daemon".into(),
            launch_generation: 1,
            session_id: "session".into(),
            authorization_epoch: 1,
            sensitivity_ceiling: "sensitive".into(),
            certificate_sha256: "11".repeat(32),
            capability_digest: "22".repeat(32),
        },
    )
    .expect("mock client")
}

async fn page_test_server(listener: TcpListener, bodies: Vec<String>) -> Vec<String> {
    let mut requests = Vec::new();
    for body in bodies {
        let (mut stream, _) = listener.accept().await.expect("request");
        let mut bytes = [0; 8192];
        let count = stream.read(&mut bytes).await.expect("read request");
        requests.push(String::from_utf8_lossy(&bytes[..count]).into_owned());
        let response = format!(
            "HTTP/1.1 200 test\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.expect("response");
    }
    requests
}

fn page_ids(first: u16, count: u16) -> Vec<String> {
    (first..first + count)
        .map(|index| format!("01890e00-0000-7000-8000-{index:012x}"))
        .collect()
}

fn project_page(ids: &[String], next_cursor: Option<&str>) -> String {
    let items = ids
        .iter()
        .map(|id| format!(r#"{{"projectId":"{id}","displayName":"Project {id}","version":1,"archived":false}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let next = next_cursor.map_or_else(|| "null".to_owned(), |value| format!(r#""{value}""#));
    format!(r#"{{"items":[{items}],"nextCursor":{next}}}"#)
}

fn workspace_page(project_id: &str, ids: &[String], next_cursor: Option<&str>) -> String {
    let items = ids
        .iter()
        .map(|id| format!(r#"{{"workspaceId":"{id}","projectId":"{project_id}","displayName":"Workspace {id}","version":1,"open":true}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let next = next_cursor.map_or_else(|| "null".to_owned(), |value| format!(r#""{value}""#));
    format!(r#"{{"items":[{items}],"nextCursor":{next}}}"#)
}

fn project_cursor(last_id: &str) -> String {
    runne_api::ProjectPageCursor::new(
        runne_api::ApiPrincipalId::new("principal").expect("principal"),
        last_id.parse().expect("project id"),
    )
    .expect("cursor")
    .encode_token()
}

fn workspace_cursor(project_id: &str, last_id: &str) -> String {
    runne_api::WorkspacePageCursor::new(
        runne_api::ApiPrincipalId::new("principal").expect("principal"),
        project_id.parse().expect("project id"),
        last_id.parse().expect("workspace id"),
    )
    .expect("cursor")
    .encode_token()
}

#[tokio::test]
async fn canonical_project_list_traverses_typed_opaque_continuations() {
    let first = page_ids(1, PROJECT_PAGE_LIMIT);
    let second = page_ids(101, 1);
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let server = tokio::spawn(page_test_server(
        listener,
        vec![
            project_page(&first, Some(&project_cursor(first.last().expect("last project")))),
            project_page(&second, None),
        ],
    ));
    let directory = tempfile::tempdir().expect("directory");
    let core = AppCore::open_with_mock_runtime(
        &directory.path().join("profile.sqlite3"),
        page_test_client(&origin),
    )
    .expect("core");

    let projects = core.list_canonical_projects().await.expect("projects");
    let requests = server.await.expect("server");

    assert_eq!(projects.len(), 101);
    assert_eq!(projects.last().expect("last project").project_id, second[0]);
    assert_eq!(requests.len(), 2);
    assert!(requests[1].contains("cursor="));
}

#[tokio::test]
async fn canonical_project_details_traverses_typed_workspace_continuations() {
    let first = page_ids(201, PROJECT_PAGE_LIMIT);
    let second = page_ids(301, 1);
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let server = tokio::spawn(page_test_server(
        listener,
        vec![
            format!(r#"{{"projectId":"{PAGE_TEST_PROJECT}","displayName":"Project","version":1,"archived":false}}"#),
            workspace_page(
                PAGE_TEST_PROJECT,
                &first,
                Some(&workspace_cursor(PAGE_TEST_PROJECT, first.last().expect("last workspace"))),
            ),
            workspace_page(PAGE_TEST_PROJECT, &second, None),
        ],
    ));
    let directory = tempfile::tempdir().expect("directory");
    let core = AppCore::open_with_mock_runtime(
        &directory.path().join("profile.sqlite3"),
        page_test_client(&origin),
    )
    .expect("core");

    let details = core
        .get_canonical_project(PAGE_TEST_PROJECT)
        .await
        .expect("details");
    let requests = server.await.expect("server");

    assert_eq!(details.workspaces.len(), 101);
    assert_eq!(details.workspaces.last().expect("last workspace").workspace_id, second[0]);
    assert_eq!(requests.len(), 3);
    assert!(requests[2].contains("cursor="));
}

#[tokio::test]
async fn canonical_project_list_fails_closed_when_the_page_bound_is_exhausted() {
    let page = page_ids(401, PROJECT_PAGE_LIMIT);
    let response = project_page(&page, Some(&project_cursor(page.last().expect("last project"))));
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let server = tokio::spawn(page_test_server(
        listener,
        (0..MAX_CANONICAL_PROJECT_PAGES).map(|_| response.clone()).collect(),
    ));
    let directory = tempfile::tempdir().expect("directory");
    let core = AppCore::open_with_mock_runtime(
        &directory.path().join("profile.sqlite3"),
        page_test_client(&origin),
    )
    .expect("core");

    assert!(matches!(
        core.list_canonical_projects().await,
        Err(AppCoreError::RuntimeUnavailable)
    ));
    assert_eq!(server.await.expect("server").len(), MAX_CANONICAL_PROJECT_PAGES);
}

#[tokio::test]
async fn canonical_workspace_list_fails_closed_when_the_page_bound_is_exhausted() {
    let page = page_ids(501, PROJECT_PAGE_LIMIT);
    let response = workspace_page(
        PAGE_TEST_PROJECT,
        &page,
        Some(&workspace_cursor(PAGE_TEST_PROJECT, page.last().expect("last workspace"))),
    );
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let mut responses = vec![format!(
        r#"{{"projectId":"{PAGE_TEST_PROJECT}","displayName":"Project","version":1,"archived":false}}"#
    )];
    responses.extend((0..MAX_CANONICAL_WORKSPACE_PAGES).map(|_| response.clone()));
    let server = tokio::spawn(page_test_server(listener, responses));
    let directory = tempfile::tempdir().expect("directory");
    let core = AppCore::open_with_mock_runtime(
        &directory.path().join("profile.sqlite3"),
        page_test_client(&origin),
    )
    .expect("core");

    assert!(matches!(
        core.get_canonical_project(PAGE_TEST_PROJECT).await,
        Err(AppCoreError::RuntimeUnavailable)
    ));
    assert_eq!(
        server.await.expect("server").len(),
        MAX_CANONICAL_WORKSPACE_PAGES + 1
    );
}
