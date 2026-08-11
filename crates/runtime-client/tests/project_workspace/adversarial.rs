use std::collections::BTreeMap;

use super::*;

const PROJECT: &str = "018f2e3a-7000-7000-8000-000000000302";
const WORKSPACE: &str = "018f2e3a-7000-7000-8000-000000000304";
const WRONG: &str = "018f2e3a-7000-7000-8000-000000000303";

async fn exact_server(
    listener: TcpListener,
    requests: usize,
    cursor_mode: bool,
) -> BTreeMap<String, usize> {
    let mut branches = BTreeMap::new();
    for _ in 0..requests {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = [0; 8192];
        let count = stream.read(&mut bytes).await.unwrap();
        let first = String::from_utf8_lossy(&bytes[..count])
            .lines()
            .next()
            .unwrap()
            .to_owned();
        let mut parts = first.split_ascii_whitespace();
        let method = parts.next().unwrap();
        let target = parts.next().unwrap();
        let path = target.split('?').next().unwrap();
        let branch = format!("{method} {path}");
        *branches.entry(branch.clone()).or_insert(0) += 1;
        let (status, body) = response(&branch, cursor_mode);
        let response = format!(
            "HTTP/1.1 {status} test\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    }
    branches
}

fn response(branch: &str, cursor_mode: bool) -> (u16, String) {
    if cursor_mode {
        let token = if branch == "GET /v1/projects" {
            format!("gocode-project-page-v1.{}", "0".repeat(96))
        } else {
            let project = PROJECT.replace('-', "");
            format!(
                "gocode-workspace-page-v1.{}{project}{}",
                "0".repeat(64),
                "0".repeat(32)
            )
        };
        return (200, format!(r#"{{"items":[],"nextCursor":"{token}"}}"#));
    }
    let body = match branch {
        "GET /v1/projects/018f2e3a-7000-7000-8000-000000000302" => format!(
            r#"{{"projectId":"{WRONG}","displayName":"name","version":1,"archived":false}}"#
        ),
        "GET /v1/workspaces/018f2e3a-7000-7000-8000-000000000304" => format!(
            r#"{{"workspaceId":"{WRONG}","projectId":"{PROJECT}","displayName":"name","version":1,"open":false}}"#
        ),
        "GET /v1/projects/018f2e3a-7000-7000-8000-000000000302/workspaces" => format!(
            r#"{{"items":[{{"workspaceId":"{WORKSPACE}","projectId":"{WRONG}","displayName":"name","version":1,"open":false}}],"nextCursor":null}}"#
        ),
        "POST /v1/projects"
        | "POST /v1/projects/018f2e3a-7000-7000-8000-000000000302/archive"
        | "POST /v1/projects/018f2e3a-7000-7000-8000-000000000302/restore"
        | "DELETE /v1/projects/018f2e3a-7000-7000-8000-000000000302" => {
            format!(r#"{{"projectId":"{WRONG}","newVersion":2}}"#)
        }
        "POST /v1/projects/018f2e3a-7000-7000-8000-000000000302/workspaces"
        | "POST /v1/workspaces/018f2e3a-7000-7000-8000-000000000304/open"
        | "POST /v1/workspaces/018f2e3a-7000-7000-8000-000000000304/root-bindings" => {
            format!(r#"{{"workspaceId":"{WRONG}","newVersion":2}}"#)
        }
        _ => panic!("unexpected request branch: {branch}"),
    };
    (if branch.starts_with("GET ") { 200 } else { 202 }, body)
}

fn assert_invalid(result: Result<(), gocode_runtime_client::RuntimeApiError>) {
    assert_eq!(
        result.unwrap_err().kind(),
        RuntimeApiErrorKind::InvalidResponse
    );
}

#[tokio::test]
async fn exact_project_workspace_branches_reject_only_identity_mismatches() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(exact_server(listener, 10, false));
    let client = mock_authenticated_runtime_client(&origin, session()).unwrap();
    let project = id();
    let workspace = CanonicalId::parse(WORKSPACE).unwrap();
    let command = identity();

    assert_invalid(client.get_project(project).await.map(|_| ()));
    assert_invalid(client.get_workspace(workspace).await.map(|_| ()));
    assert_invalid(client.list_workspaces(project, 1, None).await.map(|_| ()));
    assert_invalid(
        client
            .create_project(CreateProjectRequest::new(command.clone(), project, "name").unwrap())
            .await
            .map(|_| ()),
    );
    assert_invalid(
        client
            .archive_project(ExistingProjectRequest::new(command.clone(), project, 1).unwrap())
            .await
            .map(|_| ()),
    );
    assert_invalid(
        client
            .restore_project(ExistingProjectRequest::new(command.clone(), project, 1).unwrap())
            .await
            .map(|_| ()),
    );
    assert_invalid(
        client
            .delete_project(ExistingProjectRequest::new(command.clone(), project, 1).unwrap())
            .await
            .map(|_| ()),
    );
    assert_invalid(
        client
            .create_workspace(
                CreateWorkspaceRequest::new(command.clone(), project, workspace, "name").unwrap(),
            )
            .await
            .map(|_| ()),
    );
    assert_invalid(
        client
            .open_workspace(ExistingWorkspaceRequest::new(command.clone(), workspace, 1).unwrap())
            .await
            .map(|_| ()),
    );
    assert_invalid(
        client
            .bind_workspace_root(
                BindWorkspaceRootRequest::new(
                    command,
                    workspace,
                    1,
                    RootAdmissionToken::parse("gocode-root-admission-v2.AA").unwrap(),
                )
                .unwrap(),
            )
            .await
            .map(|_| ()),
    );

    let branches = server.await.unwrap();
    assert_eq!(branches.len(), 10);
    assert!(branches.values().all(|count| *count == 1));
}

#[tokio::test]
async fn page_responses_reject_lower_hex_cursors_with_non_uuidv7_payloads() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(exact_server(listener, 2, true));
    let client = mock_authenticated_runtime_client(&origin, session()).unwrap();

    assert_invalid(client.list_projects(1, None).await.map(|_| ()));
    assert_invalid(client.list_workspaces(id(), 1, None).await.map(|_| ()));

    let branches = server.await.unwrap();
    assert_eq!(branches.get("GET /v1/projects"), Some(&1));
    assert_eq!(
        branches.get("GET /v1/projects/018f2e3a-7000-7000-8000-000000000302/workspaces"),
        Some(&1)
    );
}
