#[path = "task_run_read_support/mod.rs"]
mod support;

use runne_runtime_client::{CanonicalId, RuntimeApiErrorKind, mock_authenticated_runtime_client};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

/// The error binding is statically `RuntimeApiError` (never
/// `RuntimeTransportError`): read-method transport failures are mapped into
/// the canonical taxonomy with no correlation identity.
#[tokio::test]
async fn task_run_read_get_connection_refused_yields_unavailable() {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    drop(listener);
    let client = mock_authenticated_runtime_client(&origin, support::session()).expect("client");
    let task_run_id = CanonicalId::parse(support::TASK_RUN_ID).expect("task run ID");

    let error = client.get_task_run(task_run_id).await.expect_err("refused");
    assert_eq!(error.kind(), RuntimeApiErrorKind::Unavailable);
    assert_eq!(error.request_id(), None);
}

#[tokio::test]
async fn task_run_read_list_connection_refused_yields_unavailable() {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    drop(listener);
    let client = mock_authenticated_runtime_client(&origin, support::session()).expect("client");

    let error = client.list_task_runs().await.expect_err("refused");
    assert_eq!(error.kind(), RuntimeApiErrorKind::Unavailable);
    assert_eq!(error.request_id(), None);
}

#[tokio::test]
async fn task_run_read_server_close_without_response_yields_unavailable() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut buffer = [0_u8; 1024];
        let _ = stream.read(&mut buffer).await;
        drop(stream);
    });
    let client = mock_authenticated_runtime_client(&origin, support::session()).expect("client");
    let task_run_id = CanonicalId::parse(support::TASK_RUN_ID).expect("task run ID");

    let error = client
        .get_task_run(task_run_id)
        .await
        .expect_err("closed connection");
    assert_eq!(error.kind(), RuntimeApiErrorKind::Unavailable);
    assert_eq!(error.request_id(), None);
}
