use super::*;

pub(super) fn start_text_only_runtime(
    executable: &std::path::Path,
    runtime_root: &std::path::Path,
    session_bus_socket: &std::path::Path,
) -> ProtectedBundledRuntimeSupervisor {
    let spec = ProtectedBundledRuntimeLaunchSpec::new(executable, runtime_root)
        .expect("TextOnly protected launch spec")
        .with_openai_provider_activation()
        .with_validated_session_bus_address(session_bus_socket)
        .expect("fixture session bus address");
    let mut supervisor =
        ProtectedBundledRuntimeSupervisor::new(DevelopmentBundledRuntimeLauncher::new(), spec);
    supervisor
        .start()
        .expect("start protected TextOnly runtime");
    supervisor
}

pub(super) async fn install_text_only_client(
    supervisor: &mut ProtectedBundledRuntimeSupervisor,
) -> runne_runtime_client::AuthenticatedRuntimeClient {
    let client = supervisor
        .take_runtime_profile()
        .expect("protected runtime profile")
        .connect(Duration::from_secs(10))
        .await
        .expect("authenticated runtime client");
    supervisor
        .record_client_ready(&client)
        .expect("record protected readiness");
    client
}

pub(super) fn assert_text_only_scope(
    database: &std::path::Path,
    conversation: runne_runtime_client::CanonicalId,
) {
    let connection = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("read TextOnly scope");
    let conversation_bytes = hex::decode(conversation.to_string().replace('-', ""))
        .expect("canonical conversation bytes");
    let scope: String = connection
        .query_row(
            "SELECT context_scope FROM conversation_context_scope WHERE conversation_id = ?1",
            [conversation_bytes],
            |row| row.get(0),
        )
        .expect("durable context-scope row");
    assert_eq!(scope, "text_only");
}

pub(super) fn assert_no_project_trust_grants(database: &std::path::Path) {
    let mut sidecar_name = database.as_os_str().to_owned();
    sidecar_name.push(".project-trust");
    let sidecar = std::path::PathBuf::from(sidecar_name);
    if !sidecar.exists() {
        return;
    }
    let connection = rusqlite::Connection::open_with_flags(
        sidecar,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("read trust sidecar");
    let grants: i64 = connection
        .query_row("SELECT COUNT(*) FROM project_trust", [], |row| row.get(0))
        .expect("trust grant count");
    assert_eq!(grants, 0, "TextOnly workflow must not create project trust");
}

pub(super) fn assert_fixture_response(messages: &[runne_app_core::ConversationMessageSummary]) {
    assert!(
        messages
            .iter()
            .any(|message| message.role == "assistant" && message.text == "fixture response")
    );
}

pub(super) fn assert_wire_receipt(path: &std::path::Path) {
    let receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).expect("wire receipt"))
            .expect("safe wire receipt");
    assert_eq!(receipt["requestCanaryFree"], true);
    assert_eq!(receipt["responseCanaryFree"], true);
    assert_eq!(receipt["responseSent"], true);
    assert!(receipt["requestByteCount"].as_u64().unwrap_or_default() > 0);
    assert!(receipt["responseByteCount"].as_u64().unwrap_or_default() > 0);
}
