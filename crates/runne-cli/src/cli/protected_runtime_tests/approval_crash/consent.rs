use super::*;

struct ApprovalCrashConsent;

struct ApprovalCrashToken {
    digest: [u8; 32],
    expires_at: i64,
}

impl super::super::ApprovalConsent for ApprovalCrashConsent {
    type Token = ApprovalCrashToken;

    fn present(
        &self,
        _: &super::super::ApprovalResponseIntent,
        approval: &super::super::ApprovalSnapshot,
        digest: [u8; 32],
    ) -> Result<Self::Token, super::super::ApprovalConfirmationError> {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(std::env::var_os("RUNNE_CLI_MOCK_APPROVAL_LOG").expect("mock consent log"))
            .expect("open mock approval consent log")
            .write_all(b"mock-approval-consent\n")
            .expect("record mock approval consent");
        Ok(ApprovalCrashToken {
            digest,
            expires_at: approval.expires_at,
        })
    }

    fn consume(&self, token: Self::Token, digest: [u8; 32], expires_at: i64) -> bool {
        token.digest == digest
            && token.expires_at == expires_at
            && expires_at > super::super::unix_millis().unwrap_or(i64::MAX)
    }
}

#[expect(
    clippy::future_not_send,
    reason = "the CLI approval confirmation runs inline on its owner thread"
)]
pub async fn execute_with_mock_consent<
    R: super::super::ApprovalResponseRuntime,
    I: super::super::PermissionRecoveryIndex,
>(
    runtime: &R,
    intent: super::super::ApprovalResponseIntent,
    index: &I,
) -> Result<super::super::CommandOutput, super::super::CliError> {
    assert_eq!(
        std::env::var("RUNNE_CLI_MOCK_APPROVAL_CONSENT").as_deref(),
        Ok("approval-crash-fixture"),
        "mock consent is opt-in only in the approval fixture child"
    );
    super::super::execute_approval_response_with_consent(
        runtime,
        intent,
        index,
        &ApprovalCrashConsent,
    )
    .await
}

pub(super) struct SeededApproval {
    pub(super) approval_id: ApprovalId,
    pub(super) task_run_id: TaskRunId,
    pub(super) command_id: String,
    pub(super) idempotency_key: String,
}

pub(super) fn store(fixture: &Fixture, authority_id: &str) -> ProjectWorkspaceStore {
    let path = fixture.root.join("runne-daemon/event-log.db");
    assert!(path.is_file(), "use the existing protected owner database");
    let authority = authority_id.replace('-', "").to_ascii_lowercase();
    assert_eq!(authority.len(), 32, "runtime authority is a UUID");
    assert!(authority.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let guard = std::sync::Arc::new(runne_security::SecretBroker::new().prohibited_content_guard());
    let store = runne_store::store::StoreTransaction::open(
        path.to_str().expect("fixture database path"),
        RuntimeAuthorityId(authority),
        guard,
    )
    .expect("open actual protected daemon Store after owner stop");
    ProjectWorkspaceStore::from_store(store)
}

pub(super) fn seed_approval(fixture: &Fixture, authority_id: &str) -> SeededApproval {
    let approval_id = ApprovalId::from_bytes(*uuid::Uuid::now_v7().as_bytes());
    let task_run_id = TaskRunId::from_bytes(*uuid::Uuid::now_v7().as_bytes());
    let invocation_id = InvocationId::from_bytes(*uuid::Uuid::now_v7().as_bytes());
    let command_id = CanonicalId::now_v7().to_string();
    let idempotency_key = format!("approval-crash-{command_id}");
    let command = runne_api::ApprovalCreateCommand::new(
        approval_id,
        task_run_id,
        None,
        invocation_id,
        runne_api::ApiPrincipalId::new("local-owner").expect("owner principal"),
        "execute",
        "workspace",
        [0x42; 32],
        7,
        3,
        i64::MAX,
        "requires approval",
    )
    .expect("valid pending approval fixture");
    let repository = store(fixture, authority_id);
    let runtime = tokio::runtime::Runtime::new().expect("approval seed runtime");
    let summary = runtime
        .block_on(runne_api::ApprovalRequestHostPort::create_pending_approval(
            &repository,
            command,
        ))
        .expect("seed approval through public Store API");
    assert_eq!(summary.approval_id(), approval_id);
    assert_eq!(summary.task_run_id(), task_run_id);
    assert_eq!(summary.state(), runne_api::ApprovalState::Pending);
    assert_eq!(summary.request_version(), 1);
    drop(repository);
    SeededApproval {
        approval_id,
        task_run_id,
        command_id,
        idempotency_key,
    }
}
