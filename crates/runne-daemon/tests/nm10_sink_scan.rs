//! NM-10 §C-E sink scans at the daemon composition level (export, backup,
//! conversation mutation): registered material never traverses a sink.

use std::io::Cursor;
use std::sync::Arc;

use runne_api::{ConversationContextScope, CreateConversationInput};
use runne_application::commands::{BeginConversationTextInput, FinishConversationTextInput};
use runne_application::conversation_service::ConversationService;
use runne_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextService, ConversationTextServiceError,
};
use runne_application::ports::{
    ApplicationCommandContext, PrincipalId, ProjectWorkspaceRepository, RuntimeAuthorityId,
    TextGenerationPhase,
};
use runne_application::prohibited_content::ProhibitedContentPort;
use runne_application::verification::export_port::{
    VerificationExporter, VerificationOutboundError,
};
use runne_domain::event::Actor;
use runne_domain::id::{CommandId, IdempotencyKey};
use runne_domain::message::MessageText;
use runne_domain::verification::backup::StreamInventory;
use runne_domain::verification::digest::VerificationDigest;
use runne_security::SecretBroker;
use runne_store::verification::backup_store::{BackupStoreError, InMemoryBackupStore};
use runne_store::{ProjectWorkspaceStore, store::StoreTransaction};

#[path = "support/nm10_rules.rs"]
mod nm10_rules;

use nm10_rules::{
    CANARY, FAKE_SECRET_CRASH, FAKE_SECRET_ENV, SecretScanner,
    assert_constants_match_frozen_fixtures, scan_absent, scanner,
};

const AUTHORITY: &str = "nm10-sink-scan";
const CONVERSATION_ID: &str = "018f2e3a-7000-7000-8001-0000000000b1";
const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8002-0000000000b2";
const PROJECT_ID: &str = "018f2e3a-7000-7000-8002-0000000000b3";

/// S7: register the fake env secrets via the production broker path; real
/// environment variables are never touched.
fn registered_secret_guard() -> Arc<dyn ProhibitedContentPort> {
    let mut broker = SecretBroker::new();
    for (name, value) in [
        ("RUNNE_T1_FAKE_SECRET_ENV", FAKE_SECRET_ENV),
        ("RUNNE_T1_FAKE_CRASH_REPORT_VAR", FAKE_SECRET_CRASH),
    ] {
        broker
            .register(name, value.as_bytes().to_vec())
            .expect("register");
    }
    Arc::new(broker.prohibited_content_guard())
}

fn store_with_registered_guard() -> (tempfile::TempDir, StoreTransaction) {
    let directory = tempfile::tempdir().expect("directory");
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir_all(&daemon).expect("layout");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700))
            .expect("permissions");
    }
    let path = daemon.join("nm10-sink-scan.sqlite");
    let store = StoreTransaction::open(
        path.to_str().expect("path"),
        RuntimeAuthorityId(AUTHORITY.into()),
        registered_secret_guard(),
    )
    .expect("store");
    (directory, store)
}

fn begin_input(text: &str) -> BeginConversationTextInput {
    BeginConversationTextInput {
        conversation_id: CONVERSATION_ID.parse().expect("conversation id"),
        expected_version: 1,
        text: MessageText::new(text).expect("text"),
    }
}

fn context(command: &str, key: &str) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: command.parse().expect("command id"),
        idempotency_key: IdempotencyKey::new(key).expect("key"),
        principal_id: PrincipalId("local-owner".into()),
        actor: Actor::new("nm10-sink-scan").expect("actor"),
    }
}

fn seed_conversation(store: &StoreTransaction) {
    use runne_domain::project_workspace::{Project, ProjectWorkspaceDisplayName, Workspace};
    let projects = ProjectWorkspaceStore::from_store(store.clone());
    let display = |text: &str| ProjectWorkspaceDisplayName::new(text.into()).expect("name");
    let key = |text: &str| IdempotencyKey::new(text).expect("key");
    let project_id = PROJECT_ID.parse().expect("project id");
    projects
        .create_project(
            "local-owner",
            CommandId::from_bytes([1; 16]),
            &key("nm10-project"),
            Project::create(project_id, display("fixture")),
        )
        .expect("seed project");
    projects
        .create_workspace(
            "local-owner",
            CommandId::from_bytes([2; 16]),
            &key("nm10-workspace"),
            Workspace::create(
                WORKSPACE_ID.parse().expect("workspace id"),
                project_id,
                display("ws"),
            ),
        )
        .expect("seed workspace");
    let seed_context = context(
        "018f2e3a-7000-7000-8000-0000000000b4",
        "nm10-create-conversation",
    );
    ConversationService::new(
        store.clone(),
        store.clone(),
        RuntimeAuthorityId(AUTHORITY.into()),
    )
    .create_from_application(
        &seed_context,
        CreateConversationInput {
            conversation_id: CONVERSATION_ID.parse().expect("conversation id"),
            workspace_id: WORKSPACE_ID.parse().expect("workspace id"),
            command_id: seed_context.command_id,
            idempotency_key: key("nm10-create-conversation"),
            scope: ConversationContextScope::Workspace,
        },
    )
    .expect("seed conversation");
}

fn text_service(
    store: &StoreTransaction,
) -> ConversationTextService<StoreTransaction, StoreTransaction> {
    ConversationTextService::new(
        store.clone(),
        store.clone(),
        RuntimeAuthorityId(AUTHORITY.into()),
        registered_secret_guard(),
    )
}

fn scan_store_files_absent(directory: &tempfile::TempDir, scanner: &SecretScanner) {
    let daemon = directory.path().join("runne-daemon");
    for name in ["nm10-sink-scan.sqlite", "nm10-sink-scan.sqlite-wal"] {
        let Ok(bytes) = std::fs::read(daemon.join(name)) else {
            continue;
        };
        scan_absent(scanner, &format!("sink:store-file:{name}"), &bytes);
    }
}

#[test]
fn nm10_registered_secrets_never_traverse_outbound_sinks() {
    assert_constants_match_frozen_fixtures();
    let secret_scanner = scanner(&[FAKE_SECRET_ENV, FAKE_SECRET_CRASH, CANARY]);
    let clean_scanner_input = "clean conversation text for the sink scan";
    // Liveness control: the frozen rules flag their own material.
    let live = format!("preamble {} epilogue", FAKE_SECRET_ENV);
    let found = match secret_scanner.scan_reader(Cursor::new(live.as_bytes())) {
        Ok(found) => found,
        Err(_) => panic!("live scan failed"),
    };
    assert!(
        found.is_some(),
        "scan rules must detect registered material"
    );

    // Sink: verification export (§E).
    let exporter = VerificationExporter::new(registered_secret_guard());
    let export = |result: Option<&str>| {
        exporter.export_run_json(
            uuid::Uuid::now_v7(),
            uuid::Uuid::now_v7(),
            clean_scanner_input,
            result,
            1,
        )
    };
    let denied = exporter.export_run_json(
        uuid::Uuid::now_v7(),
        uuid::Uuid::now_v7(),
        FAKE_SECRET_ENV,
        None,
        0,
    );
    assert_eq!(denied, Err(VerificationOutboundError::PolicyDenied));
    let delivered = export(Some(clean_scanner_input)).expect("clean export delivers");
    scan_absent(&secret_scanner, "sink:verification-export", &delivered);

    // Sink: synthetic backup archive (§E); manifest-only archive carries
    // stream names, so a registered canary name is denied up front.
    let streams = |name: &str| {
        vec![StreamInventory {
            stream_name: name.into(),
            event_count: 1,
            first_sequence: 1,
            last_sequence: 1,
        }]
    };
    let backup = InMemoryBackupStore::new(registered_secret_guard());
    let denied = backup.create_backup(
        streams(FAKE_SECRET_CRASH),
        VerificationDigest::from_bytes([1; 32]),
    );
    assert!(matches!(denied, Err(BackupStoreError::PolicyDenied)));
    assert_eq!(backup.archive_count(), 0, "no archive bytes emitted");
    let manifest = backup
        .create_backup(
            streams(clean_scanner_input),
            VerificationDigest::from_bytes([1; 32]),
        )
        .expect("clean backup delivers");
    assert!(manifest.integrity_result);
    let archive = backup
        .archive_bytes(&manifest.backup_id)
        .expect("archive bytes");
    scan_absent(&secret_scanner, "sink:backup-archive", &archive);

    // Sink: conversation mutation boundary (§C, canonical mutation guard).
    let (directory, store) = store_with_registered_guard();
    seed_conversation(&store);
    let service = text_service(&store);
    let begin = service
        .begin_text(
            &context(
                "018f2e3a-7000-7000-8000-0000000000b5",
                "nm10-begin-prohibited",
            ),
            begin_input(&format!("note {FAKE_SECRET_ENV}")),
        )
        .expect_err("registered canary is denied at the mutation boundary");
    assert_eq!(
        begin,
        ConversationTextServiceError::ProhibitedSecretMaterial
    );

    let receipt = service
        .begin_text(
            &context("018f2e3a-7000-7000-8000-0000000000b6", "nm10-begin-clean"),
            begin_input(clean_scanner_input),
        )
        .expect("clean text begins");
    assert_eq!(receipt.phase, TextGenerationPhase::Started);
    // Finish is the second step of the SAME generate command identity; the
    // prohibited-content inspection runs after the durable receipt lookup.
    let error = service
        .finish_text(
            &context("018f2e3a-7000-7000-8000-0000000000b6", "nm10-begin-clean"),
            FinishConversationTextInput {
                original: begin_input(clean_scanner_input),
                started: receipt,
                completion: runne_application::commands::ConversationTextCompletion::AssistantText(
                    MessageText::new(format!("result {FAKE_SECRET_CRASH}")).expect("text"),
                ),
            },
        )
        .expect_err("registered canary is denied at the terminal boundary");
    // The terminal text hits the canonical mutation guard at the store
    // boundary; the denial surfaces as the typed storage policy failure and
    // no commit is produced.
    assert!(matches!(
        error,
        ConversationTextServiceError::Commit(
            runne_application::ports::CommitError::StorageFailure(
                runne_application::ports::StorageFailureKind::PolicyDenied
            )
        )
    ));
    scan_store_files_absent(&directory, &secret_scanner);
}

/// Durable durability of the denial: the canary never appears in the store
/// files of a reopened database either.
#[test]
fn nm10_denial_leaves_no_canary_in_store_after_reopen() {
    let secret_scanner = scanner(&[FAKE_SECRET_ENV, FAKE_SECRET_CRASH, CANARY]);
    let (directory, store) = store_with_registered_guard();
    seed_conversation(&store);
    drop(store);
    assert!(
        directory
            .path()
            .join("runne-daemon/nm10-sink-scan.sqlite")
            .exists(),
        "database file must exist after the seeded flow"
    );
    scan_store_files_absent(&directory, &secret_scanner);
}
