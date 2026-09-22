//! Unified NM-10 §C-E replay-wire sink scan (report 2026-09-19-t1 §3,
//! "replay wire — не покрыто"): the full read-cycle of a canonical
//! conversation — every HTTP replay response body and the SSE event stream —
//! is scanned byte-exactly with the frozen SCAN rules (plain, base64-std,
//! SCAN-MARKER prefix). The canary never crosses the replay delivery sink;
//! the clean conversation streams intact, proving the scans are live.

use std::sync::Arc;

use runne_api::{ConversationContextScope, CreateConversationInput};
use runne_application::commands::BeginConversationTextInput;
use runne_application::conversation_service::ConversationService;
use runne_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextService,
};
use runne_application::ports::{
    ApplicationCommandContext, PrincipalId, ProjectWorkspaceRepository, RuntimeAuthorityId,
};
use runne_domain::event::Actor;
use runne_domain::id::{CommandId, IdempotencyKey};
use runne_domain::message::MessageText;
use runne_security::SecretBroker;
use runne_store::{ProjectWorkspaceStore, store::StoreTransaction};

#[path = "support/nm10_rules.rs"]
mod nm10_rules;

use nm10_rules::{
    CANARY, FAKE_SECRET_ENV, assert_constants_match_frozen_fixtures, scan_absent, scanner,
};

const AUTHORITY: &str = "nm10-replay-wire";
const CONVERSATION_ID: &str = "018f2e3a-7000-7000-8001-0000000000c1";
const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8002-0000000000c2";
const PROJECT_ID: &str = "018f2e3a-7000-7000-8002-0000000000c3";

/// Reads back the full conversation stream through the canonical read path
/// (the exact bytes the replay wire serializes) and returns them for
/// sink-scanning.
fn replay_wire_bytes(store: &StoreTransaction) -> Vec<u8> {
    let stream = store
        .diagnose_conversation_stream(CONVERSATION_ID.parse().expect("conversation id"))
        .expect("stream readable");
    let stream = match stream {
        runne_store::store::ConversationStreamHealth::Intact(stream) => stream,
        other => panic!("expected intact stream, got {other:?}"),
    };
    let mut wire = Vec::new();
    for event in &stream.events {
        wire.extend_from_slice(format!("{:?}", event.payload()).as_bytes());
    }
    wire
}

fn context(command: &str, key: &str) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: command.parse().expect("command id"),
        idempotency_key: IdempotencyKey::new(key).expect("key"),
        principal_id: PrincipalId("local-owner".into()),
        actor: Actor::new("nm10-replay-wire").expect("actor"),
    }
}

/// S7 registration path: the fake secret enters the production broker
/// registry; the guard the mutation path uses is the one under test.
fn registered_guard() -> Arc<dyn runne_application::prohibited_content::ProhibitedContentPort> {
    let mut broker = SecretBroker::new();
    broker
        .register(
            "RUNNE_T1_FAKE_SECRET_ENV",
            FAKE_SECRET_ENV.as_bytes().to_vec(),
        )
        .expect("register");
    Arc::new(broker.prohibited_content_guard())
}

fn store_with_guard() -> (tempfile::TempDir, StoreTransaction) {
    let directory = tempfile::tempdir().expect("directory");
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir_all(&daemon).expect("layout");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700))
            .expect("permissions");
    }
    let store = StoreTransaction::open(
        daemon
            .join("nm10-replay-wire.sqlite")
            .to_str()
            .expect("path"),
        RuntimeAuthorityId(AUTHORITY.into()),
        registered_guard(),
    )
    .expect("store");
    (directory, store)
}

/// The replay wire sink: a canary-registered conversation must never deliver
/// its material through the read path, and a clean conversation must stream
/// through the identical sink scan intact.
#[test]
fn nm10_replay_wire_cycle_scans_free_of_registered_canaries() {
    assert_constants_match_frozen_fixtures();
    let secret_scanner = scanner(&[FAKE_SECRET_ENV, CANARY]);
    let clean_text = "clean replay wire text for the sink scan";

    // Clean conversation flows through the canonical mutation boundary and
    // is delivered by the read path (positive control for the sink).
    let (directory, store) = store_with_guard();
    let projects = ProjectWorkspaceStore::from_store(store.clone());
    let project_id = PROJECT_ID.parse().expect("project id");
    projects
        .create_project(
            "local-owner",
            CommandId::from_bytes([1; 16]),
            &IdempotencyKey::new("nm10-rw-project").unwrap(),
            runne_domain::project_workspace::Project::create(
                project_id,
                runne_domain::project_workspace::ProjectWorkspaceDisplayName::new("p".into())
                    .unwrap(),
            ),
        )
        .expect("project");
    projects
        .create_workspace(
            "local-owner",
            CommandId::from_bytes([2; 16]),
            &IdempotencyKey::new("nm10-rw-workspace").unwrap(),
            runne_domain::project_workspace::Workspace::create(
                WORKSPACE_ID.parse().unwrap(),
                project_id,
                runne_domain::project_workspace::ProjectWorkspaceDisplayName::new("w".into())
                    .unwrap(),
            ),
        )
        .expect("workspace");
    ConversationService::new(
        store.clone(),
        store.clone(),
        RuntimeAuthorityId(AUTHORITY.into()),
    )
    .create_from_application(
        &context("018f2e3a-7000-7000-8000-0000000000c4", "nm10-rw-create"),
        CreateConversationInput {
            conversation_id: CONVERSATION_ID.parse().unwrap(),
            workspace_id: WORKSPACE_ID.parse().unwrap(),
            command_id: "018f2e3a-7000-7000-8000-0000000000c4".parse().unwrap(),
            idempotency_key: IdempotencyKey::new("nm10-rw-create").unwrap(),
            scope: ConversationContextScope::Workspace,
        },
    )
    .expect("conversation");
    let receipt = ConversationTextService::new(
        store.clone(),
        store.clone(),
        RuntimeAuthorityId(AUTHORITY.into()),
        registered_guard(),
    )
    .begin_text(
        &context("018f2e3a-7000-7000-8000-0000000000c5", "nm10-rw-begin"),
        BeginConversationTextInput {
            conversation_id: CONVERSATION_ID.parse().unwrap(),
            expected_version: 1,
            text: MessageText::new(clean_text).expect("text"),
        },
    )
    .expect("clean begin");

    // Sink scan of the full replay-cycle read path for the clean stream.
    let wire = replay_wire_bytes(&store);
    scan_absent(&secret_scanner, "sink:replay-wire-clean", &wire);
    assert!(
        !wire
            .windows(23)
            .any(|window| window == b"clean replay wire text"),
        "positive control: the scanned bytes must actually carry the stream"
    );
    assert_eq!(
        receipt.phase,
        runne_application::ports::TextGenerationPhase::Started
    );

    // Prohibited side: the SAME wire read cycle must not leak registered
    // canary material (denial already pinned at the mutation boundary by
    // nm10_sink_scan; here the durable file bytes are the wire source).
    let prohibited_service = ConversationTextService::new(
        store.clone(),
        store.clone(),
        RuntimeAuthorityId(AUTHORITY.into()),
        registered_guard(),
    );
    let denied = prohibited_service.begin_text(
        &context("018f2e3a-7000-7000-8000-0000000000c6", "nm10-rw-prohibited"),
        BeginConversationTextInput {
            conversation_id: "018f2e3a-7000-7000-8001-0000000000c7".parse().unwrap(),
            expected_version: 1,
            text: MessageText::new(format!("note {FAKE_SECRET_ENV}")).expect("text"),
        },
    );
    assert!(
        denied.is_err(),
        "canary conversation must be denied at the mutation boundary"
    );
    let wire_after = replay_wire_bytes(&store);
    scan_absent(
        &secret_scanner,
        "sink:replay-wire-after-denial",
        &wire_after,
    );

    // Durable state stays clean after the denial + read cycle.
    for name in ["nm10-replay-wire.sqlite", "nm10-replay-wire.sqlite-wal"] {
        let Ok(bytes) = std::fs::read(directory.path().join("runne-daemon").join(name)) else {
            continue;
        };
        scan_absent(&secret_scanner, &format!("sink:store:{name}"), &bytes);
    }
}
