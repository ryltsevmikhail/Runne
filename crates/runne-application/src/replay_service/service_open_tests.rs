use std::sync::atomic::{AtomicU64, Ordering};

use runne_api::{
    ApiPrincipalId, DaemonInstanceId, ReplayRetentionBaselineWireV2, RuntimeSessionBinding,
    StableRuntimeBinding, UnauthenticatedReplayRetentionBaselineFieldsV2,
};
use runne_domain::event::{Actor, DomainEventDraft, EventEnvelope};
use runne_domain::id::{CommandId, IdempotencyKey};
use runne_domain::task_run::TaskRun;
use runne_domain::timestamp::Timestamp;
use tokio::sync::Notify;

include!("service_open_tests/support.rs");

#[tokio::test]
async fn delayed_gap_samples_both_clocks_after_store_and_never_signs_an_expired_issuer() {
    assert!(matches!(
        delayed_gap(600, 601_000).await,
        Err(ReplayError::AuthorizationRevoked)
    ));
}

#[tokio::test]
async fn delayed_gap_uses_the_post_store_wall_time_for_a_live_issuer() {
    let Err(ReplayError::ReplayRetentionGap { baseline }) = delayed_gap(599, 601_000).await else {
        panic!("live issuer must sign the retention baseline");
    };
    let fields = baseline.to_unauthenticated_fields();
    assert_eq!(fields.issued_at_unix_ms, 601_000);
    assert_eq!(fields.expires_at_unix_ms, 602_000);
}

async fn delayed_gap(
    monotonic_after_store: u64,
    wall_after_store: u64,
) -> Result<(ReplaySession, Vec<ReplayEvent>), ReplayError> {
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let service = ReplayService::new(
        Arc::new(BlockingGapStore {
            started: Arc::clone(&started),
            release: Arc::clone(&release),
            baseline: gap_candidate(),
        }),
        [13; 32],
        EventLogLineageId::from_bytes([2; 16]),
        Arc::new(AllowAuthorization),
    );
    let monotonic = Arc::new(AtomicU64::new(0));
    let wall = Arc::new(AtomicU64::new(1_000));
    let (sessions, issuer) = baseline_issuer();
    let context = sessions
        .replay_resume_context_v2_for_test(
            &issuer,
            {
                let monotonic = Arc::clone(&monotonic);
                Arc::new(move || std::time::Duration::from_secs(monotonic.load(Ordering::SeqCst)))
            },
            {
                let wall = Arc::clone(&wall);
                Arc::new(move || Ok(wall.load(Ordering::SeqCst)))
            },
        )
        .unwrap();
    let aggregate_id = [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 1];
    let mut opening = Box::pin(service.open_session_with_baseline_context(
        "owner",
        1,
        &[1; 16],
        0,
        1,
        &aggregate_id,
        None,
        Arc::new(AllowDelivery),
        Some(&context),
        false,
    ));
    tokio::select! {
        _ = &mut opening => panic!("blocking store returned early"),
        _ = started.notified() => {}
    }
    monotonic.store(monotonic_after_store, Ordering::SeqCst);
    wall.store(wall_after_store, Ordering::SeqCst);
    release.notify_one();
    opening.await
}

#[tokio::test]
async fn v2_resume_requires_a_sensitive_lease_before_storage() {
    let service = ReplayService::new(
        Arc::new(BlockingGapStore {
            started: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
            baseline: gap_candidate(),
        }),
        [13; 32],
        EventLogLineageId::from_bytes([2; 16]),
        Arc::new(PublicAuthorization),
    );
    let (sessions, issuer) = baseline_issuer();
    let error = service
        .resume_from_retention_baseline_v2(
            "owner",
            1,
            &[1; 16],
            0,
            &scope(),
            &invalid_v2_wire(),
            sessions.replay_resume_context_v2(&issuer).unwrap(),
            Arc::new(AllowDelivery),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, ReplayError::SensitivityDenied));
}

#[tokio::test]
async fn v2_resume_reauthenticates_the_exact_wire_and_opens_the_store_request() {
    let (sessions, issuer) = baseline_issuer();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let wire = issuer
        .issue_v2(
            v2_scope(),
            crate::local_session::candidate_v2(),
            std::time::Duration::from_secs(1),
            now,
            now + 2_000,
        )
        .unwrap();
    let service = ReplayService::new(
        Arc::new(BlockingGapStore {
            started: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
            baseline: gap_candidate(),
        }),
        [13; 32],
        EventLogLineageId::from_bytes([2; 16]),
        Arc::new(AllowAuthorization),
    );
    let (session, events, _, _) = service
        .resume_from_retention_baseline_v2(
            "owner",
            1,
            &[1; 16],
            0,
            &v2_scope(),
            &wire,
            sessions.replay_resume_context_v2(&issuer).unwrap(),
            Arc::new(AllowDelivery),
        )
        .await
        .unwrap();
    assert_eq!(
        session.aggregate_id,
        [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 1]
    );
    assert!(events.is_empty());
}
