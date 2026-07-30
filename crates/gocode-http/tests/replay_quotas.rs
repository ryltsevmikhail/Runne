//! Count and encoded-byte admission for the published replay transport.

use gocode_http::limits::{
    MAX_GLOBAL_REPLAY_QUEUE_BYTES, MAX_LIVE_QUEUE_BYTES, ReplayQuotaError, ReplayQuotaManager,
};

#[test]
fn session_quota_is_atomic_per_principal_and_released_on_drop() {
    let quotas = ReplayQuotaManager::default();
    let permits = (0..8)
        .map(|_| quotas.reserve_session("principal-a").unwrap())
        .collect::<Vec<_>>();

    assert_eq!(
        quotas.reserve_session("principal-a").unwrap_err(),
        ReplayQuotaError::Backpressure
    );
    assert!(quotas.reserve_session("principal-b").is_ok());

    drop(permits);
    assert!(quotas.reserve_session("principal-a").is_ok());
}

#[test]
fn daemon_session_quota_is_shared_across_principals() {
    let quotas = ReplayQuotaManager::default();
    let permits = (0..32)
        .map(|index| {
            quotas
                .reserve_session(&format!("principal-{index}"))
                .unwrap()
        })
        .collect::<Vec<_>>();

    assert_eq!(
        quotas.reserve_session("principal-overflow").unwrap_err(),
        ReplayQuotaError::Backpressure
    );

    drop(permits);
    assert!(quotas.reserve_session("principal-overflow").is_ok());
}

#[test]
fn live_quota_is_four_per_principal_and_eight_per_daemon() {
    let quotas = ReplayQuotaManager::default();
    let principal_a = (0..4)
        .map(|_| quotas.reserve_live("principal-a").unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        quotas.reserve_live("principal-a").unwrap_err(),
        ReplayQuotaError::Backpressure
    );
    let principal_b = (0..4)
        .map(|_| quotas.reserve_live("principal-b").unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        quotas.reserve_live("principal-c").unwrap_err(),
        ReplayQuotaError::Backpressure
    );

    drop(principal_a);
    assert!(quotas.reserve_live("principal-a").is_ok());
    drop(principal_b);
}

#[test]
fn queue_quota_reserves_encoded_bytes_and_releases_them_on_drop() {
    let quotas = ReplayQuotaManager::default();
    let queue = quotas.queue();
    let full = queue.reserve(MAX_LIVE_QUEUE_BYTES).unwrap();

    assert_eq!(
        queue.reserve(1).unwrap_err(),
        ReplayQuotaError::Backpressure
    );

    drop(full);
    assert!(queue.reserve(MAX_LIVE_QUEUE_BYTES).is_ok());
}

#[test]
fn global_queue_quota_is_shared_and_atomic() {
    let quotas = ReplayQuotaManager::default();
    let reservations = (0..(MAX_GLOBAL_REPLAY_QUEUE_BYTES / MAX_LIVE_QUEUE_BYTES))
        .map(|_| quotas.queue().reserve(MAX_LIVE_QUEUE_BYTES).unwrap())
        .collect::<Vec<_>>();

    assert_eq!(
        quotas.queue().reserve(1).unwrap_err(),
        ReplayQuotaError::Backpressure
    );

    drop(reservations);
    assert!(quotas.queue().reserve(MAX_LIVE_QUEUE_BYTES).is_ok());
}
