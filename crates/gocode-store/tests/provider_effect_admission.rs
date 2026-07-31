use std::path::PathBuf;
use std::sync::Arc;

use gocode_application::provider::{
    ProviderAdmissionError, ProviderEffectAdmission, ProviderEffectAuthorityRecord,
    ProviderEffectAuthorityRef, ProviderEffectRequest,
};
use gocode_provider::{DispatchAttemptId, ProviderCallDigestVersion, ProviderCallId};
use gocode_store::provider::{
    PreparedProviderRecord, ProviderDispatchClaim, SqliteProviderDispatchStore,
    SqliteProviderEffectAdmission,
};

fn database_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "gocode-provider-admission-{name}-{}-{:?}.sqlite",
        std::process::id(),
        std::thread::current().id()
    ))
}

fn authority_ref() -> ProviderEffectAuthorityRef {
    ProviderEffectAuthorityRef::new([10; 16], 1).unwrap()
}

fn authority_record(expires_at: i64) -> ProviderEffectAuthorityRecord {
    ProviderEffectAuthorityRecord {
        authority_ref: authority_ref(),
        attempt_id: DispatchAttemptId::from_bytes([5; 16]),
        permit_id: [6; 16],
        capability_grant_id: "grant-provider".to_owned(),
        token_reservation_id: [7; 16],
        cost_reservation_id: [8; 16],
        prepared_digest: [2; 32],
        render_digest: [3; 32],
        profile_digest: [4; 32],
        owner_id: "provider-owner".to_owned(),
        scope: "provider.dispatch".to_owned(),
        fencing_token: 9,
        expires_at,
        revoked: false,
        consumed: false,
    }
}

fn setup(name: &str) -> (PathBuf, ProviderEffectRequest) {
    let path = database_path(name);
    let _ = std::fs::remove_file(&path);
    let store = SqliteProviderDispatchStore::open(&path).unwrap();
    let prepared = PreparedProviderRecord {
        call_id: ProviderCallId::from_bytes([1; 16]),
        call_digest_version: ProviderCallDigestVersion::V2,
        prepared_digest: [2; 32],
        render_digest: [3; 32],
        profile_digest: [4; 32],
    };
    store.persist_prepared(&prepared).unwrap();
    store
        .claim(&ProviderDispatchClaim {
            call_id: prepared.call_id,
            attempt_id: DispatchAttemptId::from_bytes([5; 16]),
            permit_id: [6; 16],
            prepared_digest: prepared.prepared_digest,
            render_digest: prepared.render_digest,
            profile_digest: prepared.profile_digest,
            token_reservation_id: [7; 16],
            cost_reservation_id: [8; 16],
            fencing_token: 9,
            provider_idempotency_key: "provider-attempt-5".to_owned(),
        })
        .unwrap();
    let admission = SqliteProviderEffectAdmission::open(&path).unwrap();
    admission
        .issue_authority(&authority_record(i64::MAX))
        .unwrap();
    (
        path,
        ProviderEffectRequest {
            authority_ref: authority_ref(),
            attempt_id: DispatchAttemptId::from_bytes([5; 16]),
            permit_id: [6; 16],
            prepared_digest: [2; 32],
            render_digest: [3; 32],
            profile_digest: [4; 32],
            token_reservation_id: [7; 16],
            cost_reservation_id: [8; 16],
            fencing_token: 9,
            owner_id: "provider-owner".to_owned(),
            scope: "provider.dispatch".to_owned(),
        },
    )
}

fn pre_effect_count(path: &PathBuf, table: &str) -> i64 {
    rusqlite::Connection::open(path)
        .unwrap()
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

fn pre_effect_counts(path: &PathBuf) -> [i64; 5] {
    [
        "security_dispatch_intents",
        "security_authorization_decisions",
        "security_budget_consumptions",
        "security_audit_pre_effect",
        "security_permit_claims",
    ]
    .map(|table| pre_effect_count(path, table))
}

fn assert_pre_effect_unchanged(path: &PathBuf, expected: [i64; 5]) {
    assert_eq!(
        pre_effect_counts(path),
        expected,
        "pre-effect tables were mutated"
    );
}

#[test]
fn exact_provider_admission_commits_once_and_replays_idempotently() {
    let (path, request) = setup("exact-replay");
    let admission = SqliteProviderEffectAdmission::open(&path).unwrap();

    admission.admit(&request).unwrap();
    admission.admit(&request).unwrap();

    assert_eq!(admission.committed_count().unwrap(), 1);
}

#[test]
fn mismatched_binding_rejects_before_security_pre_effect_mutation() {
    let (path, request) = setup("binding-mismatch");
    let admission = SqliteProviderEffectAdmission::open(&path).unwrap();
    let mut changed = request;
    changed.cost_reservation_id = [99; 16];

    assert_eq!(
        admission.admit(&changed),
        Err(ProviderAdmissionError::AuthorityConflict)
    );
    assert_pre_effect_unchanged(&path, [0; 5]);
}

#[test]
fn stale_fence_and_changed_replay_preserve_the_original_transaction() {
    let (path, request) = setup("replay-conflict");
    let admission = SqliteProviderEffectAdmission::open(&path).unwrap();
    admission.admit(&request).unwrap();
    let before = pre_effect_counts(&path);

    let mut stale = request.clone();
    stale.fencing_token += 1;
    assert_eq!(
        admission.admit(&stale),
        Err(ProviderAdmissionError::AuthorityConflict)
    );

    let mut changed_grant = request;
    changed_grant.authority_ref = ProviderEffectAuthorityRef::new([11; 16], 1).unwrap();
    assert_eq!(
        admission.admit(&changed_grant),
        Err(ProviderAdmissionError::AuthorityDenied)
    );
    assert_pre_effect_unchanged(&path, before);
}

#[test]
fn rejects_unknown_authority_without_mutation() {
    let (path, mut request) = setup("unknown-authority");
    let admission = SqliteProviderEffectAdmission::open(&path).unwrap();
    request.authority_ref = ProviderEffectAuthorityRef::new([99; 16], 1).unwrap();

    assert_eq!(
        admission.admit(&request),
        Err(ProviderAdmissionError::AuthorityDenied)
    );
    assert_pre_effect_unchanged(&path, [0; 5]);
}

#[test]
fn rejects_expired_revoked_wrong_owner_and_exhausted_authority() {
    let (path, request) = setup("authority-rejections");
    let admission = SqliteProviderEffectAdmission::open(&path).unwrap();

    let mut expired = authority_record(0);
    expired.authority_ref = ProviderEffectAuthorityRef::new([11; 16], 1).unwrap();
    admission.issue_authority(&expired).unwrap();
    let mut expired_request = request.clone();
    expired_request.authority_ref = expired.authority_ref;
    assert_eq!(
        admission.admit(&expired_request),
        Err(ProviderAdmissionError::AuthorityDenied)
    );
    let mut revoked = authority_record(i64::MAX);
    revoked.authority_ref = ProviderEffectAuthorityRef::new([12; 16], 1).unwrap();
    revoked.revoked = true;
    admission.issue_authority(&revoked).unwrap();
    let mut revoked_request = request.clone();
    revoked_request.authority_ref = revoked.authority_ref;
    assert_eq!(
        admission.admit(&revoked_request),
        Err(ProviderAdmissionError::AuthorityDenied)
    );
    let mut wrong_owner = request;
    wrong_owner.owner_id = "other-owner".to_owned();
    assert_eq!(
        admission.admit(&wrong_owner),
        Err(ProviderAdmissionError::AuthorityConflict)
    );
    assert_pre_effect_unchanged(&path, [0; 5]);
}

#[test]
fn consumes_exact_authority_once() {
    let (path, request) = setup("consume-once");
    let admission = SqliteProviderEffectAdmission::open(&path).unwrap();
    admission.admit(&request).unwrap();
    let before = pre_effect_counts(&path);
    admission.admit(&request).unwrap();

    assert_pre_effect_unchanged(&path, before);
}

#[test]
fn changed_replay_conflicts_without_mutation() {
    let (path, request) = setup("changed-replay-conflict");
    let admission = SqliteProviderEffectAdmission::open(&path).unwrap();
    admission.admit(&request).unwrap();
    let before = pre_effect_counts(&path);
    let mut changed = request;
    changed.render_digest = [99; 32];

    assert_eq!(
        admission.admit(&changed),
        Err(ProviderAdmissionError::AuthorityConflict)
    );
    assert_pre_effect_unchanged(&path, before);
}

#[test]
fn concurrent_consumption_has_one_winner() {
    let (path, request) = setup("concurrent-consumption");
    let admission = Arc::new(SqliteProviderEffectAdmission::open(&path).unwrap());
    let first = {
        let admission = Arc::clone(&admission);
        let request = request.clone();
        std::thread::spawn(move || admission.admit(&request))
    };
    let second = {
        let admission = Arc::clone(&admission);
        std::thread::spawn(move || admission.admit(&request))
    };

    assert!(first.join().unwrap().is_ok());
    assert!(second.join().unwrap().is_ok());
    assert_eq!(admission.committed_count().unwrap(), 1);
}
