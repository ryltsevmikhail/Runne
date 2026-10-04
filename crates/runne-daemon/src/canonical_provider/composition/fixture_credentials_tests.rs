use std::cell::Cell;

use runne_provider::{
    CredentialAuthorityPair, CredentialEnrollmentAuthorityPair, ProviderCredentialEnrollmentStore,
    ProviderId,
};
use runne_secure_store::ProviderCredentialId;
use runne_store::provider::SqliteProviderCredentialLifecycleStore;
use runne_store::schema::{ConnectionMode, apply_migrations, open_managed_connection};

use super::provision_online_with_clock;

#[test]
fn readiness_observation_uses_fresh_time_after_lifecycle_mutations() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("credential-fixture.sqlite");
    let connection = open_managed_connection(&path, ConnectionMode::Writer).unwrap();
    apply_migrations(&connection).unwrap();
    let (lifecycle, _) = CredentialAuthorityPair::new().split();
    let (enrollment, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let store = SqliteProviderCredentialLifecycleStore::open_with_connection_and_authorities(
        connection, lifecycle, enrollment,
    )
    .unwrap();
    let provider = ProviderId::new(ProviderCredentialId::Generic("openai").account()).unwrap();
    let snapshot =
        ProviderCredentialEnrollmentStore::begin_admission_snapshot(&store, &provider).unwrap();
    let current = chrono::Utc::now().timestamp();
    let samples = [current - 30, current + 30];
    let reads = Cell::new(0);

    provision_online_with_clock(&store, provider, snapshot, measurements, || {
        let index = reads.get();
        reads.set(index + 1);
        samples[index]
    })
    .unwrap_or_else(|_| panic!("fresh readiness observation must complete"));

    assert_eq!(reads.get(), 2, "ticket and readiness use separate samples");
    let observed_at: i64 = rusqlite::Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT observed_at FROM provider_credential_readiness_observations
             WHERE observation_id=?1",
            [&[0xD9; 16][..]],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(observed_at, samples[1]);
}
