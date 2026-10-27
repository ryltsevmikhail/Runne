//! Fresh original fixture reopen for S observation, without a native owner/new epoch.
//! Existing constructor runs startup/migration gates; this is NOT a read-only opener.
use super::{context::CaseContext, fixture_paths, metadata::Area, observations};
use crate::{ProjectTrustStore, schema::ConnectionMode, store::StoreTransaction};
use runne_application::ports::RuntimeAuthorityId;
use std::sync::Arc;

pub(super) fn open(context: &CaseContext, area: &Area) -> (StoreTransaction, ProjectTrustStore) {
    let daemon = area.daemon(context);
    let db = daemon.join("store.sqlite");
    fixture_paths::regular(&db, context);
    fixture_paths::regular(&daemon.join("trust.sqlite.project-trust"), context);
    let writer = observations::reopen(context, area, ConnectionMode::ValidatedReopen);
    let reader = observations::reader(context, area);
    let store = StoreTransaction::open_with_connections(
        db.to_str().unwrap(),
        writer,
        reader,
        RuntimeAuthorityId(hex::encode(area.authority)),
        Arc::new(runne_security::SecretBroker::new().prohibited_content_guard()),
    )
    .unwrap();
    let trust = ProjectTrustStore::open(&daemon.join("trust.sqlite"), area.authority).unwrap();
    super::bootstrap::trust(&trust, area);
    context.deadline.check();
    (store, trust)
}
