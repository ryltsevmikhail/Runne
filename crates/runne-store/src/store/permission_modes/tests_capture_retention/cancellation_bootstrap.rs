use super::{metadata::Area, observations, paths};
use crate::{
    ProjectTrustStore, execution_node,
    schema::{self, ConnectionMode},
    store::StoreTransaction,
};
use runne_application::{
    ports::RuntimeAuthorityId,
    project_trust::{ProjectTrustPersistence, ProjectTrustProjectId},
};
use runne_domain::id::ProjectId;
use std::{path::Path, sync::Arc};
pub(super) fn open(root: &Path, saved: &Area) -> (StoreTransaction, ProjectTrustStore, u64) {
    let daemon = saved.daemon(root);
    let db = daemon.join("store.sqlite");
    paths::regular(&db);
    // Opening trust must never manufacture a replacement sidecar.
    paths::regular(&daemon.join("trust.sqlite.project-trust"));
    let writer = observations::reopen(root, saved, ConnectionMode::ValidatedReopen);
    let reader = observations::reader(root, saved);
    let epoch = schema::next_launch_generation(&writer).unwrap();
    assert!(epoch > saved.epoch);
    let store = StoreTransaction::open_with_connections(
        db.to_str().unwrap(),
        writer,
        reader,
        RuntimeAuthorityId(hex::encode(saved.authority)),
        Arc::new(runne_security::SecretBroker::new().prohibited_content_guard()),
    )
    .unwrap();
    let trust = ProjectTrustStore::open(&daemon.join("trust.sqlite"), saved.authority).unwrap();
    let project: ProjectId = saved.project.parse().unwrap();
    let project = ProjectTrustProjectId::from_bytes(project.into_bytes());
    let original_trust = saved.trust_record();
    let retained = trust.load(project).unwrap();
    assert_eq!(retained, original_trust);
    assert_eq!(retained.token(), original_trust.token());
    {
        let writer = store.inner.writer.lock().unwrap();
        execution_node::register_local_linux_node(
            &writer,
            saved.authority,
            epoch,
            execution_node::LinuxNodeDescriptor { capacity: 1 },
            30,
        )
        .unwrap();
        execution_node::heartbeat_local_linux_node(&writer, saved.authority, epoch, 30).unwrap();
    }
    (store, trust, epoch)
}
pub(super) fn trust(trust: &ProjectTrustStore, a: &Area) {
    let project: ProjectId = a.project.parse().unwrap();
    let record = trust
        .load(ProjectTrustProjectId::from_bytes(project.into_bytes()))
        .unwrap();
    assert_eq!(record, a.trust_record());
    assert_eq!(record.token(), a.trust_record().token());
}
