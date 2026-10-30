//! Shared genuine fresh fixture setup; neither ownerless recovery nor a service launch.
use super::{
    context::CaseContext,
    fixture::Fixture,
    metadata::{Area, Capture, Kind},
};
use crate::{schema, store::LocalCommandPermissionCaptureV1};
use runne_application::{
    permission_modes::LocalCommandPermissionBindingV1, project_trust::ProjectTrustPersistence,
};

pub(super) const WORKLOAD: &str = "printf once >> effect-marker; printf 'ready\n'; while [ ! -f proceed ]; do :; done; printf forbidden >> forbidden-marker";

pub(super) fn fixture(context: &CaseContext) -> Fixture {
    context.check_roots();
    let nested = tempfile::Builder::new()
        .prefix("running-")
        .tempdir_in(&context.root.path)
        .unwrap();
    let f = Fixture::with_root(nested);
    context.deadline.check();
    f
}

pub(super) fn saved(
    context: &CaseContext,
    f: &Fixture,
    kind: Kind,
    b: &LocalCommandPermissionBindingV1,
    captured: &LocalCommandPermissionCaptureV1,
    identity: Vec<u8>,
) -> Area {
    let trust = f.trust.load(f.trust_id()).unwrap();
    let (authority, lineage) = {
        let writer = f.store.inner.writer.lock().unwrap();
        (
            schema::read_authority_id(&writer).unwrap().unwrap(),
            schema::read_event_log_lineage_id(&writer).unwrap().unwrap(),
        )
    };
    let id = b.assignment();
    let value = Area {
        version: 1,
        kind,
        context: context.record.clone(),
        writer_pid: std::process::id(),
        nested: f
            .root
            .path()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned(),
        authority,
        lineage: lineage.to_string(),
        project: f.project.to_string(),
        workspace: f.scope.workspace_id.to_string(),
        principal: f.principal.as_str().into(),
        node: id.node_id.0.clone(),
        epoch: id.node_epoch,
        area: identity,
        command_digest: *b.command_intent_digest().as_bytes(),
        capture: Capture::of(captured),
        trust_status: "Trusted".into(),
        trust_epoch: trust.instance_epoch,
        trust_revision: trust.revision,
        trust_mask: trust.managed_deny_mask,
    };
    value.validate(context);
    assert_eq!(value.identity(), *id);
    assert_eq!(value.trust_record(), trust);
    value
}
