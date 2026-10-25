//! Owned guest-only fixtures. Logical approval is not trusted Human authentication.
use super::super::{approval, ceremony, fixture::Fixture, target};
use runne_application::{
    permission_modes::{
        LocalCommandPermissionBindingV1, NativeScopeAdmissionReceipt, PermissionMode,
    },
    project_trust::{ProjectTrustPersistence, ProjectTrustStatus},
};
use runne_platform::{
    local_command_linux::{PermissionChildV1, PreparedPermissionTargetV1},
    process_managed_area::{LinuxManagedArea, LinuxManagedAreaRoot, ManagedAreaBinding},
};
use std::time::Duration;

pub(super) fn admitted() -> (
    Fixture,
    LocalCommandPermissionBindingV1,
    PreparedPermissionTargetV1,
    NativeScopeAdmissionReceipt,
    (runne_domain::id::ApprovalId, Vec<u8>),
) {
    let f = Fixture::new();
    ceremony::commit(&f, PermissionMode::RiskBased, 0);
    let elf = std::fs::read("/bin/sh").expect("installed guest shell ELF");
    assert!(elf.starts_with(b"\x7fELF"));
    let (b, prepared) = target::prepare_with_executable(
        &f,
        vec![
            "tool".into(),
            "-c".into(),
            "printf once >> effect-marker".into(),
        ],
        &elf,
    );
    assert!(!marker(&f).exists());
    f.store
        .capture_local_command_permission(&b, prepared.observation())
        .unwrap();
    let id = approval::confirm_native_fixture(&f, &b);
    let receipt = f
        .store
        .admit_local_command_permission(&b, Some(id))
        .unwrap();
    let proof = approval::durable(&f, &b, id);
    (f, b, prepared, receipt, (id, proof))
}

pub(super) fn marker(f: &Fixture) -> std::path::PathBuf {
    f.root.path().join("workspace/effect-marker")
}

pub(super) fn revoke(f: &Fixture) {
    let authority: [u8; 16] = hex::decode(&f.scope.runtime_authority_id.0)
        .unwrap()
        .try_into()
        .unwrap();
    let path = f.root.path().join("runtime/daemon/trust.sqlite");
    // Distinct connection, not a clone of the registered owner's shared handle.
    let independent = crate::ProjectTrustStore::open(&path, authority).unwrap();
    let before = independent.load(f.trust_id()).unwrap();
    assert_eq!(before.status, ProjectTrustStatus::Trusted);
    let after = independent
        .commit(
            f.trust_id(),
            ProjectTrustStatus::Untrusted,
            0,
            before.token(),
        )
        .unwrap();
    assert_eq!(after.instance_epoch, before.instance_epoch);
    assert_eq!(after.revision, before.revision + 1);
    assert_eq!(after.status, ProjectTrustStatus::Untrusted);
    drop(independent);
    let reopened = crate::ProjectTrustStore::open(&path, authority).unwrap();
    assert_eq!(reopened.load(f.trust_id()).unwrap(), after);
    assert_eq!(f.trust.load(f.trust_id()).unwrap(), after);
}

pub(super) struct Area(Option<LinuxManagedArea>);
impl Area {
    pub(super) fn new(b: &LocalCommandPermissionBindingV1) -> Self {
        let root = LinuxManagedAreaRoot::open_current_cgroup().expect("delegated guest root");
        let id = b.assignment();
        let area = root
            .create_area(
                ManagedAreaBinding::new(
                    *id.taskrun_id.as_bytes(),
                    *id.attempt_id.as_bytes(),
                    *b.invocation_id().as_bytes(),
                )
                .unwrap(),
            )
            .expect("new owned guest area");
        Self(Some(area))
    }
    pub(super) fn get(&self) -> &LinuxManagedArea {
        self.0.as_ref().unwrap()
    }
    pub(super) fn finish(mut self) {
        let area = self.0.take().unwrap();
        area.prove_empty().unwrap().revalidate().unwrap();
        area.remove_empty().expect("remove proven empty owned area");
    }
}
impl Drop for Area {
    fn drop(&mut self) {
        if let Some(area) = self.0.take() {
            let result = area.remove_empty();
            eprintln!("R05_FAILURE_AREA_CLEANUP {result:?}");
        }
    }
}

pub(super) struct Child<'a> {
    pub(super) child: PermissionChildV1<'a>,
    armed: bool,
}
impl<'a> Child<'a> {
    pub(super) fn new(child: PermissionChildV1<'a>) -> Self {
        Self { child, armed: true }
    }
    pub(super) fn stopped(&mut self) {
        self.child
            .terminate_area(Duration::from_millis(20))
            .unwrap();
        self.child.reap_after_stop(Duration::from_secs(2)).unwrap();
        self.armed = false;
    }
    pub(super) fn exited(&mut self) {
        self.armed = false;
    }
}
impl Drop for Child<'_> {
    fn drop(&mut self) {
        if self.armed {
            let stop = self.child.terminate_area(Duration::from_millis(20));
            let reap = self.child.reap_after_stop(Duration::from_secs(2));
            eprintln!("R05_FAILURE_CHILD_CLEANUP stop={stop:?} reap={reap:?}");
        }
    }
}
