//! MODEL callback/area only. Never constructs a native child or executes a command.
use super::super::{burn_guard, owner::PermissionRootFenceRequestV1, release_guard};
use super::{approval, ceremony, fixture::Fixture, target};
use crate::store::LocalCommandPermissionCaptureV1;
use runne_application::{
    permission_modes::LocalCommandPermissionBindingV1, ports::EventStoreError,
    project_trust::ProjectTrustEffectLease,
};
use runne_platform::local_command_linux::PreparedPermissionTargetV1;

pub(super) struct Case {
    pub(super) f: Fixture,
    pub(super) b: LocalCommandPermissionBindingV1,
    pub(super) capture: LocalCommandPermissionCaptureV1,
    pub(super) prepared: PreparedPermissionTargetV1,
    pub(super) area: [u8; 100],
}
impl Case {
    pub(super) fn new(admitted: bool) -> Self {
        Self::in_mode(
            admitted,
            runne_application::permission_modes::PermissionMode::RiskBased,
        )
    }
    pub(super) fn in_mode(
        admitted: bool,
        mode: runne_application::permission_modes::PermissionMode,
    ) -> Self {
        let f = Fixture::new();
        ceremony::commit(&f, mode, 0);
        let (b, capture, prepared) = target::capture(&f);
        if admitted {
            let id = approval::confirm(&f, &b);
            f.store
                .admit_local_command_permission(&b, Some(id))
                .unwrap();
        }
        let mut area = [1; 100];
        area[..4].copy_from_slice(b"RMA1");
        area[52..68].copy_from_slice(b.assignment().taskrun_id.as_bytes());
        area[68..84].copy_from_slice(b.assignment().attempt_id.as_bytes());
        Self {
            f,
            b,
            capture,
            prepared,
            area,
        }
    }
    pub(super) fn lease(&self) -> Box<dyn ProjectTrustEffectLease> {
        self.f
            .store
            .inner
            .permission_owner
            .as_ref()
            .unwrap()
            .acquire_effect_lease(&self.f.store.runtime_authority_id, self.f.trust_id())
            .unwrap()
    }
    fn request(&self) -> PermissionRootFenceRequestV1 {
        PermissionRootFenceRequestV1::new(
            self.f.scope.workspace_id,
            self.b.workspace_version(),
            self.b.admitted_root_version(),
            *self.b.held_root_identity_digest().as_bytes(),
        )
    }
    pub(super) fn burn(&self, lease: &dyn ProjectTrustEffectLease) -> Result<(), EventStoreError> {
        let owner = self.f.store.inner.permission_owner.as_ref().unwrap();
        let mut writer = self.f.store.inner.writer.lock().unwrap();
        let tx = writer
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        let request = self.request();
        let root = owner
            .acquire_root_fence(&self.f.store.runtime_authority_id, &request)
            .unwrap();
        burn_guard::commit_in_tx(
            &tx,
            &self.f.store,
            self.b.assignment(),
            self.b.claim_stream_version(),
            &self.b,
            &self.area,
            self.capture.binding_digest,
            root.as_ref(),
            lease,
        )?;
        tx.commit().map_err(|_| EventStoreError::Unavailable)
    }
    pub(super) fn release_model(
        &self,
        lease: &dyn ProjectTrustEffectLease,
        fault: u8,
    ) -> (Result<(), EventStoreError>, usize) {
        self.release_observed(lease, fault, self.prepared.observation())
    }
    pub(super) fn release_observed(
        &self,
        lease: &dyn ProjectTrustEffectLease,
        fault: u8,
        observation: runne_platform::local_command_linux::PermissionTargetObservationV1,
    ) -> (Result<(), EventStoreError>, usize) {
        let owner = self.f.store.inner.permission_owner.as_ref().unwrap();
        let mut writer = self.f.store.inner.writer.lock().unwrap();
        if fault == 2 {
            // TEMP-only storage fault; no permission or authority row is manufactured.
            writer.execute_batch("CREATE TEMP TABLE model_parent(id INTEGER PRIMARY KEY); CREATE TEMP TABLE model_child(parent INTEGER REFERENCES model_parent(id) DEFERRABLE INITIALLY DEFERRED);").unwrap();
        }
        if fault == 1 {
            // Fault injection only: refuse the production postcallback running CAS.
            writer.execute_batch("CREATE TEMP TRIGGER refuse_model_running BEFORE UPDATE OF state ON taskrun_local_command_attempts WHEN NEW.state='running' BEGIN SELECT RAISE(ABORT,'model running CAS failure'); END;").unwrap();
        }
        let tx = writer
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        let request = self.request();
        let root = owner
            .acquire_root_fence(&self.f.store.runtime_authority_id, &request)
            .unwrap();
        let observed = release_guard::ReleaseObservation::from_prepared(observation);
        let mut count = 0;
        let result = release_guard::with_release_preconditions(
            &tx,
            &self.f.store,
            self.b.assignment(),
            self.b.claim_stream_version(),
            &self.b,
            &self.area,
            self.capture.binding_digest,
            lease,
            root.as_ref(),
            &observed,
            || {
                count += 1;
                if fault == 2 {
                    tx.execute("INSERT INTO model_child(parent) VALUES(1)", [])
                        .map_err(|_| EventStoreError::Unavailable)?;
                }
                Ok(())
            },
        );
        let result = result.and_then(|()| tx.commit().map_err(|_| EventStoreError::Unavailable));
        (result, count)
    }
    pub(super) fn spent_on_owned_reopen(&self) -> i64 {
        let path = self.f.root.path().join("runtime/daemon/store.sqlite");
        let reopened =
            crate::schema::open_managed_connection(&path, crate::schema::ConnectionMode::Reader)
                .unwrap();
        let (capture, context) =
            super::super::retained_policy_rows::load(&reopened, self.b.assignment().taskrun_id)
                .unwrap();
        assert_eq!(capture.binding_digest, self.capture.binding_digest);
        assert!(
            context.is_some(),
            "newly owned database retains checked original context"
        );
        reopened.query_row("SELECT count(*) FROM x2_permission_spent WHERE taskrun_id=?1 AND binding_digest=?2",
            rusqlite::params![self.b.assignment().taskrun_id.as_bytes(), self.capture.binding_digest.as_slice()], |r| r.get(0)).unwrap()
    }
}
