//! Coordinator owns only channels; synchronous native release stays on its caller.
use super::{concurrent_fence::Control, concurrent_workers::{self as workers, Context}};
use super::super::fixture::Fixture;
use crate::ProjectTrustStore;
use runne_application::{
    ports::EventStoreError,
    project_trust::{ProjectTrustPersistence, ProjectTrustStatus},
};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
    sync::{Arc, atomic::{AtomicBool, Ordering}, mpsc::{self, Receiver, SyncSender}},
    time::{Duration, Instant},
};

pub(super) struct Race {
    pub(super) control: Arc<Control>,
    cancel: Arc<AtomicBool>,
    revoker_phase: Receiver<()>,
    observer_phase: Receiver<()>,
    permit: SyncSender<()>,
}

struct CancelBeforeJoin {
    cancel: Arc<AtomicBool>,
    permit: SyncSender<()>,
    success: bool,
}
impl CancelBeforeJoin {
    fn cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
        let _ = self.permit.try_send(());
    }
}
impl Drop for CancelBeforeJoin {
    fn drop(&mut self) { if !self.success { self.cancel(); } }
}

impl Race {
    pub(super) fn new() -> Self {
        let cancel = Arc::new(AtomicBool::new(false));
        let (revoker, revoker_phase) = mpsc::sync_channel(1);
        let (observer, observer_phase) = mpsc::sync_channel(1);
        let (permit, receive_permit) = mpsc::sync_channel(1);
        let control = Control::new(cancel.clone(), revoker, observer, receive_permit);
        Self { control, cancel, revoker_phase, observer_phase, permit }
    }

    pub(super) fn run<T>(
        self, fixture: &Fixture, marker: &Path, expected: &[u8],
        release: impl FnOnce() -> Result<T, EventStoreError>,
    ) -> Result<T, String> {
        // Stricter than v2: race8s includes setup, not just post-ready phases.
        // Post-race output/stop/drain/empty use their separate bounded cleanup budgets.
        let deadline = Instant::now() + Duration::from_secs(8);
        let authority: [u8; 16] = hex::decode(&fixture.scope.runtime_authority_id.0)
            .map_err(|_| "fixture authority decode")?.try_into()
            .map_err(|_| "fixture authority length")?;
        let project = fixture.trust_id();
        let trusted = fixture.trust.load(project).map_err(|_| "initial trust load")?;
        if trusted.status != ProjectTrustStatus::Trusted || trusted.managed_deny_mask != 0 {
            return Err("expected genuine trusted all-allow fixture".into());
        }
        let context = Context {
            path: fixture.root.path().join("runtime/daemon/trust.sqlite"),
            authority, project, trusted,
            generation: uuid::Uuid::now_v7().into_bytes(), deadline,
            cancel: self.cancel.clone(),
        };
        let (revoke_ready_tx, revoke_ready) = mpsc::sync_channel(1);
        let (observe_ready_tx, observe_ready) = mpsc::sync_channel(1);
        let (contention_tx, contention) = mpsc::sync_channel(1);
        let (revoke_done_tx, revoke_done) = mpsc::sync_channel(1);
        let (observe_done_tx, observe_done) = mpsc::sync_channel(1);
        let marker = marker.to_path_buf();
        let expected = expected.to_vec();
        let control = self.control;
        let cancel = self.cancel;
        let path = context.path.clone();
        let result = std::thread::scope(|scope| {
            // This guard is local to the scope body: Drop precedes implicit joins.
            // It also covers partial spawn, setup failure and release panic.
            let mut cleanup = CancelBeforeJoin {
                cancel: cancel.clone(), permit: self.permit.clone(), success: false,
            };
            let revoke_context = context.clone();
            let revoker = scope.spawn(move || {
                let result = workers::revoke(
                    revoke_context, revoke_ready_tx, self.revoker_phase, contention_tx,
                );
                let _ = revoke_done_tx.try_send(());
                result
            });
            let observer = scope.spawn(move || {
                let result = workers::observe(
                    context, observe_ready_tx, self.observer_phase, contention,
                    self.permit, marker, expected,
                );
                let _ = observe_done_tx.try_send(());
                result
            });
            // No assertion/unwrap after arm; all errors unwind the cancellation guard.
            let setup = (|| {
                workers::receive(&revoke_ready, deadline, Duration::from_secs(2), &cancel)??;
                workers::receive(&observe_ready, deadline, Duration::from_secs(2), &cancel)??;
                control.arm(deadline).map_err(str::to_owned)
            })();
            let released = match setup {
                Ok(()) => catch_unwind(AssertUnwindSafe(release))
                    .map_err(|_| "native release panicked".to_owned())
                    .and_then(|result| result.map_err(|_| "native release failed".to_owned())),
                Err(error) => Err(error),
            };
            if released.is_err() { cleanup.cancel(); }
            // Collect BOTH worker outcomes, even when one has failed.
            let revoke_completed = workers::collect(&revoke_done, deadline);
            if revoke_completed.is_err() { cleanup.cancel(); }
            let observe_completed = workers::collect(&observe_done, deadline);
            if observe_completed.is_err() { cleanup.cancel(); }
            let revoke_join = revoker.join();
            let observe_join = observer.join();
            let mut errors = Vec::new();
            for completion in [revoke_completed, observe_completed] {
                if let Err(error) = completion { errors.push(error); }
            }
            let revoked = match revoke_join {
                Ok(Ok(record)) => Some(record),
                Ok(Err(error)) => { errors.push(error); None }
                Err(_) => { errors.push("revoker thread panic".into()); None }
            };
            match observe_join {
                Ok(Ok(())) => {}
                Ok(Err(error)) => errors.push(error),
                Err(_) => errors.push("observer thread panic".into()),
            }
            let value = match released {
                Ok(value) => Some(value),
                Err(error) => { errors.push(error); None }
            };
            if !errors.is_empty() { return Err(errors.join("; ")); }
            let (record, calls) = revoked.ok_or("missing revoke outcome")?;
            if calls == 0 || record.status != ProjectTrustStatus::Untrusted
                || record.instance_epoch != trusted.instance_epoch
                || trusted.revision.checked_add(1) != Some(record.revision)
                || record.managed_deny_mask != 0
            { return Err("durable revoke CAS mismatch".into()); }
            control.finish().map_err(str::to_owned)?;
            cleanup.success = true;
            Ok((value.ok_or("missing native release outcome")?, record))
        });
        let (value, revoked) = result?;
        // A new connection AFTER both collected workers; not daemon/process restart.
        let reopened = ProjectTrustStore::open(&path, authority).map_err(|_| "reopen revoked trust")?;
        if reopened.load(project).map_err(|_| "read reopened revoke")? != revoked {
            return Err("reopened durable revoke mismatch".into());
        }
        Ok(value)
    }
}
