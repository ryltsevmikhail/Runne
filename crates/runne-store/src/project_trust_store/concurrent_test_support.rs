//! Guest-test-only busy observation on the actual private trust commit connection.
use super::ProjectTrustStore;
use runne_application::project_trust::{
    ProjectTrustPersistence, ProjectTrustProjectId, ProjectTrustRecord, ProjectTrustStatus,
};
use std::{
    cell::{Cell, RefCell},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::SyncSender,
    },
    time::{Duration, Instant},
};

pub(crate) struct BusyConfig {
    pub(crate) cancel: Arc<AtomicBool>,
    pub(crate) deadline: Instant,
    pub(crate) generation: [u8; 16],
    pub(crate) contention: SyncSender<[u8; 16]>,
}

struct State {
    config: BusyConfig,
    active: bool,
    calls: usize,
    notified: bool,
}

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
    static FAILED: Cell<bool> = const { Cell::new(false) };
}

fn busy(count: i32) -> bool {
    let retry = catch_unwind(AssertUnwindSafe(|| busy_inner(count))).unwrap_or(false);
    if !retry { FAILED.with(|failed| failed.set(true)); }
    retry
}

fn busy_inner(count: i32) -> bool {
    let retry = STATE.with(|slot| {
        let Ok(mut slot) = slot.try_borrow_mut() else { return false; };
        let Some(state) = slot.as_mut() else { return false; };
        if !state.active || count < 0 || state.calls >= 2000
            || state.config.cancel.load(Ordering::SeqCst)
            || Instant::now() >= state.config.deadline
        { return false; }
        state.calls += 1;
        if !state.notified {
            if state.config.contention.try_send(state.config.generation).is_err() {
                return false;
            }
            state.notified = true;
        }
        true
    });
    if !retry { return false; }
    std::thread::sleep(Duration::from_millis(1));
    true
}

pub(crate) struct BusyProbe<'a> {
    store: &'a ProjectTrustStore,
    invoked: Cell<bool>,
}

impl BusyProbe<'_> {
    /// Exactly one actual CAS call; no second attempt after a busy/storage error.
    pub(crate) fn revoke(
        &self,
        project: ProjectTrustProjectId,
        trusted: ProjectTrustRecord,
    ) -> Result<ProjectTrustRecord, String> {
        if self.invoked.replace(true) { return Err("second revoke call".into()); }
        STATE.with(|slot| {
            let mut slot = slot.try_borrow_mut().map_err(|_| "busy TLS borrow")?;
            slot.as_mut().ok_or("busy TLS missing")?.active = true;
            Ok::<_, &'static str>(())
        }).map_err(str::to_owned)?;
        let result = self.store.commit(project, ProjectTrustStatus::Untrusted, 0, trusted.token());
        STATE.with(|slot| {
            let mut slot = slot.try_borrow_mut().map_err(|_| "busy TLS borrow")?;
            slot.as_mut().ok_or("busy TLS missing")?.active = false;
            Ok::<_, &'static str>(())
        }).map_err(str::to_owned)?;
        result.map_err(|_| "actual revoke commit failed".into())
    }
}

/// Body installs readiness/phase waits, then invokes probe.revoke exactly once.
/// All body errors/panics pass through callback restoration and TLS disposal.
pub(crate) fn with_busy_probe<T>(
    store: &ProjectTrustStore,
    config: BusyConfig,
    body: impl FnOnce(&BusyProbe<'_>) -> Result<T, String>,
) -> Result<(T, usize), Vec<String>> {
    let initialized = STATE.with(|slot| {
        let Ok(mut slot) = slot.try_borrow_mut() else { return false; };
        if slot.is_some() { return false; }
        *slot = Some(State { config, active: false, calls: 0, notified: false });
        true
    });
    if !initialized { return Err(vec!["nested busy probe".into()]); }
    FAILED.with(|failed| failed.set(false));
    let mut errors = Vec::new();
    let install = store.connection.lock()
        .map_err(|_| "busy install poisoned connection")
        .and_then(|connection| connection.busy_handler(Some(busy))
            .map_err(|_| "busy install failed"));
    let probe = BusyProbe { store, invoked: Cell::new(false) };
    let value = match install {
        Ok(()) => match catch_unwind(AssertUnwindSafe(|| body(&probe))) {
            Ok(Ok(value)) => Some(value),
            Ok(Err(error)) => { errors.push(error); None }
            Err(_) => { errors.push("busy probe body panicked".into()); None }
        },
        Err(error) => { errors.push(error.into()); None }
    };
    // Restore the factory profile, not a permanently disabled busy handler.
    if store.connection.lock()
        .map_err(|_| ())
        .and_then(|connection| connection.busy_timeout(Duration::from_millis(5000))
            .map_err(|_| ())).is_err()
    { errors.push("busy timeout restoration failed".into()); }
    let state = STATE.with(|slot| slot.try_borrow_mut().ok().and_then(|mut slot| slot.take()));
    let calls = match state {
        Some(state) => {
            if state.active || !state.notified || state.calls == 0 {
                errors.push("missing completed attributed contention".into());
            }
            state.calls
        }
        None => { errors.push("busy TLS disposal failed".into()); 0 }
    };
    if FAILED.with(|failed| failed.replace(false)) {
        errors.push("busy callback refused or failed".into());
    }
    if !probe.invoked.get() { errors.push("revoke not invoked".into()); }
    if errors.is_empty() {
        match value {
            Some(value) => Ok((value, calls)),
            None => Err(vec!["busy probe missing value".into()]),
        }
    } else { Err(errors) }
}
