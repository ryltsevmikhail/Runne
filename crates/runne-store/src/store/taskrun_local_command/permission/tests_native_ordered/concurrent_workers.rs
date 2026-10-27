//! Independent trust writer and observer; neither owns a native child or root guard.
use crate::{ProjectTrustStore, project_trust_store::concurrent_test_support::{
    BusyConfig, with_busy_probe,
}};
use runne_application::project_trust::{
    ProjectTrustPersistence, ProjectTrustProjectId, ProjectTrustRecord,
};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
    sync::{Arc, atomic::{AtomicBool, Ordering}, mpsc::{Receiver, SyncSender}},
    time::{Duration, Instant},
};

#[derive(Clone)]
pub(super) struct Context {
    pub(super) path: PathBuf,
    pub(super) authority: [u8; 16],
    pub(super) project: ProjectTrustProjectId,
    pub(super) trusted: ProjectTrustRecord,
    pub(super) generation: [u8; 16],
    pub(super) deadline: Instant,
    pub(super) cancel: Arc<AtomicBool>,
}

pub(super) fn receive<T>(
    receiver: &Receiver<T>, deadline: Instant, cap: Duration, cancel: &AtomicBool,
) -> Result<T, String> {
    if cancel.load(Ordering::SeqCst) { return Err("protocol cancelled".into()); }
    let remaining = deadline.checked_duration_since(Instant::now())
        .ok_or("protocol deadline")?;
    let value = receiver.recv_timeout(cap.min(remaining))
        .map_err(|_| "protocol channel timeout/disconnect")?;
    if cancel.load(Ordering::SeqCst) { return Err("protocol cancelled".into()); }
    Ok(value)
}

pub(super) fn caught<T>(body: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or_else(|_| Err("worker panicked".into()))
}

// Collection deliberately ignores cancellation: a failed peer still has an outcome.
pub(super) fn collect(receiver: &Receiver<()>, deadline: Instant) -> Result<(), String> {
    match deadline.checked_duration_since(Instant::now()) {
        Some(remaining) => receiver.recv_timeout(remaining)
            .map_err(|_| "worker completion timeout/disconnect".into()),
        None => receiver.try_recv().map_err(|_| "worker completion past deadline".into()),
    }
}

fn open(context: &Context) -> Result<ProjectTrustStore, String> {
    let store = ProjectTrustStore::open(&context.path, context.authority)
        .map_err(|_| "worker trust open")?;
    if store.load(context.project).map_err(|_| "worker trusted load")? != context.trusted {
        return Err("worker initial trust mismatch".into());
    }
    Ok(store)
}

pub(super) fn revoke(
    context: Context,
    ready: SyncSender<Result<(), String>>,
    phase: Receiver<()>,
    contention: SyncSender<[u8; 16]>,
) -> Result<(ProjectTrustRecord, usize), String> {
    let result = caught(|| {
        let store = open(&context)?;
        with_busy_probe(&store, BusyConfig {
            cancel: context.cancel.clone(), deadline: context.deadline,
            generation: context.generation, contention,
        }, |probe| {
            ready.try_send(Ok(())).map_err(|_| "revoker ready delivery")?;
            receive(&phase, context.deadline, Duration::from_secs(3), &context.cancel)?;
            probe.revoke(context.project, context.trusted)
        }).map_err(|errors| errors.join("; "))
    });
    // If setup failed, wake the coordinator. Only the done outcome is authoritative.
    if let Err(error) = &result { let _ = ready.try_send(Err(error.clone())); }
    result
}

struct Permit {
    sender: SyncSender<()>,
    cancel: Arc<AtomicBool>,
    approved: bool,
}
impl Drop for Permit {
    fn drop(&mut self) {
        if !self.approved { self.cancel.store(true, Ordering::SeqCst); }
        if self.sender.try_send(()).is_err() { self.cancel.store(true, Ordering::SeqCst); }
    }
}

pub(super) fn observe(
    context: Context,
    ready: SyncSender<Result<(), String>>,
    phase: Receiver<()>,
    contention: Receiver<[u8; 16]>,
    permit: SyncSender<()>,
    marker: PathBuf,
    expected: Vec<u8>,
) -> Result<(), String> {
    let mut permit = Permit { sender: permit, cancel: context.cancel.clone(), approved: false };
    let result = caught(|| {
        let store = open(&context)?;
        ready.try_send(Ok(())).map_err(|_| "observer ready delivery")?;
        receive(&phase, context.deadline, Duration::from_secs(3), &context.cancel)?;
        let generation = receive(
            &contention, context.deadline, Duration::from_secs(3), &context.cancel,
        )?;
        if generation != context.generation { return Err("wrong contention generation".into()); }
        // Separate connection; query_row finishes without retaining a read transaction.
        if store.load(context.project).map_err(|_| "observer current trusted load")?
            != context.trusted
        { return Err("trust changed while effect lease held".into()); }
        let nonce_deadline = context.deadline.min(Instant::now() + Duration::from_secs(2));
        for _ in 0..2000 {
            if context.cancel.load(Ordering::SeqCst) || Instant::now() >= nonce_deadline {
                return Err("observer nonce deadline/cancellation".into());
            }
            match std::fs::read(&marker) {
                Ok(bytes) => match nonce_complete(&bytes, &expected)? {
                    true => return Ok(()),
                    false => {}
                },
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err("observer nonce read failed".into()),
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        Err("observer nonce iteration cap".into())
    });
    if let Err(error) = &result { let _ = ready.try_send(Err(error.clone())); }
    permit.approved = result.is_ok();
    // Drop sends success only after exact physical nonce AND fresh trusted read.
    drop(permit);
    result
}

// Opening the marker precedes its first write. Only exact completion grants permission.
fn nonce_complete(bytes: &[u8], expected: &[u8]) -> Result<bool, String> {
    if expected.is_empty() { return Err("empty expected nonce".into()); }
    if bytes == expected { return Ok(true); }
    if expected.starts_with(bytes) { return Ok(false); }
    Err("wrong/overlong/duplicate nonce".into())
}

#[test]
fn nonce_publication_waits_for_complete_bytes() {
    let expected = b"nonce\n";
    // Deterministic create-before-write and partial-write observations.
    for bytes in [b"".as_slice(), b"n", b"non", b"nonce"] {
        assert_eq!(nonce_complete(bytes, expected), Ok(false));
    }
    assert_eq!(nonce_complete(expected, expected), Ok(true));
    for bytes in [b"wrong".as_slice(), b"nonce\nnonce\n", b"nonce\nx"] {
        assert!(nonce_complete(bytes, expected).is_err());
    }
    assert!(nonce_complete(b"", b"").is_err());
}
