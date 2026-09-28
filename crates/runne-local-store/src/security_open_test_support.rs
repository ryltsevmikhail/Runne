use std::{
    sync::{Mutex, OnceLock},
    thread::ThreadId,
};

pub use crate::security_open_test_support_v8::downgrade_to_v8_for_test;
pub use crate::security_open_test_support_v8::fail_after_v8_payload_scrub_once_for_test;

type OpenHook = Box<dyn FnOnce() + Send>;

struct OpenHooks {
    owner: Option<ThreadId>,
    before: Option<OpenHook>,
    after: Option<OpenHook>,
}

static HOOKS: OnceLock<Mutex<OpenHooks>> = OnceLock::new();

fn hooks() -> &'static Mutex<OpenHooks> {
    HOOKS.get_or_init(|| {
        Mutex::new(OpenHooks {
            owner: None,
            before: None,
            after: None,
        })
    })
}

#[allow(clippy::missing_panics_doc)]
pub fn install_admitted_open_hooks(
    before: impl FnOnce() + Send + 'static,
    after: impl FnOnce() + Send + 'static,
) {
    let current = std::thread::current().id();
    let mut state = hooks().lock().expect("hook lock");
    assert!(
        state.owner.is_none() || state.owner == Some(current),
        "admitted open hooks belong to another test thread"
    );
    state.owner = Some(current);
    state.before = Some(Box::new(before));
    state.after = Some(Box::new(after));
}

pub(crate) fn before_admitted_open() {
    let current = std::thread::current().id();
    let hook = hooks().lock().ok().and_then(|mut state| {
        (state.owner == Some(current))
            .then(|| state.before.take())
            .flatten()
    });
    if let Some(hook) = hook {
        hook();
    }
}

pub(crate) fn after_admitted_open() {
    let current = std::thread::current().id();
    let hook = hooks().lock().ok().and_then(|mut state| {
        if state.owner != Some(current) {
            return None;
        }
        state.owner = None;
        state.before = None;
        state.after.take()
    });
    if let Some(hook) = hook {
        hook();
    }
}

/// Re-seals an admitted V8 store as V7 for migration-only tests.
///
/// # Errors
///
/// Returns an error unless the current security anchor and test mutation can
/// be committed as one exact V7 state.
pub fn downgrade_to_v7_for_test(
    store: &mut crate::LocalStore,
    secure: &dyn runne_secure_store::SecureStore,
    mutate_sql: &str,
) -> Result<(), crate::SecurityStateError> {
    let context = store
        .security
        .clone()
        .ok_or(crate::SecurityStateError::AdmissionFailed)?;
    let lock = secure.acquire_security_profile_lock(context.profile)?;
    let current = crate::security_recovery::verify_persisted_anchor_chain(
        &store.connection,
        secure,
        &lock,
        context.profile,
        context.database,
    )?;
    let transaction = store.connection.transaction()?;
    transaction.execute_batch(
        "DROP TABLE replay_promotion_pending; DROP TABLE replay_active_generations; DROP TABLE replay_shadow_events; DROP TABLE replay_shadow_generations; PRAGMA user_version=7; UPDATE meta SET schema_version=7;",
    )?;
    transaction.execute_batch(mutate_sql)?;
    let generation = current
        .generation
        .checked_add(1)
        .ok_or(crate::SecurityStateError::InvalidTransition)?;
    let digest = crate::security_state_root::protected_state_root(&transaction)?;
    let seal = secure.seal_security_transaction(
        &lock,
        context.database,
        generation,
        digest,
        current.digest(),
    )?;
    let next = runne_secure_store::SecurityAnchorV1::new(
        context.profile,
        context.database,
        generation,
        digest,
        current.digest(),
        seal,
    )?;
    transaction.execute(
        "INSERT INTO security_transactions VALUES (?1,?2,?3,?4,1)",
        rusqlite::params![
            i64::try_from(generation).map_err(|_| crate::SecurityStateError::InvalidTransition)?,
            digest.to_vec(),
            current.digest().to_vec(),
            next.sealed_transaction.as_bytes(),
        ],
    )?;
    transaction.execute(
        "UPDATE meta SET db_generation=?1,last_transaction_digest=?2,commit_marker=1 WHERE singleton=1",
        rusqlite::params![
            i64::try_from(generation).map_err(|_| crate::SecurityStateError::InvalidTransition)?,
            lower_hex(&digest),
        ],
    )?;
    transaction.commit()?;
    secure.compare_and_advance_anchor(&lock, &current, &next)?;
    Ok(())
}

fn lower_hex(value: &[u8]) -> String {
    use std::fmt::Write as _;
    value
        .iter()
        .fold(String::with_capacity(value.len() * 2), |mut out, byte| {
            write!(&mut out, "{byte:02x}").expect("writing to String is infallible");
            out
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
    };

    #[test]
    fn another_thread_cannot_consume_an_installed_hook_pair() {
        let before_calls = Arc::new(AtomicUsize::new(0));
        let after_calls = Arc::new(AtomicUsize::new(0));
        let before = Arc::clone(&before_calls);
        let after = Arc::clone(&after_calls);
        install_admitted_open_hooks(
            move || {
                before.fetch_add(1, Ordering::SeqCst);
            },
            move || {
                after.fetch_add(1, Ordering::SeqCst);
            },
        );

        thread::spawn(|| {
            before_admitted_open();
            after_admitted_open();
        })
        .join()
        .unwrap();
        assert_eq!(before_calls.load(Ordering::SeqCst), 0);
        assert_eq!(after_calls.load(Ordering::SeqCst), 0);

        before_admitted_open();
        after_admitted_open();
        assert_eq!(before_calls.load(Ordering::SeqCst), 1);
        assert_eq!(after_calls.load(Ordering::SeqCst), 1);
    }
}
