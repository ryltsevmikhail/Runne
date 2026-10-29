//! Explicit lifetime for short-lived external clients. No asynchronous Drop work.
use crate::canonical::RuntimeCredential;
use crate::{RuntimeApiError, RuntimeApiErrorKind};
use std::{cell::RefCell, future::Future, time::Duration};

tokio::task_local! {
    static SESSIONS: RefCell<Vec<SessionCleanup>>;
}
struct SessionCleanup {
    client: reqwest::Client,
    origin: String,
    credential: RuntimeCredential,
}

/// Runs a command and awaits release of every external local session opened inline.
///
/// Use for short-lived CLI commands; clients must not escape the scope. Spawned
/// tasks do not inherit it. Protected desktop sessions are not registered.
/// Returns the command outcome unchanged, separately from cleanup failure so
/// callers never mistake a successful mutation for a failed/retryable command.
/// Cancellation/process death still relies on the server's bounded session TTL.
pub async fn with_local_session_cleanup<T>(
    command: impl Future<Output = T>,
) -> (T, Result<(), RuntimeApiError>) {
    SESSIONS
        .scope(RefCell::new(Vec::new()), async {
            let output = command.await;
            let sessions = SESSIONS.with(RefCell::take);
            let mut cleanup = Ok(());
            for session in sessions {
                if let Err(error) = session.close().await {
                    cleanup = Err(error);
                }
            }
            (output, cleanup)
        })
        .await
}

pub(super) fn register(client: &reqwest::Client, origin: &str, credential: &RuntimeCredential) {
    let _ = SESSIONS.try_with(|sessions| {
        sessions.borrow_mut().push(SessionCleanup {
            client: client.clone(),
            origin: origin.to_owned(),
            credential: credential.clone(),
        });
    });
}
impl SessionCleanup {
    async fn close(self) -> Result<(), RuntimeApiError> {
        let response = self
            .client
            .post(format!("{}/v1/local-session/close", self.origin))
            .header(
                reqwest::header::AUTHORIZATION,
                self.credential.authorization_header()?,
            )
            .timeout(Duration::from_secs(2))
            .send()
            .await
            .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::Unavailable))?;
        match response.status().as_u16() {
            204 => Ok(()),
            401 => Err(RuntimeApiError::new(RuntimeApiErrorKind::Unauthorized)),
            _ => Err(RuntimeApiError::new(RuntimeApiErrorKind::Unavailable)),
        }
    }
}
