//! Daemon-owned HTTP serving boundary.
//!
//! This host deliberately publishes only the health endpoint. Command,
//! query, replay, and OpenCode session routers are not composed until their
//! production runtime dependencies exist.

use crate::error::DaemonError;
use crate::shutdown::{RuntimeTaskSupervisor, graceful_shutdown};
use gocode_http::health::{HealthState, RecoveryState, health_router};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnectionBuilder;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::{JoinError, JoinHandle, JoinSet};
use tower::ServiceExt;

trait HealthListener: Send + Sync + 'static {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    fn accept(&self) -> impl Future<Output = io::Result<Self::Stream>> + Send;
}

impl HealthListener for TcpListener {
    type Stream = tokio::net::TcpStream;

    async fn accept(&self) -> io::Result<Self::Stream> {
        TcpListener::accept(self).await.map(|(stream, _)| stream)
    }
}

/// A bound local HTTP health host.
pub struct HealthHost {
    listener: TcpListener,
}

/// An owned health-host task and its ingress-stop signal.
pub struct HealthHostTask {
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<Result<(), DaemonError>>,
}

/// Stop the health host and confirm the listener task has exited before
/// proceeding with daemon drain.
pub async fn stop_health_host(host_task: &mut HealthHostTask) -> Result<(), DaemonError> {
    if let Some(shutdown) = host_task.shutdown.take() {
        let _ = shutdown.send(());
    }

    health_host_result((&mut host_task.task).await)
}

/// Observe either an external shutdown signal or health-host termination,
/// then fence and drain runtime work before returning the termination result.
pub async fn run_health_host_until_shutdown<F>(
    mut host_task: HealthHostTask,
    supervisor: &Arc<RuntimeTaskSupervisor>,
    shutdown_timeout_ms: u64,
    shutdown: F,
) -> Result<(), DaemonError>
where
    F: Future<Output = Result<(), DaemonError>>,
{
    tokio::pin!(shutdown);
    let host_result = tokio::select! {
        signal_result = &mut shutdown => {
            let stop_result = stop_health_host(&mut host_task).await;
            signal_result.and(stop_result)
        }
        task_result = &mut host_task.task => health_host_result(task_result),
    };

    let drain_result = graceful_shutdown(supervisor, shutdown_timeout_ms).await;
    match (host_result, drain_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Ok(())) => Err(error),
        (Err(host_error), Err(drain_error)) => Err(DaemonError::Bootstrap(format!(
            "health host failed: {host_error}; graceful shutdown failed: {drain_error}"
        ))),
    }
}

impl HealthHost {
    /// Bind the daemon's configured HTTP address before accepting requests.
    pub async fn bind(http_bind: &str) -> Result<Self, DaemonError> {
        Ok(Self {
            listener: TcpListener::bind(http_bind).await?,
        })
    }

    /// The actual bound address, including an OS-assigned port when requested.
    pub fn local_addr(&self) -> Result<SocketAddr, DaemonError> {
        Ok(self.listener.local_addr()?)
    }

    /// Start the owned accept loop and expose a handle for orderly stop.
    pub fn start(self) -> HealthHostTask {
        start_health_host(self.listener)
    }

    /// Serve health until the caller completes the graceful shutdown signal.
    pub async fn serve<F>(self, shutdown: F) -> Result<(), DaemonError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        serve_health(self.listener, shutdown).await
    }
}

fn start_health_host<L>(listener: L) -> HealthHostTask
where
    L: HealthListener,
{
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(serve_health(listener, async move {
        let _ = shutdown_rx.await;
    }));
    HealthHostTask {
        shutdown: Some(shutdown_tx),
        task,
    }
}

async fn serve_health<L, F>(listener: L, shutdown: F) -> Result<(), DaemonError>
where
    L: HealthListener,
    F: Future<Output = ()> + Send + 'static,
{
    let app = health_router(HealthState {
        recovery_state: RecoveryState::Ready,
    });
    let mut connections = JoinSet::new();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => return stop_connections(&mut connections).await,
            accepted = listener.accept() => {
                match accepted {
                    Ok(stream) => {
                        let app = app.clone();
                        connections.spawn(async move {
                            let service = service_fn(move |request| {
                                let app = app.clone();
                                async move {
                                    let response = match app
                                        .oneshot(request.map(axum::body::Body::new))
                                        .await
                                    {
                                        Ok(response) => response,
                                        Err(never) => match never {},
                                    };
                                    Ok::<_, std::convert::Infallible>(response)
                                }
                            });
                            let _ = ConnectionBuilder::new(TokioExecutor::new())
                                .serve_connection(TokioIo::new(stream), service)
                                .await;
                        });
                    }
                    Err(error) => {
                        stop_connections(&mut connections).await?;
                        return Err(error.into());
                    }
                }
            }
            joined = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = joined {
                    stop_connections(&mut connections).await?;
                    return Err(DaemonError::Bootstrap(format!(
                        "health connection task failed: {error}"
                    )));
                }
            }
        }
    }
}

async fn stop_connections(connections: &mut JoinSet<()>) -> Result<(), DaemonError> {
    connections.abort_all();
    let mut first_error = None;
    while let Some(joined) = connections.join_next().await {
        if let Err(error) = joined
            && !error.is_cancelled()
            && first_error.is_none()
        {
            first_error = Some(DaemonError::Bootstrap(format!(
                "health connection task failed during shutdown: {error}"
            )));
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn health_host_result(
    task_result: Result<Result<(), DaemonError>, JoinError>,
) -> Result<(), DaemonError> {
    match task_result {
        Err(error) => Err(DaemonError::Bootstrap(format!(
            "health host task failed: {error}"
        ))),
        Ok(result) => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use tokio::io::DuplexStream;

    struct FailingListener;

    impl HealthListener for FailingListener {
        type Stream = DuplexStream;

        fn accept(&self) -> impl Future<Output = io::Result<Self::Stream>> + Send {
            std::future::ready(Err(io::Error::other("injected accept failure")))
        }
    }

    #[tokio::test]
    async fn accept_failure_triggers_daemon_fence_and_drain_before_returning_error() {
        let supervisor = RuntimeTaskSupervisor::new();
        let active_task = supervisor.register();
        let host_task = start_health_host(FailingListener);
        let daemon_supervisor = Arc::clone(&supervisor);
        let daemon = tokio::spawn(async move {
            run_health_host_until_shutdown(
                host_task,
                &daemon_supervisor,
                1_000,
                std::future::pending::<Result<(), DaemonError>>(),
            )
            .await
        });

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !supervisor.is_fenced() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("accept failure must trigger the daemon shutdown fence");
        assert!(
            !daemon.is_finished(),
            "daemon must wait for registered runtime work to drain"
        );

        drop(active_task);
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), daemon)
            .await
            .expect("daemon must finish after runtime work drains")
            .expect("daemon orchestration task must not panic");
        let error = result.expect_err("accept failure must terminate the daemon");

        assert!(
            error.to_string().contains("injected accept failure"),
            "unexpected daemon error: {error}"
        );
        assert_eq!(supervisor.active_count(), 0);
        assert_eq!(supervisor.total_completed(), 1);
    }
}
