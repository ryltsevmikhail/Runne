//! Daemon-owned HTTP serving boundary.
//!
//! Router composition belongs to the daemon application root. This module
//! owns only listener lifecycle, accepted connections, and orderly ingress
//! shutdown.

use crate::error::DaemonError;
use crate::shutdown::{RuntimeTaskSupervisor, graceful_shutdown};
use axum::Router;
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

trait HttpListener: Send + Sync + 'static {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    fn accept(&self) -> impl Future<Output = io::Result<Self::Stream>> + Send;
}

impl HttpListener for TcpListener {
    type Stream = tokio::net::TcpStream;

    async fn accept(&self) -> io::Result<Self::Stream> {
        TcpListener::accept(self).await.map(|(stream, _)| stream)
    }
}

/// A bound local HTTP host for a caller-composed router.
pub struct HttpHost {
    listener: TcpListener,
    app: Router,
}

/// An owned HTTP-host task and its ingress-stop signal.
pub struct HttpHostTask {
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<Result<(), DaemonError>>,
}

/// Stops HTTP ingress and confirms every accepted connection task has exited.
pub async fn stop_http_host(host_task: &mut HttpHostTask) -> Result<(), DaemonError> {
    if let Some(shutdown) = host_task.shutdown.take() {
        let _ = shutdown.send(());
    }

    http_host_result((&mut host_task.task).await)
}

/// Observes either an external shutdown signal or HTTP-host termination, then
/// fences and drains registered runtime work before returning.
pub async fn run_http_host_until_shutdown<F>(
    mut host_task: HttpHostTask,
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
            let stop_result = stop_http_host(&mut host_task).await;
            signal_result.and(stop_result)
        }
        task_result = &mut host_task.task => http_host_result(task_result),
    };

    let drain_result = graceful_shutdown(supervisor, shutdown_timeout_ms).await;
    match (host_result, drain_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Ok(())) => Err(error),
        (Err(host_error), Err(drain_error)) => Err(DaemonError::Bootstrap(format!(
            "HTTP host failed: {host_error}; graceful shutdown failed: {drain_error}"
        ))),
    }
}

impl HttpHost {
    /// Binds the configured address before accepting requests.
    pub async fn bind(http_bind: &str, app: Router) -> Result<Self, DaemonError> {
        Ok(Self {
            listener: TcpListener::bind(http_bind).await?,
            app,
        })
    }

    /// Returns the actual bound address, including an OS-assigned port.
    pub fn local_addr(&self) -> Result<SocketAddr, DaemonError> {
        Ok(self.listener.local_addr()?)
    }

    /// Starts the owned accept loop.
    pub fn start(self) -> HttpHostTask {
        start_http_host(self.listener, self.app)
    }

    /// Serves the supplied router until the caller signals shutdown.
    pub async fn serve<F>(self, shutdown: F) -> Result<(), DaemonError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        serve_http(self.listener, self.app, shutdown).await
    }
}

fn start_http_host<L>(listener: L, app: Router) -> HttpHostTask
where
    L: HttpListener,
{
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(serve_http(listener, app, async move {
        let _ = shutdown_rx.await;
    }));
    HttpHostTask {
        shutdown: Some(shutdown_tx),
        task,
    }
}

async fn serve_http<L, F>(listener: L, app: Router, shutdown: F) -> Result<(), DaemonError>
where
    L: HttpListener,
    F: Future<Output = ()> + Send + 'static,
{
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
                        "HTTP connection task failed: {error}"
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
                "HTTP connection task failed during shutdown: {error}"
            )));
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn http_host_result(
    task_result: Result<Result<(), DaemonError>, JoinError>,
) -> Result<(), DaemonError> {
    match task_result {
        Err(error) => Err(DaemonError::Bootstrap(format!(
            "HTTP host task failed: {error}"
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

    impl HttpListener for FailingListener {
        type Stream = DuplexStream;

        fn accept(&self) -> impl Future<Output = io::Result<Self::Stream>> + Send {
            std::future::ready(Err(io::Error::other("injected accept failure")))
        }
    }

    #[tokio::test]
    async fn accept_failure_triggers_daemon_fence_and_drain_before_returning_error() {
        let supervisor = RuntimeTaskSupervisor::new();
        let active_task = supervisor.register();
        let host_task = start_http_host(FailingListener, Router::new());
        let daemon_supervisor = Arc::clone(&supervisor);
        let daemon = tokio::spawn(async move {
            run_http_host_until_shutdown(
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
