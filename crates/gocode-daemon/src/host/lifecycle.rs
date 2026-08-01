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
use tokio::sync::{Semaphore, oneshot};
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

/// A bound TLS-only local HTTP host for a caller-composed router.
pub struct TlsHttpHost {
    listener: TcpListener,
    app: Router,
    server_config: Arc<rustls::ServerConfig>,
}

/// An owned TLS HTTP-host task and its ingress-stop signal.
pub struct TlsHttpHostTask {
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<Result<(), DaemonError>>,
}

/// Stops TLS HTTP ingress and confirms every accepted connection task has exited.
pub async fn stop_tls_http_host(host_task: &mut TlsHttpHostTask) -> Result<(), DaemonError> {
    if let Some(shutdown) = host_task.shutdown.take() {
        let _ = shutdown.send(());
    }
    http_host_result((&mut host_task.task).await)
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

impl TlsHttpHost {
    /// Binds a TCP listener which accepts only TLS connections.
    pub async fn bind(
        http_bind: &str,
        app: Router,
        server_config: Arc<rustls::ServerConfig>,
    ) -> Result<Self, DaemonError> {
        Ok(Self {
            listener: TcpListener::bind(http_bind).await?,
            app,
            server_config,
        })
    }

    /// Returns the exact hard limit for unauthenticated TLS handshakes.
    pub const fn pre_auth_handshake_limit(&self) -> usize {
        32
    }

    /// Returns the actual bound address, including an OS-assigned port.
    pub fn local_addr(&self) -> Result<SocketAddr, DaemonError> {
        Ok(self.listener.local_addr()?)
    }

    /// Starts the TLS-only accept loop.
    pub fn start(self) -> TlsHttpHostTask {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(serve_tls_http(
            self.listener,
            self.app,
            self.server_config,
            async move {
                let _ = shutdown_rx.await;
            },
        ));
        TlsHttpHostTask {
            shutdown: Some(shutdown_tx),
            task,
        }
    }
}
