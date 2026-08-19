//! Crate-owned TLS serving boundary for the sealed local runtime host.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as ConnectionBuilder;
use runne_api::{
    ConversationCommandHostPort, ConversationQueryHostPort, RuntimeSessionBinding,
    TaskRunCommandHostPort, TaskRunQueryHostPort,
};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, oneshot};
use tokio::task::{JoinHandle, JoinSet};
use tower::ServiceExt;

use crate::admission::AdmissionState;
use crate::conversations::ConversationHttpState;
use crate::health::HealthState;
use crate::local_session::VerifiedLocalTls;
use crate::replay::ReplayHttpState;
use crate::router::SecureLocalHttpHost;
use crate::runtime_profile::RuntimeProfileHttpState;
use crate::task_runs::TaskRunHttpState;

mod operational_telemetry;
mod project_workspace;

const PRE_AUTH_HANDSHAKE_LIMIT: usize = 32;
const PRE_AUTH_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(1);
const TOTAL_CONNECTION_LIMIT: usize = 64;
const HTTP_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(2);
const HTTP2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);
const HTTP2_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Redacted local TLS host failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LocalRuntimeTlsHostError {
    #[error("local runtime TLS listener is unavailable")]
    Unavailable,
    #[error("local runtime TLS host composition is incompatible")]
    Incompatible,
}

/// Bound peer-authenticated local runtime host.
///
/// The protected router and TLS verification capability never leave this crate.
pub struct LocalRuntimeTlsHost {
    listener: TcpListener,
    host: SecureLocalHttpHost,
    server_config: Arc<rustls::ServerConfig>,
}

/// Owned local runtime host task and ingress stop authority.
pub struct LocalRuntimeTlsHostTask {
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<Result<(), LocalRuntimeTlsHostError>>,
}

impl LocalRuntimeTlsHost {
    /// Binds loopback TLS and composes all canonical routes behind session auth.
    #[allow(clippy::too_many_arguments)]
    pub async fn bind<T, C>(
        bind: &str,
        server_config: Arc<rustls::ServerConfig>,
        health_state: HealthState,
        admission_state: AdmissionState,
        local_session_service: Arc<Mutex<runne_application::local_session::LocalSessionService>>,
        binding: RuntimeSessionBinding,
        dynamic_session_binding: bool,
        clock: Arc<dyn Fn() -> Duration + Send + Sync>,
        runtime_profile_state: RuntimeProfileHttpState,
        task_run_state: TaskRunHttpState<T>,
        conversation_state: ConversationHttpState<C>,
        replay_state: ReplayHttpState,
    ) -> Result<Self, LocalRuntimeTlsHostError>
    where
        T: TaskRunCommandHostPort + TaskRunQueryHostPort + 'static,
        C: ConversationCommandHostPort + ConversationQueryHostPort + 'static,
    {
        let listener = TcpListener::bind(bind)
            .await
            .map_err(|_| LocalRuntimeTlsHostError::Unavailable)?;
        if !listener
            .local_addr()
            .map_err(|_| LocalRuntimeTlsHostError::Unavailable)?
            .ip()
            .is_loopback()
        {
            return Err(LocalRuntimeTlsHostError::Unavailable);
        }
        let verified_tls = VerifiedLocalTls::from_verified_listener();
        let host = SecureLocalHttpHost::new(
            verified_tls,
            health_state,
            admission_state,
            local_session_service,
            binding,
            dynamic_session_binding,
            clock,
            runtime_profile_state,
            task_run_state,
            conversation_state,
            replay_state,
        )
        .map_err(|_| LocalRuntimeTlsHostError::Incompatible)?;
        Ok(Self {
            listener,
            host,
            server_config,
        })
    }

    /// Returns the actual loopback address, including an OS-assigned port.
    pub fn local_addr(&self) -> Result<SocketAddr, LocalRuntimeTlsHostError> {
        self.listener
            .local_addr()
            .map_err(|_| LocalRuntimeTlsHostError::Unavailable)
    }

    /// Returns the exact cap for unauthenticated TLS handshakes.
    #[must_use]
    pub const fn pre_auth_handshake_limit(&self) -> usize {
        PRE_AUTH_HANDSHAKE_LIMIT
    }

    /// Returns the cap held for every accepted connection's full lifetime.
    #[must_use]
    pub const fn total_connection_limit(&self) -> usize {
        TOTAL_CONNECTION_LIMIT
    }

    /// Starts the owned TLS accept loop.
    #[must_use]
    pub fn start(self) -> LocalRuntimeTlsHostTask {
        let (shutdown, stopped) = oneshot::channel();
        let task = tokio::spawn(serve(
            self.listener,
            self.host,
            self.server_config,
            async move {
                let _ = stopped.await;
            },
        ));
        LocalRuntimeTlsHostTask {
            shutdown: Some(shutdown),
            task,
        }
    }
}

impl LocalRuntimeTlsHostTask {
    /// Runs until either the caller's shutdown completes or the host terminates.
    pub async fn run_until<F, E>(mut self, shutdown: F) -> Result<(), E>
    where
        F: Future<Output = Result<(), E>>,
        E: From<LocalRuntimeTlsHostError>,
    {
        tokio::pin!(shutdown);
        tokio::select! {
            signal = &mut shutdown => {
                if let Some(stop) = self.shutdown.take() {
                    let _ = stop.send(());
                }
                let host = self.task.await.map_err(|_| LocalRuntimeTlsHostError::Unavailable)?;
                signal.and(host.map_err(E::from))
            }
            host = &mut self.task => {
                host.map_err(|_| LocalRuntimeTlsHostError::Unavailable)?
                    .map_err(E::from)
            }
        }
    }
}

async fn serve<F>(
    listener: TcpListener,
    host: SecureLocalHttpHost,
    server_config: Arc<rustls::ServerConfig>,
    shutdown: F,
) -> Result<(), LocalRuntimeTlsHostError>
where
    F: Future<Output = ()>,
{
    let mut connections = JoinSet::new();
    let handshakes = Arc::new(Semaphore::new(PRE_AUTH_HANDSHAKE_LIMIT));
    let total_connections = Arc::new(Semaphore::new(TOTAL_CONNECTION_LIMIT));
    let service = host.into_router();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                stop_connections(&mut connections).await;
                return Ok(());
            }
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    let Ok(connection_permit) =
                        Arc::clone(&total_connections).try_acquire_owned()
                    else {
                        continue;
                    };
                    let Ok(permit) = Arc::clone(&handshakes).try_acquire_owned() else {
                        continue;
                    };
                    let service = service.clone();
                    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(&server_config));
                    connections.spawn(async move {
                        let Ok(Ok(stream)) = tokio::time::timeout(
                            PRE_AUTH_HANDSHAKE_TIMEOUT,
                            acceptor.accept(stream),
                        )
                        .await
                        else {
                            return;
                        };
                        drop(permit);
                        let http = service_fn(move |request| {
                            let service = service.clone();
                            async move {
                                service
                                    .oneshot(request.map(axum::body::Body::new))
                                    .await
                            }
                        });
                        let mut builder = ConnectionBuilder::new(TokioExecutor::new());
                        builder
                            .http1()
                            .timer(TokioTimer::new())
                            .header_read_timeout(Some(HTTP_HEADER_READ_TIMEOUT));
                        builder
                            .http2()
                            .timer(TokioTimer::new())
                            .keep_alive_interval(Some(HTTP2_KEEP_ALIVE_INTERVAL))
                            .keep_alive_timeout(HTTP2_KEEP_ALIVE_TIMEOUT)
                            .max_concurrent_streams(Some(32));
                        let _ = builder.serve_connection(TokioIo::new(stream), http).await;
                        drop(connection_permit);
                    });
                }
                Err(_) => {
                    stop_connections(&mut connections).await;
                    return Err(LocalRuntimeTlsHostError::Unavailable);
                }
            },
            joined = connections.join_next(), if !connections.is_empty() => {
                if joined.is_some_and(|result| result.is_err()) {
                    stop_connections(&mut connections).await;
                    return Err(LocalRuntimeTlsHostError::Unavailable);
                }
            }
        }
    }
}

async fn stop_connections(connections: &mut JoinSet<()>) {
    connections.abort_all();
    while connections.join_next().await.is_some() {}
}
