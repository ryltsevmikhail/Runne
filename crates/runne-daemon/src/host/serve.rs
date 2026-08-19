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

async fn serve_tls_http<F>(
    listener: TcpListener,
    app: Router,
    server_config: Arc<rustls::ServerConfig>,
    shutdown: F,
) -> Result<(), DaemonError>
where
    F: Future<Output = ()> + Send + 'static,
{
    let mut connections = JoinSet::new();
    let handshakes = Arc::new(Semaphore::new(32));
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => return stop_connections(&mut connections).await,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    let Ok(permit) = Arc::clone(&handshakes).try_acquire_owned() else { continue };
                    let app = app.clone();
                    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(&server_config));
                    connections.spawn(async move {
                        let _permit = permit;
                        let Ok(stream) = acceptor.accept(stream).await else { return };
                        let service = service_fn(move |request| {
                            let app = app.clone();
                            async move {
                                let response = match app.oneshot(request.map(axum::body::Body::new)).await {
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
            },
            joined = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = joined {
                    stop_connections(&mut connections).await?;
                    return Err(DaemonError::Bootstrap(format!("TLS HTTP connection task failed: {error}")));
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
