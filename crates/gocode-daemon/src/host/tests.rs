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
