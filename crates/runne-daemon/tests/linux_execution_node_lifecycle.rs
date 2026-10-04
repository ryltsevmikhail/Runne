#[path = "support/owner_private.rs"]
mod owner_private;

#[cfg(target_os = "linux")]
mod linux {
    use runne_daemon::application::DaemonApplication;
    use runne_daemon::config::{BuiltInDefaults, ConfigurationSnapshot};
    use runne_daemon::error::DaemonError;
    use rusqlite::Connection;
    use std::time::Duration;
    use tokio::sync::oneshot;

    struct Running {
        stop: oneshot::Sender<()>,
        task: tokio::task::JoinHandle<Result<(), DaemonError>>,
    }

    async fn start(config: &ConfigurationSnapshot) -> Running {
        let app = DaemonApplication::start(config).await.unwrap();
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(app.run(async move {
            stopped
                .await
                .map_err(|_| DaemonError::Bootstrap("test shutdown sender dropped".into()))
        }));
        Running { stop, task }
    }

    fn row(path: &str) -> Option<(Vec<u8>, i64, i64, i64, i64)> {
        Connection::open(path).unwrap().query_row(
            "SELECT node_id,launch_generation,capacity,heartbeat_at_ms,expires_at_ms FROM execution_nodes",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        ).ok()
    }

    async fn wait_for_generation(path: &str, generation: i64) -> (Vec<u8>, i64, i64, i64, i64) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(registration) = row(path)
                    && registration.1 == generation
                {
                    return registration;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("daemon should register before accepting requests")
    }

    async fn wait_for_heartbeat_after(
        path: &str,
        generation: i64,
        heartbeat_at_ms: i64,
    ) -> (Vec<u8>, i64, i64, i64, i64) {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if let Some(registration) = row(path)
                    && registration.1 == generation
                    && registration.3 > heartbeat_at_ms
                {
                    return registration;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("daemon should advance the node heartbeat within its liveness window")
    }

    async fn stop(running: Running) {
        running.stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), running.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn daemon_registers_heartbeats_expires_and_restarts_in_a_new_epoch() {
        let directory = super::owner_private::tempdir();
        let mut defaults = BuiltInDefaults::new(directory.path());
        defaults.http_bind = "127.0.0.1:0".into();
        let config = ConfigurationSnapshot::from_defaults(&defaults);
        let app = DaemonApplication::start(&config).await.unwrap();
        let connection = Connection::open(&config.db_path).unwrap();
        let authority: Vec<u8> = connection
            .query_row(
                "SELECT authority_id FROM _authority WHERE id=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let generation: String = connection
            .query_row(
                "SELECT value FROM _daemon_info WHERE key='launch_generation'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let initial = row(&config.db_path)
            .expect("application start registers its Linux execution node before returning");
        assert_eq!(initial.1, generation.parse::<i64>().unwrap());
        assert_eq!(initial.0, authority);
        assert_eq!(initial.0.len(), 16);
        assert_eq!(initial.2, 1);
        assert_eq!(initial.4 - initial.3, 30_000);

        let (stop_sender, stopped) = oneshot::channel();
        let first = Running {
            stop: stop_sender,
            task: tokio::spawn(app.run(async move {
                stopped
                    .await
                    .map_err(|_| DaemonError::Bootstrap("test shutdown sender dropped".into()))
            })),
        };

        let refreshed = wait_for_heartbeat_after(&config.db_path, initial.1, initial.3).await;
        assert_eq!(refreshed.1, initial.1);
        assert!(refreshed.3 > initial.3);
        assert_eq!(refreshed.4 - refreshed.3, 30_000);
        stop(first).await;
        let stopped_at = row(&config.db_path).unwrap().3;
        tokio::time::sleep(Duration::from_secs(11)).await;
        assert_eq!(row(&config.db_path).unwrap().3, stopped_at);

        let second = start(&config).await;
        let restarted = wait_for_generation(&config.db_path, initial.1 + 1).await;
        assert_eq!(restarted.0, initial.0);
        assert_eq!(restarted.1, initial.1 + 1);
        stop(second).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn expired_epoch_fails_closed_without_same_epoch_resurrection() {
        let directory = super::owner_private::tempdir();
        let mut defaults = BuiltInDefaults::new(directory.path());
        defaults.http_bind = "127.0.0.1:0".into();
        let config = ConfigurationSnapshot::from_defaults(&defaults);
        let app = DaemonApplication::start(&config).await.unwrap();
        let address = app.local_addr().unwrap();
        let task = tokio::spawn(app.run(std::future::pending::<Result<(), DaemonError>>()));
        let registered = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(registration) = row(&config.db_path) {
                    break registration;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        Connection::open(&config.db_path)
            .unwrap()
            .execute(
                "UPDATE execution_nodes SET expires_at_ms=heartbeat_at_ms+1 WHERE node_id=?1",
                [&registered.0],
            )
            .unwrap();

        let result = tokio::time::timeout(Duration::from_secs(20), task)
            .await
            .expect("expired heartbeat must stop daemon")
            .unwrap();
        assert!(result.is_err(), "expired epoch must fail closed");
        assert!(std::net::TcpStream::connect(address).is_err());
        let after = row(&config.db_path).unwrap();
        assert_eq!(after.1, registered.1);
        assert_eq!(after.3, registered.3);
        assert_eq!(after.4, registered.3 + 1);
    }
}

#[cfg(not(target_os = "linux"))]
#[tokio::test]
async fn non_linux_control_daemon_does_not_register_an_execution_node() {
    use runne_daemon::application::DaemonApplication;
    use runne_daemon::config::{BuiltInDefaults, ConfigurationSnapshot};
    use runne_daemon::error::DaemonError;
    use rusqlite::Connection;
    use std::time::Duration;
    use tokio::sync::oneshot;

    let directory = owner_private::tempdir();
    let mut defaults = BuiltInDefaults::new(directory.path());
    defaults.http_bind = "127.0.0.1:0".into();
    let config = ConfigurationSnapshot::from_defaults(&defaults);
    let app = DaemonApplication::start(&config).await.unwrap();
    let (stop, stopped) = oneshot::channel();
    let (started, running) = oneshot::channel();
    let task = tokio::spawn(app.run(async move {
        let _ = started.send(());
        stopped
            .await
            .map_err(|_| DaemonError::Bootstrap("test shutdown sender dropped".into()))
    }));
    tokio::time::timeout(Duration::from_secs(2), running)
        .await
        .expect("daemon run should reach its shutdown wait")
        .expect("daemon run should signal startup");
    let count: i64 = Connection::open(&config.db_path)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM execution_nodes", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
}
