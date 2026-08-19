#[cfg(unix)]
#[tokio::test]
async fn daemon_composes_managed_bootstrap_reservation_store() {
    use std::path::Path;
    use std::time::Duration;

    use runne_daemon::{
        application::DaemonApplication,
        config::{BuiltInDefaults, ConfigurationSnapshot},
    };
    use runne_runtime_client::LocalRuntimeProfile;

    let directory = tempfile::tempdir().unwrap();
    secure_directory(directory.path());
    let mut config = ConfigurationSnapshot::from_defaults(&BuiltInDefaults::new(directory.path()));
    config.http_bind = "127.0.0.1:0".into();
    let profile_path = Path::new(&config.replay_integrity_key_path)
        .parent()
        .unwrap()
        .join("client-profile.json");
    let database_path = config.db_path.clone();
    let application = DaemonApplication::start(&config).await.unwrap();
    let (shutdown, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(application.run(async move {
        let _ = stopped.await;
        Ok::<(), runne_daemon::error::DaemonError>(())
    }));

    LocalRuntimeProfile::load(&profile_path)
        .unwrap()
        .connect(Duration::from_secs(10))
        .await
        .unwrap();

    shutdown.send(()).unwrap();
    task.await.unwrap().unwrap();
    let connection = rusqlite::Connection::open(database_path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM bootstrap_reservations WHERE reservation_state='CONSUMED'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1,
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM bootstrap_reservation_tombstones",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1,
    );
}

#[cfg(unix)]
fn secure_directory(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(not(unix))]
#[test]
fn daemon_composes_managed_bootstrap_reservation_store() {
    // Native owner-ACL profile validation remains fail closed off Unix.
}
