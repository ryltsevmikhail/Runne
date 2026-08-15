use gocode_app_core::{AppCore, RuntimeMode};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Semaphore;

#[cfg(feature = "test-support")]
use std::time::Duration;
#[cfg(feature = "test-support")]
use tokio::{io::AsyncReadExt, net::TcpListener, sync::Notify};

#[derive(Debug, serde::Serialize)]
struct IpcError {
    code: &'static str,
}

#[path = "../src/operational_telemetry_command.rs"]
mod operational_telemetry_command;

#[test]
fn command_returns_the_app_core_sanitized_telemetry_projection() {
    let directory = tempfile::tempdir().expect("temporary profile directory");
    let core = AppCore::open_with_runtime_mode(
        &directory.path().join("profile.sqlite3"),
        RuntimeMode::Bundled,
    )
    .expect("open core");

    let snapshot = operational_telemetry_command::operational_telemetry_at(&core, 10)
        .unwrap_or_else(|_| panic!("telemetry snapshot"));

    assert_eq!(
        serde_json::to_value(snapshot).expect("serialize telemetry snapshot"),
        json!({
            "schemaVersion": 1,
            "observedAtUnixSeconds": 10,
            "runtime": {
                "meta": {
                    "observedAtUnixSeconds": 10,
                    "freshness": "unavailable",
                    "completeness": "unavailable",
                },
                "snapshot": null,
            },
            "hostLifecycle": {
                "meta": {
                    "observedAtUnixSeconds": 10,
                    "freshness": "observed_in_current_cycle",
                    "completeness": "complete",
                },
                "runtimeMode": "bundled",
                "current": {
                    "lifecycle": "starting",
                    "failure": null,
                    "restartOrdinal": 0,
                    "runtimeLaunchGeneration": 0,
                    "observedAtUnixSeconds": 0,
                },
                "events": [],
                "eventStatus": "complete_since_app_core_start",
                "lastAllocatedSequence": null,
                "producerDroppedEventCount": 0,
                "producerDropCounterSaturated": false,
                "evictedEventCount": 0,
                "evictionCounterSaturated": false,
            },
        }),
    );
}

#[test]
fn command_projection_excludes_sensitive_key_names() {
    let directory = tempfile::tempdir().expect("temporary profile directory");
    let core = AppCore::open_with_runtime_mode(
        &directory.path().join("profile.sqlite3"),
        RuntimeMode::Bundled,
    )
    .expect("open core");

    let snapshot = operational_telemetry_command::operational_telemetry_at(&core, 10)
        .unwrap_or_else(|_| panic!("telemetry snapshot"));
    reject_forbidden_keys(&serde_json::to_value(snapshot).expect("serialize telemetry snapshot"));
}

#[cfg(feature = "test-support")]
#[tokio::test]
async fn stalled_telemetry_peer_is_single_flight_and_keeps_ipc_responsive() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let address = listener.local_addr().expect("address");
    let requested = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let server_requested = Arc::clone(&requested);
    let server_release = Arc::clone(&release);
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("first telemetry request");
        let mut request = [0_u8; 1024];
        assert!(stream.read(&mut request).await.expect("read request") > 0);
        server_requested.notify_one();
        server_release.notified().await;
        drop(stream);
        let (mut stream, _) = listener.accept().await.expect("later telemetry request");
        assert!(stream.read(&mut request).await.expect("read request") > 0);
    });
    let directory = tempfile::tempdir().expect("temporary profile directory");
    let core = Arc::new(
        gocode_app_core::test_support::open_protected_bundled_workspace_core(
            &directory.path().join("profile.sqlite3"),
            address,
        )
        .await
        .expect("core"),
    );

    let gate = Arc::new(Semaphore::new(1));
    let telemetry = tokio::spawn(
        operational_telemetry_command::operational_telemetry_from_core_with_gate(
            Arc::clone(&core),
            Arc::clone(&gate),
        ),
    );
    tokio::time::timeout(Duration::from_secs(1), requested.notified())
        .await
        .expect("stalled peer received telemetry request");
    telemetry.abort();
    let _ = telemetry.await;
    let Err(excess) = tokio::time::timeout(
        Duration::from_millis(100),
        operational_telemetry_command::operational_telemetry_from_core_with_gate(
            Arc::clone(&core),
            Arc::clone(&gate),
        ),
    )
    .await
    .expect("burst telemetry must not queue") else {
        panic!("burst telemetry must be rejected");
    };
    assert_eq!(
        serde_json::to_value(excess).expect("serialize static error"),
        json!({ "code": "operational_telemetry_unavailable" }),
    );
    let (ipc_sender, ipc_receiver) = tokio::sync::oneshot::channel();
    tokio::spawn(async move { ipc_sender.send(()).expect("send unrelated IPC progress") });
    tokio::time::timeout(Duration::from_millis(100), ipc_receiver)
        .await
        .expect("unrelated IPC work must progress")
        .expect("unrelated IPC completion");

    release.notify_one();
    let permit = tokio::time::timeout(Duration::from_secs(1), Arc::clone(&gate).acquire_owned())
        .await
        .expect("worker must release the gate after completion");
    drop(permit);
    let snapshot =
        operational_telemetry_command::operational_telemetry_from_core_with_gate(core, gate)
            .await
            .expect("later telemetry projection");
    assert!(snapshot.runtime().snapshot().is_none());
    server.await.expect("server");
}

#[tokio::test]
#[allow(clippy::significant_drop_tightening)]
async fn worker_panic_closes_to_the_static_telemetry_error() {
    let gate = Arc::new(Semaphore::new(1));
    let permit = Arc::clone(&gate)
        .try_acquire_owned()
        .expect("worker admission");
    let Err(error) = operational_telemetry_command::run_telemetry_blocking::<
        gocode_app_core::OperationalTelemetrySnapshotV1,
        _,
    >(permit, || panic!("test worker panic"))
    .await
    else {
        panic!("worker panic must close");
    };

    assert_eq!(
        serde_json::to_value(error).expect("serialize static error"),
        json!({ "code": "operational_telemetry_unavailable" }),
    );
}

fn reject_forbidden_keys(value: &Value) {
    const FORBIDDEN: [&str; 9] = [
        "path",
        "credential",
        "secret",
        "authority",
        "accessToken",
        "authToken",
        "apiKey",
        "rawToken",
        "debug",
    ];

    match value {
        Value::Array(values) => values.iter().for_each(reject_forbidden_keys),
        Value::Object(object) => {
            assert!(object.keys().all(|key| !FORBIDDEN.contains(&key.as_str())));
            object.values().for_each(reject_forbidden_keys);
        }
        _ => {}
    }
}
