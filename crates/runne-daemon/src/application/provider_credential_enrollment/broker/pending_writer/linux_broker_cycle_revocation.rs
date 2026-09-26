//! Opt-in production CLI writer + daemon broker Revoke lost-ACK/reopen evidence.
use super::*;
use runne_provider::*;
use std::process::Command;
#[path = "linux_broker_cycle_revocation/fixture.rs"]
mod fixture;
#[path = "linux_broker_cycle_revocation/kill_fixture.rs"]
mod kill_fixture;
#[path = "linux_broker_cycle_revocation/native.rs"]
mod native;
#[path = "linux_broker_cycle_revocation/revoke_after_kill.rs"]
mod revoke_after_kill;
#[path = "linux_broker_cycle_revocation/writer.rs"]
mod writer;
use fixture::DurableFixture;
use fixture::unix_now;
use kill_fixture::PostDeleteKillFixture;
use native::{NativeItemCleanup, assert_native_absent, item_service, reconcile_native};
use revoke_after_kill::revoke_through_real_writer_after_delete_kill;
use writer::{pair_through_real_writer, production_cli};

#[test]
#[ignore = "requires owner DBus + keyutils session and RUNNE_NATIVE_SECRET_SERVICE_E2E=1"]
fn linux_production_writer_revoke_lost_ack_recovers_after_sqlite_reopen() {
    assert!(std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some());
    assert_eq!(
        std::env::var("RUNNE_NATIVE_SECRET_SERVICE_E2E").as_deref(),
        Ok("1")
    );
    assert!(
        Command::new("keyctl")
            .args(["show", "@s"])
            .status()
            .unwrap()
            .success()
    );
    let binary = production_cli();
    let mut fixture = DurableFixture::new();
    let version = fixture
        .operation
        .allocated_credential_version()
        .unwrap()
        .clone();
    let service = item_service(&version);
    let _cleanup = NativeItemCleanup::new(&service);
    _cleanup.clear();

    pair_through_real_writer(&mut fixture, &binary);
    let paired = fixture
        .store()
        .load_operation(fixture.operation.operation_id())
        .unwrap();
    assert_eq!(paired.state(), CredentialOperationState::Completed);
    let head = fixture
        .store()
        .lifecycle_snapshot(paired.provider())
        .unwrap();
    let target = head.active_version().unwrap().clone();
    assert_eq!(target, version);
    let revoke = fixture.begin_revoke(target);
    let fenced = fixture
        .store()
        .lifecycle_snapshot(revoke.provider())
        .unwrap();
    assert_eq!(fenced.lifecycle_revision().get(), 3);
    assert_eq!(fenced.fence().get(), 3);
    assert!(fenced.active_version().is_none());

    let kill_fixture = PostDeleteKillFixture::new();
    let killed_pid = revoke_through_real_writer_after_delete_kill(
        &mut fixture,
        &binary,
        &service,
        &kill_fixture,
    );
    assert!(!std::path::Path::new(&format!("/proc/{killed_pid}")).exists());
    let claimed = fixture
        .store()
        .load_operation(revoke.operation_id())
        .unwrap();
    assert_eq!(claimed.state(), CredentialOperationState::Claimed);
    assert_native_absent(&service);

    fixture.close_store();
    fixture.reopen_store();
    reconcile_native(&fixture, &binary, unix_now());
    let completed = fixture
        .store()
        .load_operation(revoke.operation_id())
        .unwrap();
    assert_eq!(completed.state(), CredentialOperationState::Completed);
    assert_eq!(
        completed.metadata().readback_disposition(),
        Some(CredentialReadbackDisposition::ExactAbsence)
    );
    let recovered = fixture
        .store()
        .lifecycle_snapshot(completed.provider())
        .unwrap();
    assert_eq!(recovered.fence(), fenced.fence());
    assert!(recovered.active_version().is_none());
    assert_native_absent(&service);
    assert!(
        fixture.stale_pair_begin().is_err(),
        "old revision/fence must remain denied"
    );
    assert_eq!(
        fixture
            .store()
            .lifecycle_snapshot(completed.provider())
            .unwrap(),
        recovered
    );
}
