use super::*;
use runne_provider::{CredentialBindingDigest, IssueCredentialTicketDigest};

#[test]
fn session_recovery_explicitly_supersedes_expired_attempt_but_not_live_attempt() {
    for expired in [false, true] {
        with_session(0, |mut session, mut desktop, control, operation, now| {
            let snapshot = control.store.load_operation(operation).unwrap();
            let head = control
                .store
                .lifecycle_snapshot(snapshot.provider())
                .unwrap();
            let measurements = &control.measurements;
            let old = control
                .store
                .accept_cleanup_recovery(CredentialCleanupRecoveryRequest::new(
                    operation,
                    snapshot.installation_owner_id(),
                    measurements.release_manifest_digest([9; 32]).unwrap(),
                    measurements.protected_session_id([55; 32]).unwrap(),
                    measurements.desktop_supervisor_generation(8).unwrap(),
                    7,
                    head.lifecycle_revision(),
                    head.fence(),
                    measurements.continuation_binding_digest([88; 32]).unwrap(),
                    30,
                ))
                .unwrap();
            let deadline = old.expires_at();
            control.store.attach_cleanup_recovery(old).unwrap();
            control
                .store
                .issue_ticket_attempt(
                    IssueCredentialTicketDigest::new(
                        operation,
                        CredentialBindingDigest::from_measured([89; 32]).unwrap(),
                        CredentialBindingDigest::from_measured([88; 32]).unwrap(),
                        30,
                    )
                    .unwrap(),
                )
                .unwrap();
            let now = if expired {
                // Drive the real reconciliation/high-water path, not wall-clock sleep.
                control.store.reconcile_online(deadline).unwrap();
                deadline as u64
            } else {
                now
            };
            let request = desktop
                .encode_desktop_request(operation.as_bytes())
                .unwrap();
            let response = session.offer_cleanup_recovery(&request, now);
            if !expired {
                assert!(response.is_err());
                assert!(session.take_bound_broker_handoff().is_err());
                return;
            }
            let exchange_now = exchange_time(&session, now);
            let offer = desktop
                .decode_daemon_offer(&response.unwrap(), exchange_now)
                .unwrap();
            assert_eq!(session.recovery.pending.as_ref().unwrap().1.attempt(), 2);
            let ack = desktop.encode_desktop_accept(&offer, exchange_now).unwrap();
            session.accept_cleanup_recovery(&ack, exchange_now).unwrap();
            assert_eq!(
                session.take_bound_broker_handoff().unwrap().operation_id(),
                operation
            );
            assert_eq!(
                control.store.load_operation(operation).unwrap().state(),
                runne_provider::CredentialOperationState::Prepared
            );
        });
    }
}
