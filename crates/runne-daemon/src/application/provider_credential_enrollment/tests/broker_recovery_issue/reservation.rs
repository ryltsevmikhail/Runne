use super::*;
use crate::application::provider_credential_enrollment::broker::{
    pending::{
        PendingBrokerEndpointHandoff,
        recovery::{PendingCleanupBrokerHandoff, PendingCleanupBrokerReservation},
    },
    rendezvous::DaemonOwnedUnixBrokerRendezvous,
};
use runne_api::{LaunchSecret, ProviderCredentialRequestAuthorityPair};

#[test]
fn recovery_reservation_preserves_witness_for_ticket_issuance_without_intent() {
    let (f, accepted) = recovery_fixture();
    let now = accepted.issued_at();
    let (issuer, verifier) = ProviderCredentialRequestAuthorityPair::new().split();
    let base = issuer
        .issue_base([3; 32], [9; 32], [17; 32], 8, [16; 32], 7, [12; 32])
        .unwrap();
    let keys = LaunchSecret::from_bytes([51; 32]).unwrap().derive_keys();
    let transfer = issuer.issue_recovery_broker_transfer(&keys, &base).unwrap();
    let rendezvous = DaemonOwnedUnixBrokerRendezvous::create().unwrap();
    let facts = (
        rendezvous.channel_binding(),
        rendezvous.publication_public_key(),
    );
    let reserved = PendingCleanupBrokerHandoff::try_from(PendingCleanupBrokerReservation {
        accepted,
        authority: &base,
        verifier: &verifier,
        measurements: &f.measurements,
        operation: &f.operation,
        rendezvous,
        transfer,
        now,
        expected_broker_evidence: runne_api::protected_credential_broker_evidence_binding(
            [9; 32], facts.0, facts.1,
        ),
    })
    .unwrap();
    let (endpoint, witness): (
        PendingBrokerEndpointHandoff,
        AcceptedCredentialCleanupRecovery,
    ) = reserved.into();
    assert_eq!(endpoint.operation_id(), f.operation.operation_id());
    assert_eq!(endpoint.rendezvous_facts(), facts);
    let context = f
        .broker
        .claim_issue_context(
            recovery_measurements(&f, [9; 32], [17; 32]),
            [21; 32],
            f.continuation,
            7,
            8,
        )
        .unwrap();
    let mut channel = RecordingChannel::default();
    assert!(
        f.broker
            .issue_ticket(
                witness,
                f.continuation,
                &context,
                20,
                &f.store,
                &mut channel
            )
            .is_ok()
    );
}

#[test]
fn recovery_reservation_rejects_substituted_context_expiry_and_endpoint() {
    for case in 0..9 {
        let (f, accepted) = recovery_fixture();
        let (issuer, verifier) = ProviderCredentialRequestAuthorityPair::new().split();
        let owner = if case == 0 { [99; 32] } else { [3; 32] };
        let release = if case == 1 { [99; 32] } else { [9; 32] };
        let session = if case == 2 { [99; 32] } else { [17; 32] };
        let supervisor = if case == 3 { 99 } else { 8 };
        let database = if case == 4 { 99 } else { 7 };
        let base = issuer
            .issue_base(
                owner, release, session, supervisor, [16; 32], database, [12; 32],
            )
            .unwrap();
        let keys = LaunchSecret::from_bytes([51; 32]).unwrap().derive_keys();
        let transfer = issuer.issue_recovery_broker_transfer(&keys, &base).unwrap();
        let rendezvous = DaemonOwnedUnixBrokerRendezvous::create().unwrap();
        let evidence = runne_api::protected_credential_broker_evidence_binding(
            release,
            rendezvous.channel_binding(),
            rendezvous.publication_public_key(),
        );
        let now = match case {
            5 => accepted.issued_at() - 1,
            6 => accepted.expires_at(),
            _ => accepted.issued_at(),
        };
        let other = f
            .store
            .load_operation(CredentialOperationId::from_bytes([2; 16]).unwrap())
            .unwrap();
        let candidate = PendingCleanupBrokerReservation {
            accepted,
            authority: &base,
            verifier: &verifier,
            measurements: &f.measurements,
            operation: if case == 7 { &other } else { &f.operation },
            rendezvous,
            transfer,
            now,
            expected_broker_evidence: if case == 8 { [99; 32] } else { evidence },
        };
        assert!(
            PendingCleanupBrokerHandoff::try_from(candidate).is_err(),
            "case {case}"
        );
    }
}

#[test]
fn recovery_reservation_rejects_foreign_verifier_store_and_transfer_issuers() {
    for case in 0..3 {
        let (f, accepted) = recovery_fixture();
        let now = accepted.issued_at();
        let (issuer, verifier) = ProviderCredentialRequestAuthorityPair::new().split();
        let (foreign, foreign_verifier) = ProviderCredentialRequestAuthorityPair::new().split();
        let base = issuer
            .issue_base([3; 32], [9; 32], [17; 32], 8, [16; 32], 7, [12; 32])
            .unwrap();
        let other_base = foreign
            .issue_base([3; 32], [9; 32], [17; 32], 8, [16; 32], 7, [12; 32])
            .unwrap();
        let (_, foreign_measurements) = CredentialEnrollmentAuthorityPair::new().split();
        let keys = LaunchSecret::from_bytes([51; 32]).unwrap().derive_keys();
        let transfer = if case == 2 {
            foreign.issue_recovery_broker_transfer(&keys, &other_base)
        } else {
            issuer.issue_recovery_broker_transfer(&keys, &base)
        }
        .unwrap();
        let rendezvous = DaemonOwnedUnixBrokerRendezvous::create().unwrap();
        let expected_broker_evidence = runne_api::protected_credential_broker_evidence_binding(
            [9; 32],
            rendezvous.channel_binding(),
            rendezvous.publication_public_key(),
        );
        assert!(
            PendingCleanupBrokerHandoff::try_from(PendingCleanupBrokerReservation {
                accepted,
                authority: &base,
                verifier: if case == 0 {
                    &foreign_verifier
                } else {
                    &verifier
                },
                measurements: if case == 1 {
                    &foreign_measurements
                } else {
                    &f.measurements
                },
                operation: &f.operation,
                rendezvous,
                transfer,
                expected_broker_evidence,
                now,
            })
            .is_err()
        );
    }
}
