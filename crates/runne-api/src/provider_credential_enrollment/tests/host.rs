use serde_json::json;

use super::super::{
    BeginProviderCredentialEnrollment, ProviderCredentialBaseRequestAuthority,
    ProviderCredentialEnrollmentHostError, ProviderCredentialEnrollmentHostPort,
    ProviderCredentialHostFuture, ProviderCredentialIntentConsumptionProof,
    ProviderCredentialOperationHandleV2, ProviderCredentialOperationKindV2,
    ProviderCredentialOperationSnapshotV2, ProviderCredentialProviderV2,
    ProviderCredentialRequestAuthorityPair, ProviderCredentialStatusFuture,
    VerifyProviderCredential,
};
use crate::{ApiActor, ApiPrincipalId, ProviderCredentialCommandContext};
use runne_domain::id::{CommandId, IdempotencyKey};

#[test]
fn provider_credential_request_authorities_require_all_server_derived_bindings() {
    let (issuer, verifier) = ProviderCredentialRequestAuthorityPair::new().split();
    let (_, foreign_verifier) = ProviderCredentialRequestAuthorityPair::new().split();
    assert!(
        issuer
            .issue_base([1; 32], [2; 32], [3; 32], 4, [5; 32], 6, [7; 32])
            .is_ok()
    );
    assert!(
        issuer
            .issue_base([1; 32], [2; 32], [3; 32], 0, [5; 32], 6, [7; 32])
            .is_err()
    );
    let authority = issuer
        .issue_base([1; 32], [2; 32], [3; 32], 4, [5; 32], 6, [0; 32])
        .unwrap_err();
    assert_eq!(
        authority,
        ProviderCredentialEnrollmentHostError::AccessDenied
    );

    let authority = issuer
        .issue_base([1; 32], [2; 32], [3; 32], 4, [5; 32], 6, [7; 32])
        .unwrap();
    assert!(verifier.verify_base(&authority).is_ok());
    assert_eq!(
        foreign_verifier.verify_base(&authority),
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    );

    assert!(
        issuer
            .issue_intent_proof([8; 32], [9; 32], [10; 32], [11; 32], 500)
            .is_ok()
    );
    assert!(
        issuer
            .issue_intent_proof([8; 32], [9; 32], [0; 32], [11; 32], 500)
            .is_err()
    );
    let proof = issuer
        .issue_intent_proof([8; 32], [9; 32], [10; 32], [11; 32], 500)
        .unwrap();
    assert!(verifier.verify_intent_proof(&proof).is_ok());
    assert_eq!(
        foreign_verifier.verify_intent_proof(&proof),
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    );
}

#[test]
fn begin_intent_binding_changes_for_each_bound_command_field() {
    let pair = BeginProviderCredentialEnrollment::new(
        super::super::ProviderCredentialEnrollmentActionV2::Pair,
        ProviderCredentialProviderV2::OpenAi,
        7,
        "018f8d23-7f90-7c00-8000-000000000001",
        "idempotency-a",
        "intent-a",
    )
    .unwrap();
    let changed = BeginProviderCredentialEnrollment::new(
        super::super::ProviderCredentialEnrollmentActionV2::Revoke,
        ProviderCredentialProviderV2::DeepSeek,
        8,
        "018f8d23-7f90-7c00-8000-000000000002",
        "idempotency-b",
        "intent-b",
    )
    .unwrap();
    let context = ProviderCredentialCommandContext {
        command_id: CommandId::from_bytes([1; 16]),
        idempotency_key: IdempotencyKey::new("context-a").unwrap(),
        principal: ApiPrincipalId::new("principal-a").unwrap(),
        actor: ApiActor::new("actor-a").unwrap(),
    };
    let bindings = super::super::ProviderCredentialBeginIntentBinding::new(&pair, &context);
    let changed_bindings =
        super::super::ProviderCredentialBeginIntentBinding::new(&changed, &context);

    assert_ne!(
        bindings.action_provider_revision_digest(),
        changed_bindings.action_provider_revision_digest()
    );
    assert_ne!(
        bindings.command_identity_digest(),
        changed_bindings.command_identity_digest()
    );
}

#[test]
fn provider_credential_operation_snapshot_and_host_port_are_safe_and_closed() {
    let snapshot: ProviderCredentialOperationSnapshotV2 = serde_json::from_value(json!({
        "operationId": "0102030405060708090a0b0c0d0e0f10aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "brokerRendezvousId": "rendezvous-openai-7",
        "providerId": "openai",
        "operationKind": "pair",
        "state": "prepared",
        "lifecycleRevision": 7,
        "readinessRevision": 9,
        "cleanupPending": false,
        "lastDisposition": null
    }))
    .expect("safe operation snapshot");

    assert_eq!(snapshot.provider_id(), ProviderCredentialProviderV2::OpenAi);
    assert_eq!(
        snapshot.operation_kind(),
        ProviderCredentialOperationKindV2::Pair
    );
    assert_eq!(snapshot.broker_rendezvous_id(), Some("rendezvous-openai-7"));
    assert_eq!(snapshot.lifecycle_revision(), 7);
    assert_eq!(snapshot.readiness_revision(), 9);
    let snapshot = serde_json::to_value(snapshot).unwrap();
    super::assert_safe_keys(&snapshot);
    super::assert_exact_keys(
        &snapshot,
        &[
            "operationId",
            "brokerRendezvousId",
            "providerId",
            "operationKind",
            "state",
            "lifecycleRevision",
            "readinessRevision",
            "cleanupPending",
            "lastDisposition",
        ],
    );
    assert_host_port::<ClosedHost>();
    assert_eq!(
        ProviderCredentialEnrollmentHostError::AccessDenied.code(),
        "provider_credential_access_denied"
    );
    assert_eq!(
        ProviderCredentialEnrollmentHostError::InvariantViolation.code(),
        "provider_credential_invariant_violation"
    );
}

#[test]
fn verification_operation_snapshot_has_no_broker_or_enrollment_action() {
    let input = json!({
        "operationId": "0102030405060708090a0b0c0d0e0f11aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "brokerRendezvousId": null,
        "providerId": "openai",
        "operationKind": "verify_remote",
        "state": "completed",
        "lifecycleRevision": 7,
        "readinessRevision": 9,
        "cleanupPending": false,
        "lastDisposition": "completed"
    });
    let snapshot: ProviderCredentialOperationSnapshotV2 =
        serde_json::from_value(input.clone()).expect("safe verification operation snapshot");

    assert_eq!(
        snapshot.operation_kind(),
        ProviderCredentialOperationKindV2::VerifyRemote
    );
    assert_eq!(snapshot.broker_rendezvous_id(), None);

    let mut unexpected = input.clone();
    unexpected
        .as_object_mut()
        .unwrap()
        .insert("unexpected".to_owned(), json!(true));
    assert!(serde_json::from_value::<ProviderCredentialOperationSnapshotV2>(unexpected).is_err());

    let mut brokered_verification = input.clone();
    brokered_verification.as_object_mut().unwrap().insert(
        "brokerRendezvousId".to_owned(),
        json!("forbidden-for-verification"),
    );
    assert!(
        serde_json::from_value::<ProviderCredentialOperationSnapshotV2>(brokered_verification)
            .is_err()
    );

    let mut brokerless_pair = input;
    brokerless_pair
        .as_object_mut()
        .unwrap()
        .insert("operationKind".to_owned(), json!("pair"));
    assert!(
        serde_json::from_value::<ProviderCredentialOperationSnapshotV2>(brokerless_pair).is_err()
    );
}

fn assert_host_port<T: ProviderCredentialEnrollmentHostPort>() {}

struct ClosedHost;

impl ProviderCredentialEnrollmentHostPort for ClosedHost {
    fn begin<'a>(
        &'a self,
        _authority: ProviderCredentialBaseRequestAuthority,
        _proof: ProviderCredentialIntentConsumptionProof,
        _context: crate::ProviderCredentialCommandContext,
        _command: BeginProviderCredentialEnrollment,
    ) -> ProviderCredentialHostFuture<'a> {
        Box::pin(async { Err(ProviderCredentialEnrollmentHostError::Unavailable) })
    }
    fn resume<'a>(
        &'a self,
        _authority: ProviderCredentialBaseRequestAuthority,
        _context: crate::ProviderCredentialCommandContext,
        _operation_handle: ProviderCredentialOperationHandleV2,
    ) -> ProviderCredentialHostFuture<'a> {
        Box::pin(async { Err(ProviderCredentialEnrollmentHostError::Unavailable) })
    }
    fn status<'a>(
        &'a self,
        _authority: ProviderCredentialBaseRequestAuthority,
        _provider: ProviderCredentialProviderV2,
    ) -> ProviderCredentialStatusFuture<'a> {
        Box::pin(async { Err(ProviderCredentialEnrollmentHostError::Unavailable) })
    }
    fn verify<'a>(
        &'a self,
        _authority: ProviderCredentialBaseRequestAuthority,
        _proof: ProviderCredentialIntentConsumptionProof,
        _context: crate::ProviderCredentialCommandContext,
        _command: VerifyProviderCredential,
    ) -> ProviderCredentialHostFuture<'a> {
        Box::pin(async { Err(ProviderCredentialEnrollmentHostError::Unavailable) })
    }
}
