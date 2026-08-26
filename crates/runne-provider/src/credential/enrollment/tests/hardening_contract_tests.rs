use runne_domain::id::{CommandId, IdempotencyKey};

use super::super::{
    BeginCredentialOperation, CredentialBindingDigest, CredentialFence,
    CredentialInstallationOwnerId, CredentialLifecycleRevision, CredentialOperationAction,
    CredentialOperationId, IssueCredentialTicketDigest,
};
use crate::{CredentialVersionRef, ProviderId};

#[test]
fn hardening_begin_requires_the_exact_installation_owner() {
    let provider = ProviderId::new("openai").unwrap();
    let owner = CredentialInstallationOwnerId::from_bytes([1; 32]).unwrap();

    let begin = BeginCredentialOperation::new(
        CommandId::from_bytes([2; 16]),
        IdempotencyKey::new("owner-bound-begin").unwrap(),
        CredentialOperationId::from_bytes([3; 16]).unwrap(),
        owner,
        provider.clone(),
        CredentialOperationAction::Pair,
        Some(CredentialVersionRef::new(provider, 1).unwrap()),
        None,
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        digest(4),
    )
    .unwrap();

    assert_eq!(begin.installation_owner_id(), owner);
}

#[test]
fn hardening_ticket_request_is_digest_only_with_bounded_ttl() {
    let request = IssueCredentialTicketDigest::new(
        CredentialOperationId::from_bytes([5; 16]).unwrap(),
        digest(6),
        digest(7),
        60,
    )
    .unwrap();

    assert_eq!(request.ticket_ttl_seconds(), 60);
}

fn digest(value: u8) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([value; 32]).unwrap()
}
