use super::same_key;
use crate::{Digest, ThresholdAdmissionScope};

#[test]
fn journal_key_excludes_commitment_scope_but_binds_promotion_revision_and_command() {
    let original = scope();
    let mut mutations = [
        original.clone(),
        original.clone(),
        original.clone(),
        original.clone(),
        original.clone(),
        original,
    ];
    mutations[0].authorization = Digest::fixture([11; 32]);
    mutations[1].commitment = Digest::fixture([12; 32]);
    mutations[2].candidate = Digest::fixture([13; 32]);
    mutations[3].inventory = Digest::fixture([14; 32]);
    mutations[4].metadata = Digest::fixture([15; 32]);
    mutations[5].report = Digest::fixture([16; 32]);
    assert!(mutations.iter().all(|value| same_key(&scope(), value)));
}

fn scope() -> ThresholdAdmissionScope {
    ThresholdAdmissionScope {
        authority_instance: Digest::fixture([0; 32]),
        promotion: "promotion".into(),
        revision: 7,
        command: "verify".into(),
        authorization: Digest::fixture([1; 32]),
        commitment: Digest::fixture([2; 32]),
        candidate: Digest::fixture([3; 32]),
        inventory: Digest::fixture([4; 32]),
        metadata: Digest::fixture([5; 32]),
        report: Digest::fixture([6; 32]),
    }
}
