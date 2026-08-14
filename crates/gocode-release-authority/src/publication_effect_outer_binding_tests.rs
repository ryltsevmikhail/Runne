use std::collections::BTreeMap;

use crate::publication_effect_command::{PublicationEffectCommand, PublicationEffectContext};
use crate::publication_effect_ledger::FixturePublicationEffectLedger;
use crate::publication_effect_types::PublicationEffectScope;
use crate::{AuthorityError, CandidateBinding, Digest, PromotionId, PromotionState};

const CONTEXT: PublicationEffectContext = PublicationEffectContext {
    observed_at: 15,
    revocation_epoch: 1,
    allowlist_generation: 1,
};

fn scope() -> PublicationEffectScope {
    PublicationEffectScope {
        authority_instance: Digest::fixture([1; 32]),
        promotion: "promotion-a".into(),
        candidate_digest: Digest::fixture([2; 32]),
        rc3_authorization_digest: Digest::fixture([3; 32]),
        manifest_digest: Digest::fixture([4; 32]),
        final_review_digest: Digest::fixture([5; 32]),
        allowlist_digest: Digest::fixture([6; 32]),
        allowlist_generation: 1,
        destination: "github".into(),
        channel: "release-notes".into(),
        effect_kind: "publish".into(),
        effect_scope_digest: Digest::fixture([7; 32]),
        executor: [
            "principal".into(),
            "account".into(),
            "lane".into(),
            "key".into(),
            "profile".into(),
        ],
        executable_digest: Digest::fixture([8; 32]),
        workflow_digest: Digest::fixture([9; 32]),
        idempotency_namespace: "ns-1".into(),
        valid_from: 10,
        expires_at: 20,
        revocation_epoch: 1,
        generation: 1,
    }
}

fn ledger() -> FixturePublicationEffectLedger {
    let scope = scope();
    let mut ledger = FixturePublicationEffectLedger::default();
    ledger
        .claim_command(&PublicationEffectCommand::claim("claim-1", &scope, CONTEXT))
        .unwrap();
    ledger
}

fn record() -> crate::store_machine::Record {
    crate::store_machine::Record {
        authority_instance: Digest::fixture([1; 32]),
        state: Some(PromotionState::PublicationAuthorized),
        binding: Some(CandidateBinding::fixture(
            [10; 32], [11; 32], [12; 32], [2; 32], [13; 32],
        )),
        publication_manifest: Some(Digest::fixture([4; 32])),
        publication_authorization: Some(Digest::fixture([3; 32])),
        publication_destination: Some("github".into()),
        publication_channel: Some("release-notes".into()),
        publication_namespace: Some("ns-1".into()),
        publication_workflow: Some(Digest::fixture([9; 32])),
        publication_valid_from: Some(10),
        publication_expires_at: Some(20),
        publication_revocation_epoch: Some(1),
        ..Default::default()
    }
}

fn entries(record: crate::store_machine::Record) -> BTreeMap<PromotionId, crate::store_machine::Record> {
    BTreeMap::from([(PromotionId::fixture("promotion-a"), record)])
}

fn rejected(records: &BTreeMap<PromotionId, crate::store_machine::Record>) {
    assert_eq!(
        crate::store_durable_publication_binding::validate(
            Digest::fixture([1; 32]),
            records,
            &ledger(),
        ),
        Err(AuthorityError::BindingMismatch)
    );
}

#[test]
fn embedded_ledger_requires_one_exact_outer_promotion_freeze() {
    assert_eq!(
        crate::store_durable_publication_binding::validate(
            Digest::fixture([1; 32]),
            &entries(record()),
            &ledger(),
        ),
        Ok(())
    );
    rejected(&BTreeMap::new());

    macro_rules! mismatch {
        ($field:ident = $value:expr) => {{
            let mut record = record();
            record.$field = $value;
            rejected(&entries(record));
        }};
    }
    mismatch!(authority_instance = Digest::fixture([99; 32]));
    mismatch!(state = Some(PromotionState::Rc3Review));
    mismatch!(binding = Some(CandidateBinding::fixture(
        [10; 32], [11; 32], [12; 32], [99; 32], [13; 32]
    )));
    mismatch!(publication_manifest = Some(Digest::fixture([99; 32])));
    mismatch!(publication_authorization = Some(Digest::fixture([99; 32])));
    mismatch!(publication_destination = Some("other".into()));
    mismatch!(publication_channel = Some("other".into()));
    mismatch!(publication_namespace = Some("other".into()));
    mismatch!(publication_workflow = Some(Digest::fixture([99; 32])));
    mismatch!(publication_valid_from = Some(11));
    mismatch!(publication_expires_at = Some(21));
    mismatch!(publication_revocation_epoch = Some(2));
}
