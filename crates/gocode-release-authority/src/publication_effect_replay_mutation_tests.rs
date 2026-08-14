use crate::Digest;
use crate::publication_effect_command::{PublicationEffectCommand, PublicationEffectContext};
use crate::publication_effect_durable::DurableFixturePublicationEffectLedger;
use crate::publication_effect_types::{PublicationEffectError, PublicationEffectScope};

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

#[test]
fn replay_mutation_of_each_bound_claim_field_diverges_without_writing() {
    let path = std::env::temp_dir().join(format!(
        "publication-effect-mutation-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let original = scope();
    let command = PublicationEffectCommand::claim("claim-1", &original, CONTEXT);
    let mut ledger = DurableFixturePublicationEffectLedger::create(&path).unwrap();
    ledger.claim_command(&command).unwrap();
    let before = std::fs::read(&path).unwrap();
    macro_rules! diverges {
        ($field:ident = $value:expr) => {{
            let mut changed = original.clone();
            changed.$field = $value;
            let replay = PublicationEffectCommand::claim("claim-1", &changed, CONTEXT);
            assert_eq!(
                ledger.replay_command(&replay),
                Err(PublicationEffectError::CommandReplayDiverged),
                stringify!($field)
            );
            assert_eq!(std::fs::read(&path).unwrap(), before);
        }};
    }
    diverges!(authority_instance = Digest::fixture([10; 32]));
    diverges!(promotion = "promotion-b".into());
    diverges!(candidate_digest = Digest::fixture([11; 32]));
    diverges!(rc3_authorization_digest = Digest::fixture([12; 32]));
    diverges!(manifest_digest = Digest::fixture([13; 32]));
    diverges!(final_review_digest = Digest::fixture([14; 32]));
    diverges!(allowlist_digest = Digest::fixture([15; 32]));
    diverges!(allowlist_generation = 2);
    diverges!(destination = "other".into());
    diverges!(channel = "other".into());
    diverges!(effect_kind = "other".into());
    diverges!(effect_scope_digest = Digest::fixture([16; 32]));
    diverges!(
        executor = [
            "other".into(),
            "account".into(),
            "lane".into(),
            "key".into(),
            "profile".into()
        ]
    );
    diverges!(executable_digest = Digest::fixture([17; 32]));
    diverges!(workflow_digest = Digest::fixture([18; 32]));
    diverges!(idempotency_namespace = "other".into());
    diverges!(valid_from = 11);
    diverges!(expires_at = 19);
    diverges!(revocation_epoch = 2);
    diverges!(generation = 2);
    for context in [
        PublicationEffectContext {
            observed_at: 16,
            ..CONTEXT
        },
        PublicationEffectContext {
            revocation_epoch: 2,
            ..CONTEXT
        },
        PublicationEffectContext {
            allowlist_generation: 2,
            ..CONTEXT
        },
    ] {
        let replay = PublicationEffectCommand::claim("claim-1", &original, context);
        assert_eq!(
            ledger.replay_command(&replay),
            Err(PublicationEffectError::CommandReplayDiverged)
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
    let _ = std::fs::remove_file(&path);
}
