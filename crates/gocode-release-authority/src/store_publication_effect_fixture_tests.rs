use crate::publication_effect_command::{PublicationEffectCommand, PublicationEffectContext};
use crate::publication_effect_failpoint::PublicationEffectFailpoint;
use crate::publication_effect_ledger::FixturePublicationEffectLedger;
use crate::publication_effect_types::{
    PublicationEffectError, PublicationEffectScope, PublicationEffectState,
};
use crate::{
    Digest, DurableFixturePromotionAuthority, PromotionState, ThresholdFixtureStoreBinding,
};

#[path = "../tests/canonical_wire/admission_support.rs"]
mod admission_support;
#[path = "../tests/canonical_wire/metadata_support.rs"]
mod metadata_support;
#[path = "../tests/verify_signed/support.rs"]
mod signing_support;
#[path = "../tests/canonical_wire/support.rs"]
mod support;
#[path = "../tests/verified_stage_support.rs"]
mod verified_stage_support;

const CONTEXT: PublicationEffectContext = PublicationEffectContext {
    observed_at: 15,
    revocation_epoch: 1,
    allowlist_generation: 1,
};

pub fn fixture() -> (crate::InMemoryPromotionStore, PublicationEffectScope) {
    let (mut memory, promotion, _) = signing_support::signing_authorized();
    let authority_instance = memory.authority_instance;
    let record = memory.entries.get_mut(&promotion).unwrap();
    let candidate = record.binding.unwrap().candidate();
    record.state = Some(PromotionState::PublicationAuthorized);
    record.publication_manifest = Some(Digest::fixture([4; 32]));
    record.publication_authorization = Some(Digest::fixture([3; 32]));
    record.publication_destination = Some("github".into());
    record.publication_channel = Some("stable".into());
    record.publication_namespace = Some("ns-1".into());
    record.publication_executor = Some("executor".into());
    record.publication_lane = Some("publish-lane".into());
    record.publication_workflow = Some(Digest::fixture([9; 32]));
    record.publication_valid_from = Some(10);
    record.publication_expires_at = Some(20);
    record.publication_revocation_epoch = Some(1);
    record.previous_snapshot = record.snapshot.as_ref().map(|snapshot| snapshot.digest);
    record.revision += 1;
    let fingerprint = crate::store::CommandFingerprint::derived(Digest::fixture([77; 32]));
    record.commands.insert(
        "fixture-publication".into(),
        (
            fingerprint,
            crate::TransactionOutcome {
                state: PromotionState::Rc3Review,
                revision: record.revision,
                fixture: true,
            },
        ),
    );
    record.snapshot = Some(crate::store_snapshot::build(&promotion, record, fingerprint).unwrap());
    let scope = PublicationEffectScope {
        authority_instance,
        promotion: promotion.0,
        candidate_digest: candidate,
        rc3_authorization_digest: Digest::fixture([3; 32]),
        manifest_digest: Digest::fixture([4; 32]),
        final_review_digest: Digest::fixture([5; 32]),
        allowlist_digest: Digest::fixture([6; 32]),
        allowlist_generation: 1,
        destination: "github".into(),
        channel: "stable".into(),
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
    };
    (memory, scope)
}

fn path() -> std::path::PathBuf {
    std::path::Path::new("/dev/shm").join(format!(
        "gocode-authority-publication-effect-crash-{}",
        std::process::id()
    ))
}

pub fn binding() -> ThresholdFixtureStoreBinding {
    ThresholdFixtureStoreBinding::new(
        Digest::fixture(verified_stage_support::bootstrap_digest()),
        "fixture-v1",
        1,
    )
    .unwrap()
}

#[test]
fn authoritative_root_repairs_post_rename_cut_and_replays_exact_claim() {
    let path = path();
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("lease"));
    let (memory, scope) = fixture();
    let command = PublicationEffectCommand::claim("claim-1", &scope, CONTEXT);
    let authority =
        DurableFixturePromotionAuthority::create_from_in_memory(&path, binding(), &memory).unwrap();
    authority.load().unwrap();
    authority.arm_publication_failpoint(PublicationEffectFailpoint::AfterRenameBeforeParentSync);
    assert_eq!(
        authority.fixture_claim_publication_command(&command),
        Err(PublicationEffectError::DurableStateUnavailable)
    );
    assert_eq!(
        authority.fixture_claim_publication_command(&PublicationEffectCommand::claim(
            "claim-2", &scope, CONTEXT,
        )),
        Err(PublicationEffectError::DurableStateUnavailable)
    );
    drop(authority);

    let authority = DurableFixturePromotionAuthority::reopen(&path, binding()).unwrap();
    assert_eq!(
        authority
            .fixture_replay_publication_command(&command)
            .unwrap()
            .state,
        PublicationEffectState::Claimed
    );
    drop(authority);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("lease"));
}

#[test]
fn self_consistent_successor_with_foreign_freeze_rejects_before_anchor_repair() {
    type ScopeMutation = Box<dyn Fn(&mut PublicationEffectScope)>;
    let mutations: Vec<ScopeMutation> = vec![
        Box::new(|scope| scope.authority_instance = Digest::fixture([99; 32])),
        Box::new(|scope| scope.promotion = "other-promotion".into()),
        Box::new(|scope| scope.candidate_digest = Digest::fixture([99; 32])),
        Box::new(|scope| scope.rc3_authorization_digest = Digest::fixture([99; 32])),
        Box::new(|scope| scope.manifest_digest = Digest::fixture([99; 32])),
        Box::new(|scope| scope.destination = "other".into()),
        Box::new(|scope| scope.channel = "beta".into()),
        Box::new(|scope| scope.idempotency_namespace = "other-ns".into()),
        Box::new(|scope| scope.workflow_digest = Digest::fixture([99; 32])),
        Box::new(|scope| scope.valid_from = 11),
        Box::new(|scope| scope.expires_at = 19),
        Box::new(|scope| scope.revocation_epoch = 2),
    ];
    for (index, mutate) in mutations.into_iter().enumerate() {
        let path = std::path::Path::new("/dev/shm").join(format!(
            "gocode-authority-foreign-successor-{index}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("lease"));
        let (memory, mut scope) = fixture();
        let authority =
            DurableFixturePromotionAuthority::create_from_in_memory(&path, binding(), &memory)
                .unwrap();
        let current = std::fs::read(&path).unwrap();
        let anchor = std::fs::read(path.with_extension("lease")).unwrap();
        drop(authority);
        mutate(&mut scope);
        let mut ledger = FixturePublicationEffectLedger::default();
        let context = PublicationEffectContext {
            observed_at: 15,
            revocation_epoch: scope.revocation_epoch,
            allowlist_generation: scope.allowlist_generation,
        };
        ledger
            .claim_command(&PublicationEffectCommand::claim("claim-1", &scope, context))
            .unwrap();
        let ledger = crate::publication_effect_durable::encode_ledger(&ledger).unwrap();
        let successor =
            crate::store_durable_authority::authority_wire::fixture_successor(&current, &ledger)
                .unwrap();
        std::fs::write(&path, successor).unwrap();
        assert_eq!(
            DurableFixturePromotionAuthority::reopen(&path, binding()).err(),
            Some(crate::AuthorityError::BindingMismatch),
            "case {index}"
        );
        assert_eq!(std::fs::read(path.with_extension("lease")).unwrap(), anchor);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("lease"));
    }
}
