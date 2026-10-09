use runne_application::project_trust::{
    ManagedEffectDecision, ProjectTrustEffectLease, ProjectTrustProjectId, ProjectTrustRecord,
    ProjectTrustStatus, TrustPersistenceError,
};
use runne_security::project_trust_policy::effects::{
    EffectDecision, ManagedEffectClass, ManagedEffectPolicyV1, ProjectTrustEffectPolicySnapshot,
    compile_effect_policy, managed_effect_policy_digest_v2,
};

fn snapshot(policy: ManagedEffectPolicyV1) -> ProjectTrustEffectPolicySnapshot {
    ProjectTrustEffectPolicySnapshot {
        record: ProjectTrustRecord {
            status: ProjectTrustStatus::Trusted,
            instance_epoch: 3,
            revision: 8,
            managed_deny_mask: 0,
        },
        policy,
    }
}

#[test]
fn each_closed_class_compiles_ask_and_deny_over_allow_preset() {
    for class in ManagedEffectClass::ALL {
        let ask = ManagedEffectPolicyV1::all_allow().with_decision(class, EffectDecision::Ask);
        assert_eq!(
            compile_effect_policy(&snapshot(ask), class, EffectDecision::Allow),
            EffectDecision::Ask
        );
        let deny = ManagedEffectPolicyV1::all_allow().with_decision(class, EffectDecision::Deny);
        assert_eq!(
            compile_effect_policy(&snapshot(deny), class, EffectDecision::Allow),
            EffectDecision::Deny
        );
    }
}

#[test]
fn deny_precedes_preset_and_allow_keeps_preset_decision() {
    let class = ManagedEffectClass::ProcessStart;
    let deny = ManagedEffectPolicyV1::all_allow().with_decision(class, EffectDecision::Deny);
    assert_eq!(
        compile_effect_policy(&snapshot(deny), class, EffectDecision::Allow),
        EffectDecision::Deny
    );
    let ask = ManagedEffectPolicyV1::all_allow().with_decision(class, EffectDecision::Ask);
    assert_eq!(
        compile_effect_policy(&snapshot(ask), class, EffectDecision::Deny),
        EffectDecision::Deny
    );
    assert_eq!(
        compile_effect_policy(
            &snapshot(ManagedEffectPolicyV1::all_allow()),
            class,
            EffectDecision::Ask
        ),
        EffectDecision::Ask
    );
    for class in ManagedEffectClass::ALL {
        assert_eq!(
            compile_effect_policy(
                &snapshot(ManagedEffectPolicyV1::all_allow()),
                class,
                EffectDecision::Allow
            ),
            EffectDecision::Allow
        );
    }
}

#[test]
fn unknown_policy_version_and_invalid_snapshot_close_to_deny() {
    let mut unknown = ManagedEffectPolicyV1::all_allow();
    unknown.version = 9;
    assert_eq!(
        compile_effect_policy(
            &snapshot(unknown),
            ManagedEffectClass::FsRead,
            EffectDecision::Allow
        ),
        EffectDecision::Deny
    );
    let mut invalid = snapshot(ManagedEffectPolicyV1::all_allow());
    invalid.record.instance_epoch = 0;
    assert_eq!(
        compile_effect_policy(&invalid, ManagedEffectClass::FsRead, EffectDecision::Allow),
        EffectDecision::Deny
    );
}

struct LegacyLease;

impl ProjectTrustEffectLease for LegacyLease {
    fn record(&self) -> ProjectTrustRecord {
        ProjectTrustRecord::untrusted_default(3)
    }
}

#[test]
fn legacy_effect_lease_keeps_record_and_snapshot_default_fails_closed() {
    let lease = LegacyLease;
    assert_eq!(lease.record().instance_epoch, 3);
    assert_eq!(lease.snapshot(), Err(TrustPersistenceError::Unavailable));
    assert_eq!(ManagedEffectDecision::from_code(9), None);
}

#[test]
fn v2_digest_binds_project_record_and_canonical_rules() {
    let project = ProjectTrustProjectId::from_bytes([0x31; 16]);
    let base = snapshot(ManagedEffectPolicyV1::all_allow());
    let digest = managed_effect_policy_digest_v2(project, &base).unwrap();
    assert_ne!(
        digest,
        managed_effect_policy_digest_v2(ProjectTrustProjectId::from_bytes([0x32; 16]), &base)
            .unwrap()
    );
    let changed_rule = ManagedEffectPolicyV1::all_allow()
        .with_decision(ManagedEffectClass::NetworkUse, EffectDecision::Deny);
    assert_ne!(
        digest,
        managed_effect_policy_digest_v2(project, &snapshot(changed_rule)).unwrap()
    );
    let mut changed_record = base;
    changed_record.record.revision += 1;
    assert_ne!(
        digest,
        managed_effect_policy_digest_v2(project, &changed_record).unwrap()
    );
    let mut unsupported = base;
    unsupported.policy.version = 8;
    assert!(managed_effect_policy_digest_v2(project, &unsupported).is_none());
}
