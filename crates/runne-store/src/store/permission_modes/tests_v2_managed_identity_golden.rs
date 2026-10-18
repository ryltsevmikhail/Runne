use runne_application::project_trust::{
    ManagedEffectClass, ManagedEffectDecision, ManagedEffectPolicyV1,
    ProjectTrustEffectPolicySnapshot, ProjectTrustProjectId, ProjectTrustRecord,
    ProjectTrustStatus,
};

use super::super::support::{Fixture, Storage};
use crate::store::permission_modes::managed_identity::{digest, lease};

#[test]
fn six_independent_rule_changes_change_the_envelope_identity() {
    let project = ProjectTrustProjectId::from_bytes([0x41; 16]);
    let record = ProjectTrustRecord {
        status: ProjectTrustStatus::Managed,
        instance_epoch: 9,
        revision: 4,
        managed_deny_mask: 3,
    };
    let base = ProjectTrustEffectPolicySnapshot {
        record,
        policy: ManagedEffectPolicyV1::all_allow(),
    };
    let base_identity = lease::with_challenge(
        lease::identity_for_snapshot(project, 7, base).unwrap(),
        [0x5a; 32],
    );
    for class in ManagedEffectClass::ALL {
        let changed = ProjectTrustEffectPolicySnapshot {
            policy: base
                .policy
                .with_decision(class, ManagedEffectDecision::Deny),
            ..base
        };
        let candidate = lease::with_challenge(
            lease::identity_for_snapshot(project, 7, changed).unwrap(),
            [0x5a; 32],
        );
        assert_ne!(candidate.canonical_digest, base_identity.canonical_digest);
        assert_ne!(
            candidate.challenge_binding.unwrap().envelope_digest,
            base_identity.challenge_binding.unwrap().envelope_digest
        );
    }
}

#[test]
fn envelope_has_a_stable_versioned_encoding_and_binds_project_version() {
    let old = digest::envelope_digest([0x11; 32], [0x22; 32], 3);
    assert_eq!(
        super::super::hex(old.as_bytes()),
        "37399d016be16b0d6f4dfa04854c078fc58ac3a172abdbac0c9a969044f880e8"
    );
    assert_ne!(old, digest::envelope_digest([0x11; 32], [0x22; 32], 4));
}

#[test]
fn missing_selection_does_not_use_the_v66_zero_sentinel() {
    let fixture = Fixture::new(Storage::File);
    let old = fixture
        .store()
        .load_permission_mode_selection_snapshot(&fixture.scope, &fixture.principal)
        .unwrap();
    let authority = fixture.authority();
    let current = authority.trust_lease.snapshot().unwrap();
    let typed = fixture
        .store()
        .load_permission_mode_selection_with_managed_identity(
            &fixture.scope,
            &fixture.principal,
            &authority,
        )
        .unwrap();
    assert_eq!(old.managed_policy_version, 0);
    assert!(matches!(
        typed.identity,
        crate::store::permission_modes::model::ManagedIdentityMetadata::ClosedRulesV2(value)
            if value.snapshot == current
    ));
}
