//! Versioned digest for only the managed classes supplied by a retained scope.

use runne_domain::id::IntegrityDigest;
use sha2::{Digest, Sha256};

use crate::project_trust::{ManagedEffectClass, ProjectTrustEffectPolicySnapshot};

/// Immutable componentwise projection and its independent digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetainedRelevantSemanticsV1 {
    pub evaluator_version: u16,
    pub semantics_version: u16,
    pub preset_version: u16,
    pub source_policy_version: u64,
    pub command_policy_version: u64,
    pub provided: [bool; 6],
    pub decisions: [Option<crate::project_trust::ManagedEffectDecision>; 6],
    pub digest: IntegrityDigest,
}

pub(super) fn retained_relevant_semantics(
    snapshot: &ProjectTrustEffectPolicySnapshot,
    provided: [bool; 6],
    preset_version: u16,
    source_policy_version: u64,
    command_policy_version: u64,
) -> Option<RetainedRelevantSemanticsV1> {
    if !snapshot.is_valid()
        || preset_version != 1
        || source_policy_version != crate::project_trust::FROZEN_POLICY_VERSION
        || command_policy_version != crate::project_trust::LOCAL_COMMAND_POLICY_VERSION
    {
        return None;
    }
    let evaluator_version = super::model::RETAINED_POLICY_EVALUATOR_VERSION_V1;
    let semantics_version = super::model::RETAINED_RELEVANT_SEMANTICS_VERSION_V1;
    let mut hash = Sha256::new();
    hash.update(b"runne:d21:retained-relevant-semantics:v1\0");
    hash.update(evaluator_version.to_be_bytes());
    hash.update(semantics_version.to_be_bytes());
    hash.update(preset_version.to_be_bytes());
    hash.update(source_policy_version.to_be_bytes());
    hash.update(command_policy_version.to_be_bytes());
    let mut decisions = [None; 6];
    for (index, class) in ManagedEffectClass::ALL.into_iter().enumerate() {
        hash.update([class.tag(), u8::from(provided[index])]);
        if provided[index] {
            let decision = snapshot.policy.decision_for(class);
            decisions[index] = Some(decision);
            hash.update([decision.tag()]);
        }
    }
    Some(RetainedRelevantSemanticsV1 {
        evaluator_version,
        semantics_version,
        preset_version,
        source_policy_version,
        command_policy_version,
        provided,
        decisions,
        digest: IntegrityDigest::from_bytes(hash.finalize().into()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project_trust::{
        ManagedEffectClass, ManagedEffectDecision as D, ManagedEffectPolicyV1,
    };

    #[test]
    fn fixed_mapping_covers_supported_v1_v2_subsets_and_rejects_unqualified_create() {
        use crate::permission_modes::{FilesystemPermission as Fs, NetworkScope};
        use std::collections::BTreeSet;

        let v1 = super::super::tests_support::Fixture::new();
        let map = super::super::provided_classes::retained_provided_classes;
        assert_eq!(
            map(v1.original.scope()),
            Some([true, true, true, true, true, true])
        );
        for mask in 0_u8..16 {
            let rights = [Fs::Read, Fs::Create, Fs::Write, Fs::Delete]
                .into_iter()
                .enumerate()
                .filter_map(|(index, right)| (mask & (1 << index) != 0).then_some(right))
                .collect::<BTreeSet<_>>();
            let fixture =
                super::super::tests_support::Fixture::v2(NetworkScope::None, rights.clone());
            if rights.contains(&Fs::Create) && !rights.contains(&Fs::Write) {
                assert_eq!(map(fixture.original.scope()), None);
                continue;
            }
            assert_eq!(
                map(fixture.original.scope()),
                Some([
                    rights.contains(&Fs::Read),
                    rights.contains(&Fs::Create),
                    rights.contains(&Fs::Write) || rights.contains(&Fs::Create),
                    rights.contains(&Fs::Delete),
                    true,
                    false
                ])
            );
            assert!(
                fixture
                    .original
                    .scope()
                    .managed_policy
                    .supports_closed_scope(fixture.original.scope())
            );
        }
        let network = super::super::tests_support::Fixture::v2(
            NetworkScope::BroadSameUser,
            [Fs::Read, Fs::Write].into_iter().collect(),
        );
        assert_eq!(
            map(network.original.scope()),
            Some([true, false, true, false, true, true])
        );
        let mut incomplete = v1.original.scope().clone();
        incomplete.filesystem.permissions.remove(&Fs::Delete);
        assert_eq!(map(&incomplete), None);
    }

    #[test]
    fn each_provided_class_obeys_managed_precedence_across_all_presets() {
        for class in ManagedEffectClass::ALL {
            for decision in [D::Allow, D::Ask, D::Deny] {
                for mode in [
                    crate::permission_modes::PermissionMode::FullAccess,
                    crate::permission_modes::PermissionMode::RiskBased,
                    crate::permission_modes::PermissionMode::AskAlways,
                ] {
                    let mut fixture = super::super::tests_support::Fixture::new();
                    let base = super::super::tests_support::full_allow_snapshot();
                    let snapshot = crate::project_trust::ProjectTrustEffectPolicySnapshot {
                        policy: base.policy.with_decision(class, decision),
                        ..base
                    };
                    fixture.replace_current(snapshot, mode, 3);
                    let result =
                        crate::permission_modes::PermissionPolicyCompiler::evaluate_retained_v1(
                            &fixture.input(super::super::RetainedPhaseObservationV1 {
                                phase: super::super::RetainedPhaseV1::BeforeGo,
                                runtime_start: None,
                                elapsed_runtime_ms: None,
                            }),
                        );
                    let matches_expected = match decision {
                        D::Deny => {
                            matches!(result, super::super::RetainedPolicyEvaluationV1::Denied)
                        }
                        D::Ask => matches!(
                            result,
                            super::super::RetainedPolicyEvaluationV1::RequireApproval { .. }
                        ),
                        D::Allow if mode == crate::permission_modes::PermissionMode::FullAccess => {
                            matches!(
                                result,
                                super::super::RetainedPolicyEvaluationV1::PolicyCompatible { .. }
                            )
                        }
                        D::Allow => matches!(
                            result,
                            super::super::RetainedPolicyEvaluationV1::RequireApproval { .. }
                        ),
                    };
                    assert!(
                        matches_expected,
                        "{class:?} {decision:?} {mode:?}: {result:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn digest_uses_the_frozen_domain_and_canonical_fixed_width_fields() {
        let snapshot = ProjectTrustEffectPolicySnapshot {
            record: crate::project_trust::ProjectTrustRecord {
                status: crate::project_trust::ProjectTrustStatus::Managed,
                instance_epoch: 9,
                revision: 3,
                managed_deny_mask: 0,
            },
            policy: ManagedEffectPolicyV1::new(
                1,
                [D::Allow, D::Ask, D::Deny, D::Allow, D::Ask, D::Deny],
            ),
        };
        let semantics = retained_relevant_semantics(
            &snapshot,
            [true, false, true, false, true, false],
            1,
            2,
            1,
        )
        .unwrap();
        assert_eq!(
            semantics.decisions,
            [
                Some(D::Allow),
                None,
                Some(D::Deny),
                None,
                Some(D::Ask),
                None
            ]
        );
        // Independent byte-for-byte vector: literal NUL domain, fixed-width BE
        // versions, and class/provided/decision tags for this fixture.
        const EXPECTED_PAYLOAD_V1: [u8; 78] = [
            0x72, 0x75, 0x6e, 0x6e, 0x65, 0x3a, 0x64, 0x32, 0x31, 0x3a, 0x72, 0x65, 0x74, 0x61,
            0x69, 0x6e, 0x65, 0x64, 0x2d, 0x72, 0x65, 0x6c, 0x65, 0x76, 0x61, 0x6e, 0x74, 0x2d,
            0x73, 0x65, 0x6d, 0x61, 0x6e, 0x74, 0x69, 0x63, 0x73, 0x3a, 0x76, 0x31, 0x00, 0x00,
            0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x02, 0x00, 0x03, 0x01,
            0x03, 0x04, 0x00, 0x05, 0x01, 0x02, 0x06, 0x00,
        ];
        const EXPECTED_DIGEST_V1: &str =
            "9430234ec5421cb4508e97ba7ba7b8f20bb112307547491e6ef8e873b0df9849";
        assert_eq!(
            IntegrityDigest::from_bytes(Sha256::digest(EXPECTED_PAYLOAD_V1).into()).to_string(),
            EXPECTED_DIGEST_V1
        );
        assert_eq!(semantics.digest.to_string(), EXPECTED_DIGEST_V1);
    }

    #[test]
    fn unused_decisions_and_snapshot_revision_do_not_change_relevant_semantics() {
        let first = ProjectTrustEffectPolicySnapshot {
            record: crate::project_trust::ProjectTrustRecord {
                status: crate::project_trust::ProjectTrustStatus::Managed,
                instance_epoch: 9,
                revision: 3,
                managed_deny_mask: 0,
            },
            policy: ManagedEffectPolicyV1::all_allow(),
        };
        let later = ProjectTrustEffectPolicySnapshot {
            record: crate::project_trust::ProjectTrustRecord {
                revision: 4,
                ..first.record
            },
            policy: first
                .policy
                .with_decision(ManagedEffectClass::NetworkUse, D::Deny),
        };
        let provided = [true, true, true, true, true, false];
        let old = retained_relevant_semantics(&first, provided, 1, 2, 1).unwrap();
        let new = retained_relevant_semantics(&later, provided, 1, 2, 1).unwrap();
        assert_eq!(old, new);
    }

    #[test]
    fn every_provided_decision_and_policy_version_changes_the_digest() {
        let base = ProjectTrustEffectPolicySnapshot {
            record: crate::project_trust::ProjectTrustRecord {
                status: crate::project_trust::ProjectTrustStatus::Managed,
                instance_epoch: 9,
                revision: 3,
                managed_deny_mask: 0,
            },
            policy: ManagedEffectPolicyV1::all_allow(),
        };
        let provided = [true; 6];
        let original = retained_relevant_semantics(&base, provided, 1, 2, 1).unwrap();
        for class in ManagedEffectClass::ALL {
            let changed = ProjectTrustEffectPolicySnapshot {
                policy: base.policy.with_decision(class, D::Ask),
                ..base
            };
            assert_ne!(
                original.digest,
                retained_relevant_semantics(&changed, provided, 1, 2, 1)
                    .unwrap()
                    .digest
            );
        }
        assert!(retained_relevant_semantics(&base, provided, 2, 2, 1).is_none());
        assert!(retained_relevant_semantics(&base, provided, 1, 3, 1).is_none());
        assert!(retained_relevant_semantics(&base, provided, 1, 2, 2).is_none());
    }
}
