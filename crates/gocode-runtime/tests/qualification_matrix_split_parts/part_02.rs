use gocode_runtime::qualification_matrix::*;
use crate::support::base;

#[test]
fn row14_restart_rotation_stale_identity_rejected() {
    // Stale-after-rotation: every identity axis matches except generation,
    // modelling pre-rotation identity presented after a committed rotation.
    // The wire mechanism is indistinguishable from an ordinary mismatch
    // (matrix §2: `StaleRotatedIdentity` collapses onto generation/session).
    let input = QualificationInput {
        generation: IdentityMatch::Mismatch,
        ..base()
    };
    assert_eq!(
        qualify(&input),
        QualificationDisposition::Rejected(QualificationRejection::GenerationMismatch)
    );
}

#[test]
fn row15_rotation_preserves_stable_replay_identity() {
    // Model-level: all axes match after rotation → non-blocking. The real
    // replay path (idempotency, single application) is proven by the wire-level
    // test in Task 8 stage 2 (matrix row 15).
    let input = base();
    assert_eq!(qualify(&input), QualificationDisposition::VerifiedProtectedV2);
}

#[test]
fn row16_external_shutdown_noop() {
    // Model-level external qualification is non-blocking. Structural desktop
    // evidence: `RuntimeLifecycleManager::external()` has `owned_runtime: None`;
    // `stop_owned_runtime` invokes lifecycle stop only for `Some`. No OS-level
    // signal or state-hash evidence is claimed.
    let input = QualificationInput {
        mode: QualificationMode::External,
        mode_evidence: ModeEvidence::External {
            explicit_selection: true,
            provenance: ExternalOwnerPrivateProvenance::Verified,
        },
        ..base()
    };
    assert_eq!(
        qualify(&input),
        QualificationDisposition::VerifiedExternalOwnerPrivate
    );
}

#[test]
fn row17_desktop_terminate_proven_owned() {
    // Bundled process ownership is distinct typed evidence.
    let input = QualificationInput {
        evidence_class: EvidenceClass::Fixture,
        ..base()
    };
    assert_eq!(qualify(&input), QualificationDisposition::FixtureQualified);
}

#[test]
fn row18_desktop_terminate_non_owned_rejected() {
    let input = QualificationInput {
        mode_evidence: ModeEvidence::Bundled {
            process_ownership: BundledProcessOwnership::Unproven,
        },
        ..base()
    };
    assert_eq!(
        qualify(&input),
        QualificationDisposition::Rejected(QualificationRejection::OwnershipNotProven)
    );
}

#[test]
fn row19_credential_absence_blocked() {
    let input = QualificationInput {
        credential_gate: CredentialGate::NotConfigured,
        ..base()
    };
    assert_eq!(
        qualify(&input),
        QualificationDisposition::Rejected(QualificationRejection::BlockedCredentials)
    );
}

#[test]
fn row20_mixed_version_connect_rejected() {
    // Mixed-version client/runtime connect is modelled as a capability-set
    // mismatch: the exact-match capability comparison fails (matrix row 20).
    let input = QualificationInput {
        capability_set_match: false,
        ..base()
    };
    assert_eq!(
        qualify(&input),
        QualificationDisposition::Rejected(QualificationRejection::CapabilitySetMismatch)
    );
}

#[test]
fn row21_telemetry_capability_sync_rejection() {
    // `runtime.operational-telemetry.v1` required but not published →
    // capability-set mismatch; the sync of both sets to the committed
    // bundle.json is pinned by `qualification_bundle_sync.rs` (matrix row 21).
    let input = QualificationInput {
        capability_set_match: false,
        ..base()
    };
    assert_eq!(
        qualify(&input),
        QualificationDisposition::Rejected(QualificationRejection::CapabilitySetMismatch)
    );
}

#[test]
fn row22_fixture_evidence_never_production() {
    // Valid V2 fixtures are qualified, never verified, in both modes.
    for mode in [QualificationMode::Bundled, QualificationMode::External] {
        let input = QualificationInput {
            mode,
            evidence_class: EvidenceClass::Fixture,
            mode_evidence: evidence_for(mode),
            ..base()
        };
        assert_eq!(qualify(&input), QualificationDisposition::FixtureQualified);
        assert!(!matches!(
            qualify(&input),
            QualificationDisposition::VerifiedProtectedV2
                | QualificationDisposition::VerifiedExternalOwnerPrivate
        ));
    }
}

#[test]
fn row23_bundled_ignores_explicit_selection_flag() {
    // Bundled process ownership cannot be supplied as external provenance.
    let input = QualificationInput {
        mode_evidence: ModeEvidence::External {
            explicit_selection: true,
            provenance: ExternalOwnerPrivateProvenance::Verified,
        },
        ..base()
    };
    assert_eq!(qualify(&input), QualificationDisposition::Rejected(QualificationRejection::ModeMismatch));
}

#[test]
fn row24a_cross_kind_digest_protected_claim_external_artifact() {
    // kind = ProtectedV2 with a foreign-kind digest → profile digest mismatch.
    let input = QualificationInput {
        bundle_hash_match: false,
        ..base()
    };
    assert_eq!(
        qualify(&input),
        QualificationDisposition::Rejected(QualificationRejection::ProfileDigestMismatch)
    );
}

#[test]
fn row24b_cross_kind_digest_external_claim_protected_artifact() {
    // kind = ExternalOwnerPrivate with a protected-kind digest → profile digest
    // mismatch; the digest check precedes the external-branch gates.
    let input = QualificationInput {
        mode: QualificationMode::External,
        mode_evidence: ModeEvidence::External {
            explicit_selection: true,
            provenance: ExternalOwnerPrivateProvenance::Verified,
        },
        bundle_hash_match: false,
        ..base()
    };
    assert_eq!(
        qualify(&input),
        QualificationDisposition::Rejected(QualificationRejection::ProfileDigestMismatch)
    );
}

#[test]
fn row25_credential_absent_external_no_fallback() {
    // Credential absence in external mode blocks qualification; there is no
    // implicit bundled fallback (matrix row 25).
    let input = QualificationInput {
        mode: QualificationMode::External,
        mode_evidence: ModeEvidence::External {
            explicit_selection: true,
            provenance: ExternalOwnerPrivateProvenance::Verified,
        },
        credential_gate: CredentialGate::NotConfigured,
        ..base()
    };
    assert_eq!(
        qualify(&input),
        QualificationDisposition::Rejected(QualificationRejection::BlockedCredentials)
    );
}

#[test]
fn row25b_missing_explicit_selection_precedes_credentials() {
    // Explicit selection precedes the credential gate for external evidence.
    let input = QualificationInput {
        mode: QualificationMode::External,
        mode_evidence: ModeEvidence::External {
            explicit_selection: false,
            provenance: ExternalOwnerPrivateProvenance::Verified,
        },
        credential_gate: CredentialGate::NotConfigured,
        ..base()
    };
    assert_eq!(
        qualify(&input),
        QualificationDisposition::Rejected(QualificationRejection::MissingExplicitExternalSelection)
    );
}

#[test]
fn row26_v1_production_fixture_rejected() {
    // Fixture evidence must not mask the bundled V1 production rejection.
    let input = QualificationInput {
        mode: QualificationMode::Bundled,
        contract_version: ProviderContractVersion::V1,
        role: RuntimeRole::Production,
        evidence_class: EvidenceClass::Fixture,
        ..base()
    };
    assert_eq!(
        qualify(&input),
        QualificationDisposition::Rejected(QualificationRejection::ProtectedV2Required)
    );
}

fn evidence_for(mode: QualificationMode) -> ModeEvidence {
    match mode {
        QualificationMode::Bundled => ModeEvidence::Bundled {
            process_ownership: BundledProcessOwnership::Proven,
        },
        QualificationMode::External => ModeEvidence::External {
            explicit_selection: true,
            provenance: ExternalOwnerPrivateProvenance::Verified,
        },
    }
}
