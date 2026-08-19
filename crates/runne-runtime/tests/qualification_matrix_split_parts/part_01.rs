use runne_runtime::qualification_matrix::*;
use crate::support::base;

#[test]
fn row01_bundled_openai_without_protected_v2_rejected() {
    // Bundled OpenAI without protected V2 (V1 contract, production role):
    // the absent protected-V2 transport is the more specific failure than a
    // generic version/role denial (matrix row 1).
    let input = QualificationInput {
        mode: QualificationMode::Bundled,
        contract_version: ProviderContractVersion::V1,
        role: RuntimeRole::Production,
        evidence_class: EvidenceClass::Production,
        ..base()
    };
    assert_eq!(
        qualify(&input),
        QualificationDisposition::Rejected(QualificationRejection::ProtectedV2Required)
    );
}

#[test]
fn row02_bundled_v2_protected_fixture_qualified() {
    // Fixture evidence downgrades only an otherwise valid V2 production input.
    let input = QualificationInput {
        evidence_class: EvidenceClass::Fixture,
        ..base()
    };
    assert_eq!(qualify(&input), QualificationDisposition::FixtureQualified);
}

#[test]
fn row03_external_without_explicit_selection_rejected() {
    // External daemon without explicit selection: rejected before any
    // version/role evaluation (matrix row 3; version is "any").
    let input = QualificationInput {
        mode: QualificationMode::External,
        contract_version: ProviderContractVersion::V1,
        role: RuntimeRole::DeterministicCompatibility,
        mode_evidence: ModeEvidence::External {
            explicit_selection: false,
            provenance: ExternalOwnerPrivateProvenance::Verified,
        },
        deterministic_inputs_only: true,
        ..base()
    };
    assert_eq!(
        qualify(&input),
        QualificationDisposition::Rejected(QualificationRejection::MissingExplicitExternalSelection)
    );
}

#[test]
fn row04_external_explicit_selection_fixture_qualified() {
    // External daemon with explicit selection and fixture evidence: non-blocking
    // in the fixture class, downgraded to `FixtureQualified` (matrix row 4).
    let input = QualificationInput {
        mode: QualificationMode::External,
        evidence_class: EvidenceClass::Fixture,
        mode_evidence: ModeEvidence::External {
            explicit_selection: true,
            provenance: ExternalOwnerPrivateProvenance::Verified,
        },
        ..base()
    };
    assert_eq!(qualify(&input), QualificationDisposition::FixtureQualified);
}

#[test]
fn row05_v1_deterministic_compatibility_disposition() {
    // V1 deterministic compatibility is a separate non-production disposition
    // in both modes (matrix row 5).
    for mode in [QualificationMode::Bundled, QualificationMode::External] {
        let input = QualificationInput {
            mode,
            contract_version: ProviderContractVersion::V1,
            role: RuntimeRole::DeterministicCompatibility,
            evidence_class: EvidenceClass::Production,
            mode_evidence: evidence_for(mode),
            deterministic_inputs_only: true,
            ..base()
        };
        assert_eq!(
            qualify(&input),
            QualificationDisposition::DeterministicCompatibilityV1
        );
    }
}

#[test]
fn row06_v1_production_role_rejected() {
    // External + V1 + production role with explicit selection: version/role
    // denial; `ProtectedV2Required` is reserved for the bundled branch (row 1).
    let external = QualificationInput {
        mode: QualificationMode::External,
        contract_version: ProviderContractVersion::V1,
        role: RuntimeRole::Production,
        mode_evidence: ModeEvidence::External {
            explicit_selection: true,
            provenance: ExternalOwnerPrivateProvenance::Verified,
        },
        ..base()
    };
    assert_eq!(
        qualify(&external),
        QualificationDisposition::Rejected(QualificationRejection::ContractVersionDeniedForRole)
    );
    // V1 + non-deterministic inputs in compatibility role: same denial
    // (behaviourally `CanonicalProviderError::V1TextInputs`).
    let non_deterministic = QualificationInput {
        mode: QualificationMode::Bundled,
        contract_version: ProviderContractVersion::V1,
        role: RuntimeRole::DeterministicCompatibility,
        deterministic_inputs_only: false,
        ..base()
    };
    assert_eq!(
        qualify(&non_deterministic),
        QualificationDisposition::Rejected(QualificationRejection::ContractVersionDeniedForRole)
    );
}

#[test]
fn row07_mode_mismatch_rejected() {
    // B-spec ↔ E-provenance confusion is represented by incompatible variants.
    let input = QualificationInput {
        mode: QualificationMode::External,
        contract_version: ProviderContractVersion::V2,
        role: RuntimeRole::Production,
        evidence_class: EvidenceClass::Production,
        mode_evidence: ModeEvidence::Bundled {
            process_ownership: BundledProcessOwnership::Proven,
        },
        ..base()
    };
    assert_eq!(
        qualify(&input),
        QualificationDisposition::Rejected(QualificationRejection::ModeMismatch)
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

#[test]
fn row08_profile_digest_mismatch_rejected() {
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
fn row09_authority_mismatch_rejected() {
    let input = QualificationInput {
        authority: IdentityMatch::Mismatch,
        ..base()
    };
    assert_eq!(
        qualify(&input),
        QualificationDisposition::Rejected(QualificationRejection::AuthorityMismatch)
    );
}

#[test]
fn row10_principal_mismatch_rejected() {
    let input = QualificationInput {
        principal: IdentityMatch::Mismatch,
        ..base()
    };
    assert_eq!(
        qualify(&input),
        QualificationDisposition::Rejected(QualificationRejection::PrincipalMismatch)
    );
}

#[test]
fn row11_lineage_mismatch_rejected() {
    let input = QualificationInput {
        lineage: IdentityMatch::Mismatch,
        ..base()
    };
    assert_eq!(
        qualify(&input),
        QualificationDisposition::Rejected(QualificationRejection::LineageMismatch)
    );
}

#[test]
fn row12_session_mismatch_rejected() {
    let input = QualificationInput {
        session: IdentityMatch::Mismatch,
        ..base()
    };
    assert_eq!(
        qualify(&input),
        QualificationDisposition::Rejected(QualificationRejection::SessionMismatch)
    );
}

#[test]
fn row13_generation_mismatch_rejected() {
    let input = QualificationInput {
        generation: IdentityMatch::Mismatch,
        ..base()
    };
    assert_eq!(
        qualify(&input),
        QualificationDisposition::Rejected(QualificationRejection::GenerationMismatch)
    );
}
