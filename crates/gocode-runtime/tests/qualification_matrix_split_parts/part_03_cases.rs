#[test]
fn rejection_axes_one_at_a_time_rejected() {
    let cases = [
        (QualificationInput { mode_evidence: ModeEvidence::External { explicit_selection: true, provenance: ExternalOwnerPrivateProvenance::Verified }, ..base() }, QualificationRejection::ModeMismatch),
        (QualificationInput { authority: IdentityMatch::Mismatch, ..base() }, QualificationRejection::AuthorityMismatch),
        (QualificationInput { principal: IdentityMatch::Mismatch, ..base() }, QualificationRejection::PrincipalMismatch),
        (QualificationInput { lineage: IdentityMatch::Mismatch, ..base() }, QualificationRejection::LineageMismatch),
        (QualificationInput { session: IdentityMatch::Mismatch, ..base() }, QualificationRejection::SessionMismatch),
        (QualificationInput { generation: IdentityMatch::Mismatch, ..base() }, QualificationRejection::GenerationMismatch),
        (QualificationInput { bundle_hash_match: false, ..base() }, QualificationRejection::ProfileDigestMismatch),
        (QualificationInput { capability_set_match: false, ..base() }, QualificationRejection::CapabilitySetMismatch),
        (QualificationInput { credential_gate: CredentialGate::NotConfigured, ..base() }, QualificationRejection::BlockedCredentials),
        (QualificationInput { contract_version: ProviderContractVersion::V1, ..base() }, QualificationRejection::ProtectedV2Required),
        (QualificationInput { contract_version: ProviderContractVersion::V1, role: RuntimeRole::DeterministicCompatibility, ..base() }, QualificationRejection::ContractVersionDeniedForRole),
        (QualificationInput { contract_version: ProviderContractVersion::V2, role: RuntimeRole::DeterministicCompatibility, ..base() }, QualificationRejection::ContractVersionDeniedForRole),
        (QualificationInput { mode_evidence: ModeEvidence::Bundled { process_ownership: BundledProcessOwnership::Unproven }, ..base() }, QualificationRejection::OwnershipNotProven),
        (QualificationInput { mode: QualificationMode::External, mode_evidence: ModeEvidence::External { explicit_selection: false, provenance: ExternalOwnerPrivateProvenance::Verified }, ..base() }, QualificationRejection::MissingExplicitExternalSelection),
        (QualificationInput { mode: QualificationMode::External, contract_version: ProviderContractVersion::V1, mode_evidence: external_evidence(), ..base() }, QualificationRejection::ContractVersionDeniedForRole),
        (QualificationInput { mode: QualificationMode::External, mode_evidence: ModeEvidence::External { explicit_selection: true, provenance: ExternalOwnerPrivateProvenance::Unverified }, ..base() }, QualificationRejection::ExternalProvenanceUnverified),
    ];
    for (input, expected) in cases {
        assert_eq!(qualify(&input), QualificationDisposition::Rejected(expected));
    }
}

#[test]
fn selected_mode_requires_matching_typed_evidence() {
    for (mode, evidence) in [
        (QualificationMode::Bundled, external_evidence()),
        (QualificationMode::External, ModeEvidence::Bundled { process_ownership: BundledProcessOwnership::Proven }),
    ] {
        assert_eq!(qualify(&QualificationInput { mode, mode_evidence: evidence, ..base() }), QualificationDisposition::Rejected(QualificationRejection::ModeMismatch));
    }
}

#[test]
fn v2_never_returns_deterministic_compatibility_v1() {
    for bits in 0..(1_u32 << 16) {
        let input = from_bits(bits) ;
        if input.contract_version == ProviderContractVersion::V2 {
            assert_ne!(qualify(&input), QualificationDisposition::DeterministicCompatibilityV1);
        }
    }
}

#[test]
fn exhaustive_sweep_accepts_only_declarative_whitelist() {
    for bits in 0..(1_u32 << 16) {
        let input = from_bits(bits);
        let actual = qualify(&input);
        match whitelisted_disposition(&input) {
            Some(expected) => assert_eq!(actual, expected, "allowlist violation for bits {bits:05b}"),
            None => assert!(is_rejected(&actual), "non-whitelisted input accepted for bits {bits:05b}: {actual:?}"),
        }
    }
}

const ALLOWED_ACCEPTS: [(QualificationMode, ProviderContractVersion, RuntimeRole, EvidenceClass, QualificationDisposition); 8] = [
    (QualificationMode::Bundled, ProviderContractVersion::V1, RuntimeRole::DeterministicCompatibility, EvidenceClass::Fixture, QualificationDisposition::DeterministicCompatibilityV1),
    (QualificationMode::Bundled, ProviderContractVersion::V1, RuntimeRole::DeterministicCompatibility, EvidenceClass::Production, QualificationDisposition::DeterministicCompatibilityV1),
    (QualificationMode::External, ProviderContractVersion::V1, RuntimeRole::DeterministicCompatibility, EvidenceClass::Fixture, QualificationDisposition::DeterministicCompatibilityV1),
    (QualificationMode::External, ProviderContractVersion::V1, RuntimeRole::DeterministicCompatibility, EvidenceClass::Production, QualificationDisposition::DeterministicCompatibilityV1),
    (QualificationMode::Bundled, ProviderContractVersion::V2, RuntimeRole::Production, EvidenceClass::Fixture, QualificationDisposition::FixtureQualified),
    (QualificationMode::Bundled, ProviderContractVersion::V2, RuntimeRole::Production, EvidenceClass::Production, QualificationDisposition::VerifiedProtectedV2),
    (QualificationMode::External, ProviderContractVersion::V2, RuntimeRole::Production, EvidenceClass::Fixture, QualificationDisposition::FixtureQualified),
    (QualificationMode::External, ProviderContractVersion::V2, RuntimeRole::Production, EvidenceClass::Production, QualificationDisposition::VerifiedExternalOwnerPrivate),
];

fn whitelisted_disposition(input: &QualificationInput) -> Option<QualificationDisposition> {
    if !common_axes_valid(input) || !valid_evidence(input) || (input.contract_version == ProviderContractVersion::V1 && !input.deterministic_inputs_only) {
        return None;
    }
    ALLOWED_ACCEPTS.iter().find_map(|(mode, version, role, evidence, disposition)| {
        ((*mode, *version, *role, *evidence)
            == (input.mode, input.contract_version, input.role, input.evidence_class))
            .then_some(*disposition)
    })
}

fn common_axes_valid(input: &QualificationInput) -> bool {
    input.bundle_hash_match && input.capability_set_match && input.credential_gate == CredentialGate::Configured
        && [input.authority, input.principal, input.lineage, input.session, input.generation].into_iter().all(|axis| axis == IdentityMatch::Match)
}

fn valid_evidence(input: &QualificationInput) -> bool {
    matches!(
        (input.mode, input.mode_evidence),
        (QualificationMode::Bundled, ModeEvidence::Bundled { process_ownership: BundledProcessOwnership::Proven })
            | (QualificationMode::External, ModeEvidence::External { explicit_selection: true, provenance: ExternalOwnerPrivateProvenance::Verified })
    )
}

fn external_evidence() -> ModeEvidence {
    ModeEvidence::External { explicit_selection: true, provenance: ExternalOwnerPrivateProvenance::Verified }
}
