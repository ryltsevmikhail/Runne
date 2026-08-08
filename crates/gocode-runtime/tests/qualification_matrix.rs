//! Decision-table tests for the typed qualification matrix
//! (`gocode_runtime::qualification_matrix`, Task 8).
//!
//! Rows 1..26 of `docs/matrices/TASK8_QUALIFICATION_MATRIX.md` are proven one
//! disposition each in `part_01`/`part_02`; `part_03` sweeps all axis
//! combinations; `part_04` pins the typed error mappings.

mod support {
    use gocode_runtime::qualification_matrix::*;

    /// All-OK bundled V2 production input; individual tests override axes via
    /// struct-update syntax.
    pub fn base() -> QualificationInput {
        QualificationInput {
            mode: QualificationMode::Bundled,
            contract_version: ProviderContractVersion::V2,
            role: RuntimeRole::Production,
            evidence_class: EvidenceClass::Production,
            mode_evidence: ModeEvidence::Bundled {
                process_ownership: BundledProcessOwnership::Proven,
            },
            deterministic_inputs_only: false,
            bundle_hash_match: true,
            capability_set_match: true,
            credential_gate: CredentialGate::Configured,
            authority: IdentityMatch::Match,
            principal: IdentityMatch::Match,
            lineage: IdentityMatch::Match,
            session: IdentityMatch::Match,
            generation: IdentityMatch::Match,
        }
    }

    /// True when the disposition is a fail-closed typed rejection.
    pub fn is_rejected(disposition: &QualificationDisposition) -> bool {
        matches!(disposition, QualificationDisposition::Rejected(_))
    }
}

mod part_01 {
    include!("qualification_matrix_split_parts/part_01.rs");
}

mod part_02 {
    include!("qualification_matrix_split_parts/part_02.rs");
}

mod part_03 {
    include!("qualification_matrix_split_parts/part_03_input.rs");
    include!("qualification_matrix_split_parts/part_03_cases.rs");
}

mod part_04 {
    include!("qualification_matrix_split_parts/part_04.rs");
}
