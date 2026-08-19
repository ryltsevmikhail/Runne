use crate::support::{base, is_rejected};
use runne_runtime::qualification_matrix::*;

/// Decodes all decision axes from `bits`; bit 15 selects matching evidence.
fn from_bits(bits: u32) -> QualificationInput {
    let mode = if bits & 1 == 0 {
        QualificationMode::Bundled
    } else {
        QualificationMode::External
    };
    let matching_evidence = bits & (1 << 15) != 0;
    QualificationInput {
        mode,
        contract_version: version(bits),
        role: role(bits),
        evidence_class: evidence(bits),
        mode_evidence: mode_evidence(mode, matching_evidence, bits),
        deterministic_inputs_only: bits & (1 << 5) != 0,
        bundle_hash_match: bits & (1 << 6) != 0,
        capability_set_match: bits & (1 << 7) != 0,
        credential_gate: if bits & (1 << 9) == 0 {
            CredentialGate::NotConfigured
        } else {
            CredentialGate::Configured
        },
        authority: identity(bits, 10),
        principal: identity(bits, 11),
        lineage: identity(bits, 12),
        session: identity(bits, 13),
        generation: identity(bits, 14),
    }
}

fn version(bits: u32) -> ProviderContractVersion {
    if bits & (1 << 1) == 0 { ProviderContractVersion::V1 } else { ProviderContractVersion::V2 }
}
fn role(bits: u32) -> RuntimeRole {
    if bits & (1 << 2) == 0 { RuntimeRole::Production } else { RuntimeRole::DeterministicCompatibility }
}
fn evidence(bits: u32) -> EvidenceClass {
    if bits & (1 << 3) == 0 { EvidenceClass::Fixture } else { EvidenceClass::Production }
}
fn identity(bits: u32, bit: u32) -> IdentityMatch {
    if bits & (1 << bit) == 0 { IdentityMatch::Mismatch } else { IdentityMatch::Match }
}
fn mode_evidence(mode: QualificationMode, matches_mode: bool, bits: u32) -> ModeEvidence {
    let bundled = ModeEvidence::Bundled {
        process_ownership: if bits & (1 << 8) == 0 {
            BundledProcessOwnership::Unproven
        } else {
            BundledProcessOwnership::Proven
        },
    };
    let external = ModeEvidence::External {
        explicit_selection: bits & (1 << 4) != 0,
        provenance: if bits & (1 << 8) == 0 {
            ExternalOwnerPrivateProvenance::Unverified
        } else {
            ExternalOwnerPrivateProvenance::Verified
        },
    };
    match (mode, matches_mode) {
        (QualificationMode::Bundled, true) | (QualificationMode::External, false) => bundled,
        (QualificationMode::External, true) | (QualificationMode::Bundled, false) => external,
    }
}
