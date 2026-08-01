/// Immutable evidence recorded against a migration cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationEvidence {
    /// Pinned source baseline and fixture inventory.
    Baseline {
        /// Full pinned source commit SHA.
        source_sha: String,
        /// Canonical inventory digest.
        inventory_digest: ArtifactDigest,
        /// Sanitized fixture-set digest.
        fixture_digest: ArtifactDigest,
    },
    /// Executable foundation evidence.
    Foundation {
        /// Implemented contract digest.
        contract_digest: ArtifactDigest,
        /// Durable store-integrity evidence digest.
        store_integrity_digest: ArtifactDigest,
        /// Deterministic test evidence digest.
        deterministic_test_digest: ArtifactDigest,
    },
    /// Read-only import and parity evidence.
    ReadOnlyParity {
        /// Import report digest.
        import_report_digest: ArtifactDigest,
        /// Completeness proof digest.
        completeness_digest: ArtifactDigest,
        /// Number of canonical mutations observed.
        canonical_mutation_count: u64,
    },
    /// Pure simulated-shadow evidence.
    SimulatedShadow {
        /// Semantic diff report digest.
        semantic_diff_digest: ArtifactDigest,
        /// Number of canonical writes observed.
        canonical_write_count: u64,
        /// Number of external effects observed.
        external_effect_count: u64,
        /// Number of client acknowledgements observed.
        client_acknowledgement_count: u64,
    },
    /// Evidence for one production gate.
    ProductionGate(GateEvidence),
}

impl MigrationEvidence {
    pub fn identity_digest(&self) -> ArtifactDigest {
        match self {
            Self::Baseline { fixture_digest, .. } => *fixture_digest,
            Self::Foundation {
                deterministic_test_digest,
                ..
            } => *deterministic_test_digest,
            Self::ReadOnlyParity {
                completeness_digest,
                ..
            } => *completeness_digest,
            Self::SimulatedShadow {
                semantic_diff_digest,
                ..
            } => *semantic_diff_digest,
            Self::ProductionGate(evidence) => evidence.evidence_digest,
        }
    }

    pub fn semantic_digest(&self) -> ArtifactDigest {
        let mut hasher = Sha256::new();
        hasher.update(b"gocode-migration-evidence\x01");
        match self {
            Self::Baseline {
                source_sha,
                inventory_digest,
                fixture_digest,
            } => {
                hasher.update([1]);
                update_length_prefixed(&mut hasher, source_sha.as_bytes());
                hasher.update(inventory_digest.as_bytes());
                hasher.update(fixture_digest.as_bytes());
            }
            Self::Foundation {
                contract_digest,
                store_integrity_digest,
                deterministic_test_digest,
            } => {
                hasher.update([2]);
                hasher.update(contract_digest.as_bytes());
                hasher.update(store_integrity_digest.as_bytes());
                hasher.update(deterministic_test_digest.as_bytes());
            }
            Self::ReadOnlyParity {
                import_report_digest,
                completeness_digest,
                canonical_mutation_count,
            } => {
                hasher.update([3]);
                hasher.update(import_report_digest.as_bytes());
                hasher.update(completeness_digest.as_bytes());
                hasher.update(canonical_mutation_count.to_be_bytes());
            }
            Self::SimulatedShadow {
                semantic_diff_digest,
                canonical_write_count,
                external_effect_count,
                client_acknowledgement_count,
            } => {
                hasher.update([4]);
                hasher.update(semantic_diff_digest.as_bytes());
                hasher.update(canonical_write_count.to_be_bytes());
                hasher.update(external_effect_count.to_be_bytes());
                hasher.update(client_acknowledgement_count.to_be_bytes());
            }
            Self::ProductionGate(evidence) => {
                hasher.update([5]);
                update_length_prefixed(&mut hasher, evidence.gate_id.as_str().as_bytes());
                hasher.update(evidence.gate_revision.to_be_bytes());
                hasher.update([evidence.family as u8]);
                update_length_prefixed(&mut hasher, evidence.source_generation.as_str().as_bytes());
                update_length_prefixed(
                    &mut hasher,
                    evidence.candidate_generation.as_str().as_bytes(),
                );
                hasher.update((evidence.cohort.dimensions().len() as u16).to_be_bytes());
                for dimension in evidence.cohort.dimensions() {
                    update_length_prefixed(&mut hasher, dimension.key().as_bytes());
                    update_length_prefixed(&mut hasher, dimension.value().as_bytes());
                }
                hasher.update(evidence.contract_digest.as_bytes());
                hasher.update(evidence.profile_digest.as_bytes());
                hasher.update(evidence.config_digest.as_bytes());
                hasher.update(evidence.measured_at.as_unix_micros().to_be_bytes());
                hasher.update(evidence.valid_until.as_unix_micros().to_be_bytes());
                match evidence.status {
                    GateStatus::Passed => hasher.update([1]),
                    GateStatus::Failed { code } => hasher.update([2, gate_failure_tag(code)]),
                    GateStatus::Revoked { reason } => {
                        hasher.update([3, gate_revocation_tag(reason)]);
                    }
                }
                hasher.update(evidence.evidence_digest.as_bytes());
            }
        }
        ArtifactDigest::from_bytes(hasher.finalize().into())
    }
}
