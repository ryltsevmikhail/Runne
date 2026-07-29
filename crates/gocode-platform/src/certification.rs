//! Local exact-tuple platform certifier.

use gocode_application::migration::{
    gates::{GateEvidence, GateStatus},
    platform::{
        FilesystemClass, PlatformArchitecture, PlatformCertificationError,
        PlatformCertificationPort, PlatformCertificationRequest, PlatformOs, PlatformTuple,
        PlatformVfs, ProcessModel,
    },
    types::GateFamily,
};

/// Local certifier bound to one exact reviewed platform tuple.
#[derive(Debug, Clone)]
pub struct LocalPlatformCertifier {
    certified: PlatformTuple,
}

impl LocalPlatformCertifier {
    /// Bind the adapter to one exact reviewed tuple.
    pub fn new(certified: PlatformTuple) -> Self {
        Self { certified }
    }
}

impl PlatformCertificationPort for LocalPlatformCertifier {
    fn certify(
        &self,
        request: PlatformCertificationRequest,
    ) -> Result<GateEvidence, PlatformCertificationError> {
        if !valid_tuple(&self.certified) || !valid_tuple(&request.platform) {
            return Err(PlatformCertificationError::InvalidTuple);
        }
        if request.platform != self.certified {
            return Err(PlatformCertificationError::TupleNotCertified);
        }
        if request.gate_revision == 0 || request.valid_until <= request.context.now {
            return Err(PlatformCertificationError::InvalidEvidenceWindow);
        }
        if request.evidence_digest.as_bytes() == &[0; 32] {
            return Err(PlatformCertificationError::EmptyEvidenceDigest);
        }

        Ok(GateEvidence {
            gate_id: request.gate_id,
            gate_revision: request.gate_revision,
            family: GateFamily::PlatformCertification,
            source_generation: request.context.source_generation,
            candidate_generation: request.context.candidate_generation,
            cohort: request.context.cohort,
            contract_digest: request.context.contract_digest,
            profile_digest: request.context.profile_digest,
            config_digest: request.context.config_digest,
            measured_at: request.context.now,
            valid_until: request.valid_until,
            status: GateStatus::Passed,
            evidence_digest: request.evidence_digest,
        })
    }
}

fn valid_tuple(tuple: &PlatformTuple) -> bool {
    valid_os(&tuple.os)
        && valid_architecture(&tuple.architecture)
        && valid_filesystem(&tuple.filesystem)
        && valid_vfs(&tuple.vfs)
        && valid_process_model(&tuple.process_model)
        && tuple.sandbox_profile_digest.as_bytes() != &[0; 32]
}

fn valid_os(value: &PlatformOs) -> bool {
    match value {
        PlatformOs::Other(value) => valid_extension(value),
        PlatformOs::Linux | PlatformOs::MacOs | PlatformOs::Windows => true,
    }
}

fn valid_architecture(value: &PlatformArchitecture) -> bool {
    match value {
        PlatformArchitecture::Other(value) => valid_extension(value),
        PlatformArchitecture::Aarch64 | PlatformArchitecture::X86_64 => true,
    }
}

fn valid_filesystem(value: &FilesystemClass) -> bool {
    match value {
        FilesystemClass::Other(value) => valid_extension(value),
        FilesystemClass::LocalDurable | FilesystemClass::Network => true,
    }
}

fn valid_vfs(value: &PlatformVfs) -> bool {
    match value {
        PlatformVfs::Other(value) => valid_extension(value),
        PlatformVfs::SqliteDefault | PlatformVfs::AppleFullFsync => true,
    }
}

fn valid_process_model(value: &ProcessModel) -> bool {
    match value {
        ProcessModel::Other(value) => valid_extension(value),
        ProcessModel::Posix | ProcessModel::Windows | ProcessModel::Sandboxed => true,
    }
}

fn valid_extension(value: &str) -> bool {
    const MAX_EXTENSION_BYTES: usize = 64;
    !value.is_empty()
        && value.len() <= MAX_EXTENSION_BYTES
        && !value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
}

#[cfg(test)]
mod tests {
    use gocode_application::migration::{
        gates::GateContext,
        platform::*,
        types::{ArtifactDigest, CohortDimension, CohortSelector, GateId, RuntimeGenerationRef},
    };

    use super::*;

    #[test]
    fn certification_is_exact_to_os_arch_filesystem_vfs_and_sandbox() {
        let certifier = LocalPlatformCertifier::new(certified_tuple());
        assert!(
            certifier
                .certify(certification_request(certified_tuple()))
                .is_ok()
        );

        let mut changed = certified_tuple();
        changed.vfs = PlatformVfs::Other("network-vfs".into());
        assert_eq!(
            certifier.certify(certification_request(changed)),
            Err(PlatformCertificationError::TupleNotCertified)
        );
    }

    fn certified_tuple() -> PlatformTuple {
        PlatformTuple {
            os: PlatformOs::MacOs,
            architecture: PlatformArchitecture::Aarch64,
            filesystem: FilesystemClass::LocalDurable,
            vfs: PlatformVfs::AppleFullFsync,
            process_model: ProcessModel::Sandboxed,
            sandbox_profile_digest: ArtifactDigest::from_bytes([7; 32]),
        }
    }

    fn certification_request(platform: PlatformTuple) -> PlatformCertificationRequest {
        PlatformCertificationRequest {
            platform,
            gate_id: GateId::new("platform-gate-1").unwrap(),
            gate_revision: 1,
            context: GateContext {
                source_generation: RuntimeGenerationRef::new("source-v1").unwrap(),
                candidate_generation: RuntimeGenerationRef::new("candidate-v1").unwrap(),
                cohort: CohortSelector::new(vec![
                    CohortDimension::new("deployment_mode", "production").unwrap(),
                ])
                .unwrap(),
                contract_digest: ArtifactDigest::from_bytes([2; 32]),
                profile_digest: ArtifactDigest::from_bytes([3; 32]),
                config_digest: ArtifactDigest::from_bytes([4; 32]),
                now: 100_i64.into(),
            },
            valid_until: 200_i64.into(),
            evidence_digest: ArtifactDigest::from_bytes([8; 32]),
        }
    }
}
