#[derive(Debug, Clone)]
pub struct EnforcementCapabilityDescriptor {
    pub backend_id: String,
    pub platform: Platform,
    pub os_revision: String,
    pub supported_profiles: Vec<String>,
    pub certification_evidence_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Linux,
    MacOs,
    Windows,
    Unknown,
}

#[derive(Debug, Clone)]
pub enum PlatformConstraint {
    RequiresCodesignedTarget,
}

#[derive(Debug, Clone)]
pub struct PlatformCertificationEvidence {
    pub platform: Platform,
    pub os_version: String,
    pub certified_profiles: Vec<String>,
    pub unavailable_profiles: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum CertificationError {
    #[error("platform not certified")]
    PlatformNotCertified,
    #[error("profile unavailable: {0}")]
    ProfileUnavailable(String),
    #[error("certification stale")]
    CertificationStale,
    #[error("recertification required")]
    RecertificationRequired,
    #[error("profile coverage incomplete: missing {0:?}")]
    ProfileCoverageIncomplete(Vec<String>),
    #[error("backend unavailable")]
    BackendUnavailable,
}

pub struct CertificationManager {
    certified: bool,
    descriptor: Option<EnforcementCapabilityDescriptor>,
    known_os_version: String,
}

impl Default for CertificationManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CertificationManager {
    pub fn new() -> Self {
        Self {
            certified: false,
            descriptor: None,
            known_os_version: String::new(),
        }
    }

    pub fn certify(
        &mut self,
        descriptor: EnforcementCapabilityDescriptor,
        os_version: String,
    ) -> Result<PlatformCertificationEvidence, CertificationError> {
        if descriptor.supported_profiles.is_empty() {
            return Err(CertificationError::ProfileUnavailable(
                "no profiles supported".into(),
            ));
        }

        self.certified = true;
        self.descriptor = Some(descriptor.clone());
        self.known_os_version = os_version.clone();

        Ok(PlatformCertificationEvidence {
            platform: descriptor.platform,
            os_version,
            certified_profiles: descriptor.supported_profiles.clone(),
            unavailable_profiles: vec![],
        })
    }

    pub fn is_certified(&self) -> bool {
        self.certified
    }

    pub fn detect_os_upgrade(&self, new_version: &str) -> bool {
        self.certified && new_version != self.known_os_version
    }

    pub fn require_certification(&self) -> Result<(), CertificationError> {
        if !self.certified {
            return Err(CertificationError::PlatformNotCertified);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uncertified_rejects_dispatch() {
        let manager = CertificationManager::new();

        assert!(manager.require_certification().is_err());
    }

    #[test]
    fn certified_allows_dispatch() {
        let mut manager = CertificationManager::new();
        manager.certify(test_descriptor(), "5.15.0".into()).unwrap();

        assert!(manager.require_certification().is_ok());
    }

    #[test]
    fn os_upgrade_requires_recertification() {
        let mut manager = CertificationManager::new();
        manager.certify(test_descriptor(), "5.15.0".into()).unwrap();

        assert!(manager.detect_os_upgrade("6.0.0"));
    }

    #[test]
    fn empty_profiles_unavailable() {
        let mut manager = CertificationManager::new();
        let result = manager.certify(
            EnforcementCapabilityDescriptor {
                backend_id: "empty".into(),
                platform: Platform::Linux,
                os_revision: "5.15.0".into(),
                supported_profiles: vec![],
                certification_evidence_digest: "sha256:abc".into(),
            },
            "5.15.0".into(),
        );

        assert!(result.is_err());
    }

    fn test_descriptor() -> EnforcementCapabilityDescriptor {
        EnforcementCapabilityDescriptor {
            backend_id: "linux-v1".into(),
            platform: Platform::Linux,
            os_revision: "5.15.0".into(),
            supported_profiles: vec!["workspace-coding".into()],
            certification_evidence_digest: "sha256:abc".into(),
        }
    }
}
