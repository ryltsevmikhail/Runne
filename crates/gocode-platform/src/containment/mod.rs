//! Платформенные бэкенды containment: Linux seccomp/Landlock/cgroups,
//! macOS App Sandbox и Windows AppContainer.

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
pub mod windows;

/// Ограниченный идентификатор native containment-бэкенда.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ContainmentBackendId(String);

impl ContainmentBackendId {
    /// Создаёт непустой идентификатор бэкенда.
    pub fn new(value: impl Into<String>) -> Result<Self, ContainmentError> {
        bounded_value(value.into()).map(Self)
    }
}

/// Ограниченная версия native containment-бэкенда.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ContainmentBackendVersion(String);

impl ContainmentBackendVersion {
    /// Создаёт непустую версию бэкенда.
    pub fn new(value: impl Into<String>) -> Result<Self, ContainmentError> {
        bounded_value(value.into()).map(Self)
    }
}

/// Идентичность runner, для которого была проведена qualification.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RunnerIdentity(String);

impl RunnerIdentity {
    /// Создаёт непустую идентичность runner.
    pub fn new(value: impl Into<String>) -> Result<Self, ContainmentError> {
        bounded_value(value.into()).map(Self)
    }
}

/// Платформа, для которой запрошен containment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostPlatform {
    /// Linux.
    Linux,
    /// macOS.
    MacOs,
    /// Windows.
    Windows,
    /// Другая именованная платформа.
    Other(String),
}

impl HostPlatform {
    fn is_valid(&self) -> bool {
        !matches!(self, Self::Other(value) if value.is_empty() || value.len() > 256)
    }
}

/// Gate, который обязан покрываться containment-бэкендом.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ContainmentGate {
    /// Прямой исходящий сетевой доступ запрещён.
    DirectEgressDenied,
    /// Доступ к файловой системе ограничен workspace.
    WorkspaceFilesystemConfined,
}

/// Наблюдение runtime с устойчивым идентификатором и дайджестом значения.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RuntimeProbe {
    id: String,
    observed_value_digest: String,
}

impl RuntimeProbe {
    /// Создаёт валидное наблюдение runtime.
    pub fn new(
        id: impl Into<String>,
        observed_value_digest: impl Into<String>,
    ) -> Result<Self, ContainmentError> {
        Ok(Self {
            id: bounded_value(id.into())?,
            observed_value_digest: bounded_value(observed_value_digest.into())?,
        })
    }
}

/// Запрос на startup-attestation containment-бэкенда.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainmentRequest {
    backend_id: ContainmentBackendId,
    backend_version: ContainmentBackendVersion,
    platform: HostPlatform,
    runner_identity: RunnerIdentity,
    requested_gates: Vec<ContainmentGate>,
}

impl ContainmentRequest {
    /// Создаёт запрос с канонически отсортированными уникальными gates.
    pub fn new(
        backend_id: ContainmentBackendId,
        backend_version: ContainmentBackendVersion,
        platform: HostPlatform,
        runner_identity: RunnerIdentity,
        requested_gates: Vec<ContainmentGate>,
    ) -> Result<Self, ContainmentError> {
        if !platform.is_valid() || !canonical_gates(&requested_gates) {
            return Err(ContainmentError::BackendUnavailable);
        }

        Ok(Self {
            backend_id,
            backend_version,
            platform,
            runner_identity,
            requested_gates,
        })
    }
}

/// Данные qualification native containment-бэкенда без утверждения о permit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeCertificate {
    backend_id: ContainmentBackendId,
    backend_version: ContainmentBackendVersion,
    platform: HostPlatform,
    runner_identity: RunnerIdentity,
    qualification_date: String,
    evidence_digest: String,
    covered_gates: Vec<ContainmentGate>,
}

impl NativeCertificate {
    /// Создаёт канонический сертификат qualification.
    pub fn new(
        backend_id: ContainmentBackendId,
        backend_version: ContainmentBackendVersion,
        platform: HostPlatform,
        runner_identity: RunnerIdentity,
        qualification_date: impl Into<String>,
        evidence_digest: impl Into<String>,
        covered_gates: Vec<ContainmentGate>,
    ) -> Result<Self, ContainmentError> {
        if !platform.is_valid() || !canonical_gates(&covered_gates) {
            return Err(ContainmentError::BackendUnavailable);
        }

        Ok(Self {
            backend_id,
            backend_version,
            platform,
            runner_identity,
            qualification_date: bounded_value(qualification_date.into())?,
            evidence_digest: bounded_value(evidence_digest.into())?,
            covered_gates,
        })
    }

    fn exactly_covers(&self, request: &ContainmentRequest) -> bool {
        self.backend_id == request.backend_id
            && self.backend_version == request.backend_version
            && self.platform == request.platform
            && self.runner_identity == request.runner_identity
            && self.covered_gates == request.requested_gates
    }

    fn probes_match(&self, probes: &[RuntimeProbe]) -> bool {
        !probes.is_empty()
            && probes.windows(2).all(|pair| pair[0].id < pair[1].id)
            && probes
                .iter()
                .all(|probe| probe.observed_value_digest == self.evidence_digest)
    }
}

/// Результат startup-attestation в Phase 6A.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationVerdict {
    /// Бэкенд не может быть разрешён до Phase 6B.
    Unavailable,
    /// Сертификат qualification подтверждён — containment разрешён.
    Permit,
}

/// Fail-closed classifier для startup-attestation.
pub struct StartupAttestor;

impl StartupAttestor {
    /// Проверяет предъявленные evidence и делегирует платформе-специфичному
    /// бэкенду. До Phase 6B все бэкенды остаются fail-closed.
    pub fn attest(
        request: &ContainmentRequest,
        certificate: Option<&NativeCertificate>,
        probes: &[RuntimeProbe],
    ) -> Result<AttestationVerdict, ContainmentError> {
        let certificate = certificate.ok_or(ContainmentError::BackendUnavailable)?;
        if !certificate.exactly_covers(request) || !certificate.probes_match(probes) {
            return Err(ContainmentError::BackendUnavailable);
        }

        #[cfg(target_os = "linux")]
        return linux::LinuxContainment::attest(request, Some(certificate), probes);

        #[cfg(not(target_os = "linux"))]
        {
            let _ = ();
            Ok(AttestationVerdict::Unavailable)
        }
    }
}

fn bounded_value(value: String) -> Result<String, ContainmentError> {
    if value.is_empty() || value.len() > 256 {
        return Err(ContainmentError::BackendUnavailable);
    }
    Ok(value)
}

fn canonical_gates(gates: &[ContainmentGate]) -> bool {
    gates.windows(2).all(|pair| pair[0] < pair[1])
}

/// Дескриптор возможностей бэкенда — какие профили поддерживает платформа.
#[derive(Debug, Clone)]
pub struct EnforcementCapabilityDescriptor {
    /// Идентификатор бэкенда containment.
    pub backend_id: String,
    /// Целевая платформа бэкенда.
    pub platform: String,
    /// Версия операционной системы.
    pub os_revision: String,
    /// Поддерживаемые профили enforcement.
    pub supported_profiles: Vec<String>,
    /// Дайджест сертификационных свидетельств.
    pub certification_evidence_digest: String,
}

/// Ошибка применения containment.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ContainmentError {
    /// Бэкенд недоступен на текущей платформе.
    #[error("backend unavailable on this platform")]
    BackendUnavailable,
    /// Запрошенный профиль не поддерживается.
    #[error("profile not supported: {0}")]
    ProfileUnsupported(String),
    /// Не удалось применить sandbox.
    #[error("sandbox apply failed: {0}")]
    SandboxApplyFailed(String),
    /// Ошибка ввода-вывода.
    #[error("io error: {0}")]
    Io(String),
}
