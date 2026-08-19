#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum GateFamily {
    StoreIntegrity = 1,
    CanonicalAudit = 2,
    SecurityPolicy = 3,
    PlatformCertification = 4,
    RuntimeHealth = 5,
    RecoveryReadiness = 6,
    DrainReadiness = 7,
    RollbackReadiness = 8,
    CapacitySlo = 9,
    ShadowIsolation = 10,
}

impl GateFamily {
    pub const ALL: [Self; 10] = [
        Self::StoreIntegrity,
        Self::CanonicalAudit,
        Self::SecurityPolicy,
        Self::PlatformCertification,
        Self::RuntimeHealth,
        Self::RecoveryReadiness,
        Self::DrainReadiness,
        Self::RollbackReadiness,
        Self::CapacitySlo,
        Self::ShadowIsolation,
    ];
}

fn validate_bounded_string(
    value: String,
    field: &'static str,
    max: usize,
) -> Result<String, MigrationValueError> {
    if value.is_empty() {
        return Err(MigrationValueError::Empty { field });
    }
    if value.len() > max {
        return Err(MigrationValueError::TooLong {
            field,
            max,
            actual: value.len(),
        });
    }
    if value.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err(MigrationValueError::ControlCharacter { field });
    }
    Ok(value)
}

fn update_length_prefixed(hasher: &mut Sha256, value: &str) {
    let bytes = value.as_bytes();
    hasher.update((bytes.len() as u16).to_be_bytes());
    hasher.update(bytes);
}
