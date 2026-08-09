/// Ephemeral secret material. Its bytes are visible only inside this crate.
pub struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    fn new(value: Vec<u8>) -> Self {
        Self(Zeroizing::new(value))
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// Temporary authorized secret handle retained for compatibility with callers.
pub struct SecretHandle {
    pub secret_ref: SecretRef,
    value: SecretValue,
    valid: bool,
}

impl SecretHandle {
    pub fn value(&self) -> Option<&[u8]> {
        self.valid.then_some(self.value.bytes())
    }

    pub fn is_valid(&self) -> bool {
        self.valid
    }

    /// Returns the typed carrier without exposing its bytes.
    pub fn as_secret_value(&self) -> &SecretValue {
        &self.value
    }
}

impl Drop for SecretHandle {
    fn drop(&mut self) {
        self.valid = false;
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("reference not found")]
    ReferenceNotFound,
    #[error("reference revoked")]
    ReferenceRevoked,
    #[error("reference version is no longer current")]
    ReferenceVersionMismatch,
    #[error("secret registry unavailable")]
    Unavailable,
}

struct SecretEntry {
    value: SecretValue,
    state: SecretState,
    version: u64,
    _name: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SecretState {
    Active,
    Revoked,
}

/// Private, shared secret-registry state. It is never serialized or exposed.
pub(crate) struct SecretRegistryState {
    secrets: HashMap<SecretRefId, SecretEntry>,
    policy_epoch: u64,
    unavailable: bool,
    derived_representations: Zeroizing<Vec<Vec<u8>>>,
}

impl SecretRegistryState {
    pub(crate) fn new() -> Self {
        Self {
            secrets: HashMap::new(),
            policy_epoch: 1,
            unavailable: false,
            derived_representations: Zeroizing::new(Vec::new()),
        }
    }

    pub(crate) fn policy_epoch(&self) -> u64 {
        self.policy_epoch
    }

    pub(crate) fn is_available(&self) -> bool {
        !self.unavailable
    }

    pub(crate) fn matches_active_representation(&self, bytes: &[u8]) -> bool {
        self.derived_representations.iter().any(|representation| {
            !representation.is_empty()
                && bytes
                    .windows(representation.len())
                    .any(|window| window == representation)
        })
    }

    pub(crate) fn maximum_active_representation_len(&self) -> usize {
        self.derived_representations
            .iter()
            .map(Vec::len)
            .max()
            .unwrap_or(1)
    }

    fn advance_epoch(&mut self) -> Result<(), SecretError> {
        self.policy_epoch = match self.policy_epoch.checked_add(1) {
            Some(next) => next,
            None => {
                self.unavailable = true;
                return Err(SecretError::Unavailable);
            }
        };
        Ok(())
    }

    fn rebuild_representations(&mut self) {
        self.derived_representations.zeroize();
        let mut next = Vec::new();
        for entry in self.secrets.values() {
            if entry.state == SecretState::Active && !entry.value.bytes().is_empty() {
                add_representations(&mut next, entry.value.bytes());
            }
        }
        self.derived_representations = Zeroizing::new(next);
    }
}
