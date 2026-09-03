use crate::SecureStoreError;

#[derive(Clone, Copy)]
pub(super) enum BrokerError {
    AccessDenied,
    Conflict,
    Corrupt,
    Unsupported,
}

impl From<BrokerError> for SecureStoreError {
    fn from(value: BrokerError) -> Self {
        match value {
            BrokerError::AccessDenied => Self::CredentialAccessDenied,
            BrokerError::Conflict => Self::ProviderCredentialOperationFailed,
            BrokerError::Corrupt => Self::CorruptProviderCredential,
            BrokerError::Unsupported => Self::UnsupportedSecureStoreBackend,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_backend_keeps_its_closed_disposition() {
        assert_eq!(
            SecureStoreError::from(BrokerError::Unsupported),
            SecureStoreError::UnsupportedSecureStoreBackend
        );
    }
}
