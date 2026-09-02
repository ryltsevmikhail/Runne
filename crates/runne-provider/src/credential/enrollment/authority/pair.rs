use std::sync::Arc;

use super::{
    CredentialEnrollmentAuthorityPair, CredentialEnrollmentMeasurementAuthority,
    CredentialEnrollmentStoreAuthority, EnrollmentAuthoritySeal,
};

impl CredentialEnrollmentAuthorityPair {
    /// Creates one isolated authority pair.
    pub fn new() -> Self {
        let seal = Arc::new(EnrollmentAuthoritySeal);
        Self {
            store: CredentialEnrollmentStoreAuthority { seal: seal.clone() },
            measurements: CredentialEnrollmentMeasurementAuthority { seal },
        }
    }

    /// Separates the store issuer from the independent measurement issuer.
    pub fn split(
        self,
    ) -> (
        CredentialEnrollmentStoreAuthority,
        CredentialEnrollmentMeasurementAuthority,
    ) {
        (self.store, self.measurements)
    }
}

impl Default for CredentialEnrollmentAuthorityPair {
    fn default() -> Self {
        Self::new()
    }
}
