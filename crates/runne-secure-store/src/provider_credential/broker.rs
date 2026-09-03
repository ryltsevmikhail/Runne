mod dispatch;
mod errors;
mod factory;
#[cfg(feature = "provider-credential-broker-writer")]
#[cfg_attr(
    not(any(test, feature = "test-support")),
    expect(dead_code, reason = "B1 is closed until B2 supplies broker admission")
)]
mod migration;
#[cfg(feature = "provider-credential-broker-writer")]
#[cfg_attr(
    not(any(test, feature = "test-support")),
    expect(dead_code, reason = "B1 is closed until B2 supplies broker admission")
)]
mod migration_identity;
mod readback;
mod readback_observation;
mod verification_readback;
#[cfg(feature = "provider-credential-broker-writer")]
#[cfg_attr(
    not(any(test, feature = "test-support")),
    expect(dead_code, reason = "B1 is closed until B2 supplies broker admission")
)]
mod writer;

pub use dispatch::{ProviderCredentialDispatchMaterializer, ProviderCredentialDispatchRead};
pub use factory::{NativeProviderCredentialReaderParts, NativeProviderCredentialReaders};
#[cfg(feature = "provider-credential-broker-writer")]
pub use migration::{
    BrokeredCreateInput, BrokeredDeleteInput, BrokeredLegacySourceDeleteInput,
    BrokeredMigrateLegacyInput,
};
#[cfg(feature = "provider-credential-broker-writer")]
pub use migration_identity::{
    BrokeredWriterIdentityMigrationInput, BrokeredWriterIdentityVerificationInput,
    WriterIdentityMigrationObservation,
};
pub use readback::{
    CredentialReadbackObservation, ExactAbsenceReadback, ExactVersionReadback,
    ProviderCredentialReadback,
};
pub use verification_readback::{
    ProviderCredentialVerificationMaterializer, ProviderCredentialVerificationReadback,
};
#[cfg(feature = "provider-credential-broker-writer")]
pub use writer::{
    BrokeredProviderCredentialWriter, NativeProviderCredentialEffectRoute,
    NativeProviderCredentialWriters,
};

#[cfg(test)]
mod tests;
