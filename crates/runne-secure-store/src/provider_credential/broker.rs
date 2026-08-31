mod errors;
mod factory;
#[cfg(feature = "provider-credential-broker-writer")]
mod migration;
#[cfg(feature = "provider-credential-broker-writer")]
mod migration_identity;
mod readback;
mod readback_observation;
mod verification_readback;
#[cfg(feature = "provider-credential-broker-writer")]
mod writer;

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
    ProviderCredentialDispatchMaterializer, ProviderCredentialReadback,
    ProviderCredentialVerificationMaterializer,
};
pub use verification_readback::ProviderCredentialVerificationReadback;
#[cfg(feature = "provider-credential-broker-writer")]
pub use writer::{BrokeredProviderCredentialWriter, NativeProviderCredentialWriters};

#[cfg(test)]
mod tests;
