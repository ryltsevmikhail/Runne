mod errors;
mod factory;
#[cfg(feature = "provider-credential-broker-writer")]
mod migration;
#[cfg(feature = "provider-credential-broker-writer")]
mod migration_identity;
mod readback;
mod readback_observation;
#[cfg(feature = "provider-credential-broker-writer")]
mod writer;

pub use factory::NativeProviderCredentialReaders;
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
#[cfg(feature = "provider-credential-broker-writer")]
pub use writer::{BrokeredProviderCredentialWriter, NativeProviderCredentialWriters};

#[cfg(test)]
mod tests;
