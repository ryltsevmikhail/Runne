mod dispatch;
mod errors;
mod factory;
#[cfg(any(target_os = "macos", test))]
pub mod legacy_presence;
mod legacy_reader;
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
pub use legacy_reader::NativeLegacySourceReadback;
mod readback_observation;
mod verification_readback;
#[cfg(feature = "provider-credential-broker-writer")]
#[cfg_attr(
    not(any(test, feature = "test-support")),
    expect(dead_code, reason = "B1 is closed until B2 supplies broker admission")
)]
mod writer;

pub use dispatch::{
    ProviderCredentialDispatchMaterializer, ProviderCredentialDispatchRead,
    ProviderCredentialRecoveryRead,
};
pub use factory::{
    NativeProviderCredentialReaderParts, NativeProviderCredentialReaders,
    native_verification_materializer,
};
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
    NativeProviderCredentialVerificationMaterializer, ProviderCredentialVerificationMaterializer,
    ProviderCredentialVerificationReadback, VerificationMaterializerAdapter,
    VerificationNativeMaterializer,
};
#[cfg(feature = "provider-credential-broker-writer")]
pub use writer::{
    BrokeredProviderCredentialLegacySource, BrokeredProviderCredentialWriter,
    NativeProviderCredentialEffectRoute, NativeProviderCredentialWriters,
};

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_legacy_absence;
