mod claim;
mod measurement;
mod migration;

pub use claim::CredentialClaimBinding;
pub use measurement::{
    BrokerChannelBinding, CandidateSourceIdentity, ContinuationBindingDigest, ContractBundleDigest,
    CredentialMeasurementSnapshot, CredentialProcessBinding, DaemonAuthorityId,
    DesktopExecutableIdentity, ExpectedInstallMeasurement, ObservedInstallMeasurement,
    ProtectedSessionId, ReaderExecutableIdentity, ReleaseManifestDigest, WriterExecutableIdentity,
    WriterLaunchId, WriterProcessHandleIdentity, WriterProcessStartIdentity,
};
pub use migration::{CredentialReleaseMigrationBinding, WriterIdentityMigrationPhase};

use sha2::{Digest, Sha256};

fn push(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}
