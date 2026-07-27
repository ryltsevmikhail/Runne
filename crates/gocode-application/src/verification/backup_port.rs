use async_trait::async_trait;
use gocode_domain::verification::backup::BackupManifestRef;
use std::path::Path;

#[async_trait]
pub trait VerificationBackup: Send + Sync {
    async fn create_backup(&self, target_path: &Path) -> Result<BackupManifestRef, String>;
    async fn verify_backup(&self, manifest: &BackupManifestRef) -> Result<(), String>;
}
