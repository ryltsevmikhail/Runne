use async_trait::async_trait;
use runne_domain::verification::backup::*;
use runne_domain::verification::identity::RunID;

#[async_trait]
pub trait RetentionManager: Send + Sync {
    async fn find_detachable_runs(&self, policy: &RetentionPolicy) -> Result<Vec<RunID>, String>;
    async fn detach_blobs(
        &self,
        run_ids: &[RunID],
        reason: &str,
    ) -> Result<Vec<PruningEntry>, String>;
}
