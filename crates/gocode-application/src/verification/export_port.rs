use async_trait::async_trait;
use gocode_domain::verification::backup::ExportRunJson;
use gocode_domain::verification::identity::RunID;

pub struct ExportScope { pub principal: String, pub capability: String, pub redaction_level: String }

#[async_trait]
pub trait VerificationExporter: Send + Sync {
    async fn export_run_json(&self, run_id: &RunID, scope: &ExportScope) -> Result<ExportRunJson, String>;
}
