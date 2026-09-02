use serde::Deserialize;

use crate::DirectorySelectionRef;

/// Exact renderer request for native prepared-workspace construction.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrepareSelectedWorkspaceRequest {
    pub selection: DirectorySelectionRef,
    pub renderer_generation: u64,
    pub request_id: String,
    pub workspace_id: String,
    pub expected_version: u64,
}

#[cfg(test)]
mod tests {
    use super::PrepareSelectedWorkspaceRequest;

    const REFERENCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn prepare_request_accepts_only_the_exact_camel_case_wire_schema() {
        let valid = format!(
            r#"{{"selection":"{REFERENCE}","rendererGeneration":1,"requestId":"request","workspaceId":"01890e00-0000-7000-8000-000000000001","expectedVersion":1}}"#,
        );
        assert!(serde_json::from_str::<PrepareSelectedWorkspaceRequest>(&valid).is_ok());
        assert!(
            serde_json::from_str::<PrepareSelectedWorkspaceRequest>(
                &valid.replace("requestId", "request_id")
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<PrepareSelectedWorkspaceRequest>(&valid.replacen(
                '}',
                ",\"path\":\"/private\"}",
                1
            ))
            .is_err()
        );
        assert!(
            serde_json::from_str::<PrepareSelectedWorkspaceRequest>(r#"{"selection":"x"}"#)
                .is_err()
        );
    }
}
