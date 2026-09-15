use crate::prepared_workspace::PreparedWorkspaceRef;
use serde::Deserialize;
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenSelectedWorkspaceRequest {
    pub prepared: PreparedWorkspaceRef,
    pub renderer_generation: u64,
    pub request_id: String,
}

pub type RetryOpenSelectedWorkspaceRequest = OpenSelectedWorkspaceRequest;

#[cfg(test)]
mod tests {
    use super::OpenSelectedWorkspaceRequest;

    const REFERENCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn open_request_accepts_only_the_prepared_generation_request_wire_shape() {
        let valid = format!(
            r#"{{"prepared":"{REFERENCE}","rendererGeneration":1,"requestId":"request"}}"#,
        );
        assert!(serde_json::from_str::<OpenSelectedWorkspaceRequest>(&valid).is_ok());
        assert!(
            serde_json::from_str::<OpenSelectedWorkspaceRequest>(
                &valid.replace("rendererGeneration", "renderer_generation")
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<OpenSelectedWorkspaceRequest>(&valid.replacen(
                '}',
                ",\"workspaceId\":\"01890e00-0000-7000-8000-000000000001\"}",
                1
            ))
            .is_err()
        );
    }

    #[test]
    fn retry_request_accepts_only_the_same_strict_wire_shape() {
        let valid = format!(
            r#"{{"prepared":"{REFERENCE}","rendererGeneration":1,"requestId":"request"}}"#,
        );
        let retry = serde_json::from_str::<super::RetryOpenSelectedWorkspaceRequest>(&valid)
            .expect("retry wire shape");
        let _ = retry;
        assert!(
            serde_json::from_str::<super::RetryOpenSelectedWorkspaceRequest>(&valid.replacen(
                '}',
                ",\"workspaceId\":\"01890e00-0000-7000-8000-000000000001\"}",
                1,
            ),)
            .is_err()
        );
        assert!(
            serde_json::from_str::<super::RetryOpenSelectedWorkspaceRequest>(&valid.replacen(
                '}',
                ",\"path\":\"/private\"}",
                1
            ),)
            .is_err()
        );
    }
}
