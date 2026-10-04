#[path = "support/mod.rs"]
mod support;

use runne_provider::ProviderRecoveryCapabilities;
use runne_provider::{
    AttemptId, DispatchAttemptId, ProviderPort, ProviderRecoveryBinding, ProviderRecoveryError,
    ProviderRecoveryRequest, ProviderResumeRequest, RemoteResponseId, RemoteStreamCursor,
    ScriptedProvider, TaskRunId,
};
use runne_provider_openai::{
    OPENAI_RESPONSES_BACKGROUND_PROFILE_ID, OpenAiBackgroundResponse, OpenAiResponsesTextProfile,
    OpenAiResponsesTextRenderer,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const BACKGROUND_PROFILE: &[u8] =
    include_bytes!("../../../docs/profiles/openai-responses-background-text-v1.json");

#[test]
fn background_profile_is_exact_opt_in_and_keeps_transport_controls_unadvertised() {
    let profile = OpenAiResponsesTextProfile::from_json(BACKGROUND_PROFILE).unwrap();
    assert_eq!(profile.profile_id(), OPENAI_RESPONSES_BACKGROUND_PROFILE_ID);
    assert_eq!(profile.provider_id(), "openai-background");
    assert_eq!(support::profile().provider_id(), "openai");
    assert!(profile.is_background());
    let digest: [u8; 32] = Sha256::digest(BACKGROUND_PROFILE).into();
    assert_eq!(profile.profile_digest(), digest);
    assert_eq!(profile.model_id(), "gpt-5.5");
    assert_eq!(profile.currency(), "USD");
    assert_eq!(
        ProviderRecoveryCapabilities::default(),
        ProviderRecoveryCapabilities {
            status_check: false,
            stream_resume: false,
            remote_cancel: false,
        }
    );

    let bytes = OpenAiResponsesTextRenderer::new(profile.clone())
        .prepare(&support::call(&profile))
        .unwrap();
    let request: Value = serde_json::from_slice(bytes.rendered_bytes()).unwrap();
    assert_eq!(request["background"], true);
    assert_eq!(request["store"], false);
    assert_eq!(request["stream"], true);
}

#[test]
fn existing_profile_rendering_remains_non_background_and_unstored() {
    let profile = support::profile();
    assert!(!profile.is_background());
    let bytes = OpenAiResponsesTextRenderer::new(profile.clone())
        .prepare(&support::call(&profile))
        .unwrap();
    let request: Value = serde_json::from_slice(bytes.rendered_bytes()).unwrap();
    assert_eq!(request["background"], false);
    assert_eq!(request["store"], false);
    assert_eq!(request["stream"], true);
}

#[test]
fn background_status_requires_remote_id_and_maps_only_explicit_states() {
    let pending =
        OpenAiBackgroundResponse::from_json(br#"{"id":"resp_abc","status":"queued"}"#).unwrap();
    assert_eq!(pending.response_id().as_str(), "resp_abc");
    assert_eq!(
        pending.status(),
        &runne_provider::ProviderRemoteResponseStatus::Pending
    );
    let in_progress =
        OpenAiBackgroundResponse::from_json(br#"{"id":"resp_abc","status":"in_progress"}"#)
            .unwrap();
    assert_eq!(in_progress.status(), pending.status());

    let completed = OpenAiBackgroundResponse::from_json(
        br#"{"id":"resp_abc","status":"completed","usage":{"input_tokens":8,"output_tokens":3,"total_tokens":11,"input_tokens_details":{"cached_tokens":2},"output_tokens_details":{"reasoning_tokens":1}}}"#,
    )
    .unwrap();
    assert!(matches!(
        completed.status(),
        runne_provider::ProviderRemoteResponseStatus::Completed { usage: Some(usage) }
            if usage.input_tokens() == 8 && usage.output_tokens() == 3 && usage.cached_input_tokens() == 2
    ));

    let unknown =
        OpenAiBackgroundResponse::from_json(br#"{"id":"resp_abc","status":"future_state"}"#)
            .unwrap();
    assert_eq!(
        unknown.status(),
        &runne_provider::ProviderRemoteResponseStatus::Unknown
    );
    assert!(OpenAiBackgroundResponse::from_json(br#"{"status":"completed"}"#).is_err());
}

#[test]
fn background_status_rejects_oversize_and_malformed_usage() {
    let padded = format!(
        "{{\"id\":\"resp_abc\",\"status\":\"queued\"}}{}",
        " ".repeat(65_537)
    );
    assert_eq!(
        OpenAiBackgroundResponse::from_json(padded.as_bytes())
            .unwrap()
            .status(),
        &runne_provider::ProviderRemoteResponseStatus::Pending
    );
    assert!(OpenAiBackgroundResponse::from_json(&vec![b' '; 4_194_305]).is_err());
    assert!(OpenAiBackgroundResponse::from_json(
        br#"{"id":"resp_abc","status":"completed","usage":{"input_tokens":1,"output_tokens":1,"input_tokens_details":{"cached_tokens":2}}}"#,
    )
    .is_err());
    assert_eq!(
        OpenAiBackgroundResponse::from_json(
            br#"{"id":"resp_abc","status":"failed","error":{"code":"server_error","message":"redact me"}}"#,
        )
        .unwrap()
        .status(),
        &runne_provider::ProviderRemoteResponseStatus::Failed {
            code: Some("server_error".into()),
            usage: None,
        }
    );
    assert_eq!(
        OpenAiBackgroundResponse::from_json(
            br#"{"id":"resp_abc","status":"incomplete","incomplete_details":{"reason":"max_output_tokens"}}"#,
        )
        .unwrap()
        .status(),
        &runne_provider::ProviderRemoteResponseStatus::Incomplete {
            reason: Some("max_output_tokens".into()),
            usage: None,
        }
    );
    assert_eq!(
        OpenAiBackgroundResponse::from_json(br#"{"id":"resp_abc","status":"cancelled"}"#)
            .unwrap()
            .status(),
        &runne_provider::ProviderRemoteResponseStatus::Cancelled { usage: None }
    );
}

#[tokio::test]
async fn existing_adapter_recovery_controls_fail_closed_by_default() {
    let provider = ScriptedProvider::new([], vec![]).unwrap();
    assert_eq!(
        provider.recovery_capabilities(),
        ProviderRecoveryCapabilities::default()
    );
    let binding = ProviderRecoveryBinding::new(
        TaskRunId::from_bytes([1; 16]),
        AttemptId::from_bytes([2; 16]),
        DispatchAttemptId::from_bytes([3; 16]),
        [4; 32],
    )
    .unwrap();
    let request = ProviderRecoveryRequest::new(binding, RemoteResponseId::new("resp_x").unwrap());
    assert_eq!(
        provider.check_remote_status(request.clone()).await,
        Err(ProviderRecoveryError::Unsupported)
    );
    assert_eq!(
        provider.cancel_remote(request.clone()).await,
        Err(ProviderRecoveryError::Unsupported)
    );
    assert_eq!(
        provider
            .resume_remote_stream(ProviderResumeRequest::new(
                request,
                RemoteStreamCursor::new(4)
            ))
            .await,
        Err(ProviderRecoveryError::Unsupported)
    );
}
