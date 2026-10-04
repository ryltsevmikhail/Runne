use super::*;
use crate::OPENAI_RESPONSES_BACKGROUND_PROFILE_ID;

#[test]
fn response_control_urls_are_background_only_and_segment_bounded() {
    let background = OpenAiResponsesTextProfile::from_json(include_bytes!(
        "../../../docs/profiles/openai-responses-background-text-v1.json"
    ))
    .unwrap();
    assert_eq!(
        background.profile_id(),
        OPENAI_RESPONSES_BACKGROUND_PROFILE_ID
    );
    let policy = OpenAiTransportPolicy::for_profile(&background).unwrap();
    let response_id = RemoteResponseId::new("resp_safe_1").unwrap();
    assert_eq!(
        policy.status_url(&response_id).unwrap(),
        "https://api.openai.com/v1/responses/resp_safe_1"
    );
    assert_eq!(
        policy.cancellation_url(&response_id).unwrap(),
        "https://api.openai.com/v1/responses/resp_safe_1/cancel"
    );
    assert!(
        policy
            .status_url(&RemoteResponseId::new("resp_a/../b").unwrap())
            .is_err()
    );
    assert!(
        policy
            .status_url(&RemoteResponseId::new("resp_a?x=1").unwrap())
            .is_err()
    );
    assert!(
        policy
            .status_url(&RemoteResponseId::new("resp_a%2fb").unwrap())
            .is_err()
    );

    let legacy = OpenAiResponsesTextProfile::from_json(include_bytes!(
        "../../../docs/profiles/openai-responses-text-v1.json"
    ))
    .unwrap();
    assert!(
        OpenAiTransportPolicy::for_profile(&legacy)
            .unwrap()
            .status_url(&response_id)
            .is_err()
    );
}
