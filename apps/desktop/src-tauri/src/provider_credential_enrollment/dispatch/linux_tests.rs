use super::exchange::accepted_disposition;
use crate::provider_credential_enrollment::CredentialIntentAction;
use runne_platform_desktop::SecureCredentialPromptDisposition;

#[test]
fn linux_pair_and_revoke_reject_prompt_dispositions_for_the_other_action() {
    let pair_with_confirmation = accepted_disposition(
        CredentialIntentAction::Pair,
        SecureCredentialPromptDisposition::Confirmed,
    );
    let revoke_with_cancellation = accepted_disposition(
        CredentialIntentAction::Revoke,
        SecureCredentialPromptDisposition::Cancelled,
    );
    assert!(pair_with_confirmation.is_err());
    assert!(revoke_with_cancellation.is_err());
}
