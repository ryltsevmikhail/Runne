#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the protected V2 router remains unmounted until qualified admission is composed"
    )
)]

use runne_api::ProviderCredentialOperationHandleV2;
use serde::Deserialize;

/// Authenticated opaque resume identity with no provider or authority fields.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ResumeBody {
    pub(super) operation_id: ProviderCredentialOperationHandleV2,
}
