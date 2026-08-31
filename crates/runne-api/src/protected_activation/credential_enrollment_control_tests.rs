use super::*;
use crate::{
    ApiActor, ApiPrincipalId, BeginProviderCredentialEnrollment,
    ProviderCredentialBeginIntentBinding, ProviderCredentialCommandContext,
    ProviderCredentialEnrollmentActionV2, ProviderCredentialProviderV2,
};
use runne_domain::id::{CommandId, IdempotencyKey};

include!("credential_enrollment_control_tests_support.rs");
include!("credential_enrollment_control_tests_basic.rs");
include!("credential_enrollment_control_tests_claims.rs");
include!("credential_enrollment_control_tests_admission.rs");
include!("credential_enrollment_control_tests_frames.rs");
include!("credential_enrollment_control_tests_validation.rs");
