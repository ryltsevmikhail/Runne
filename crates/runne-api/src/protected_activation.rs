include!("protected_activation/secret.rs");
include!("protected_activation/identity.rs");
include!("protected_activation/binding.rs");
include!("protected_activation/request.rs");
include!("protected_activation/first_activation_prepared.rs");
include!("protected_activation/first_activation_commit.rs");
include!("protected_activation/owned_launch.rs");
include!("protected_activation/renew_request.rs");
include!("protected_activation/renew_ticket.rs");
include!("protected_activation/shutdown.rs");
include!("protected_activation/ready_model.rs");
include!("protected_activation/ready_codec.rs");
include!("protected_activation/provider_readiness.rs");
include!("protected_activation/wire_core.rs");
include!("protected_activation/wire_identity.rs");
include!("protected_activation/wire_binding.rs");
include!("protected_activation/wire_disposition.rs");
include!("protected_activation/root_admission.rs");
include!("protected_activation/root_bind_transport.rs");
include!("protected_activation/root_admission_authenticator.rs");
include!("protected_activation/root_handle_transfer_authenticator.rs");
include!("protected_activation/enrollment_launch_prelude.rs");
include!("protected_activation/enrollment_prelude_codec.rs");
include!("protected_activation/enrollment_transition_v2_prepare.rs");
include!("protected_activation/enrollment_transition_v2_view.rs");
include!("protected_activation/enrollment_transition_v2_prelude.rs");
include!("protected_activation/credential_status_v2.rs");
include!("protected_activation/credential_broker_transfer_authenticator.rs");
include!("protected_activation/credential_broker_writer_startup_authenticator.rs");
include!("protected_activation/linux_pair_secret_relay_offer.rs");
include!("protected_activation/qualification_fault_relay.rs");
include!("protected_activation/qualification_run_context_relay.rs");
mod credential_service;
pub use credential_service::*;
#[cfg(test)]
#[path = "protected_activation/enrollment_launch_prelude_tests.rs"]
mod enrollment_launch_prelude_tests;
#[cfg(test)]
#[path = "protected_activation/enrollment_transition_v2_tests.rs"]
mod enrollment_transition_v2_tests;
include!("protected_activation/enrollment_launch_binding.rs");
include!("protected_activation/enrollment_target_codec.rs");
#[cfg(test)]
#[path = "protected_activation/enrollment_target_tests.rs"]
mod enrollment_target_tests;
include!("protected_activation/enrollment_launch_v3_core.rs");
include!("protected_activation/enrollment_launch_v3_ready.rs");
include!("protected_activation/enrollment_launch_v3_renew.rs");
include!("protected_activation/enrollment_launch_v3_shutdown.rs");
#[cfg(test)]
#[path = "protected_activation/enrollment_launch_v3_adversarial_tests.rs"]
mod enrollment_launch_v3_adversarial_tests;
#[cfg(test)]
#[path = "protected_activation/enrollment_launch_v3_post_sign_tests.rs"]
mod enrollment_launch_v3_post_sign_tests;
#[cfg(test)]
#[path = "protected_activation/enrollment_launch_v3_tests.rs"]
mod enrollment_launch_v3_tests;
include!("protected_activation/root_handle_control.rs");
include!("protected_activation/credential_enrollment_control.rs");
include!("protected_activation/credential_enrollment_lifecycle.rs");
mod credential_cleanup_recovery;
mod credential_discovery;
mod credential_round;
pub use credential_cleanup_recovery::{
    ProtectedCredentialRecoveryBootstrap, ProtectedCredentialRecoveryCodec,
    ProtectedCredentialRecoveryContext, ProtectedCredentialRecoveryOffer,
};
pub use credential_discovery::ProtectedCredentialDiscoveryCodec;
pub use credential_round::{ProtectedCredentialRoundBrokerFacts, ProtectedCredentialRoundCodec};
include!("protected_activation_parts/port_17.rs");
include!("protected_activation_parts/port_18.rs");
include!("protected_activation_parts/port_19.rs");
