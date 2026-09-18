#[path = "online/attachment.rs"]
mod attachment;
#[path = "online/begin.rs"]
mod begin;
#[path = "online/claim.rs"]
mod claim;
#[path = "online/compatibility_mirror.rs"]
mod compatibility_mirror;
#[path = "online/complete.rs"]
mod complete;
#[path = "online/completion_receipt.rs"]
mod completion_receipt;
#[path = "online/head.rs"]
mod head;
#[path = "online/legacy_cleanup_binding.rs"]
mod legacy_cleanup_binding;
#[path = "online/legacy_cutover.rs"]
mod legacy_cutover;
#[path = "online/qualification_issue.rs"]
mod qualification_issue;
#[path = "online/readback.rs"]
mod readback;
#[path = "online/readiness_observation.rs"]
mod readiness_observation;
#[path = "online/recovery.rs"]
mod recovery;
#[path = "online/recovery_admission.rs"]
mod recovery_admission;
#[path = "online/recovery_attachment.rs"]
mod recovery_attachment;
#[path = "online/recovery_claim.rs"]
mod recovery_claim;
#[path = "online/retired_cleanup.rs"]
mod retired_cleanup;
#[path = "online/rows.rs"]
mod rows;
#[path = "online/safe_projection.rs"]
mod safe_projection;
#[path = "online/verification.rs"]
mod verification;
#[path = "online/verification_context.rs"]
mod verification_context;

use runne_provider::ProviderCredentialEnrollmentStore;

#[cfg(test)]
#[path = "online/qualification_crash_tests.rs"]
mod qualification_crash_tests;
#[cfg(test)]
#[path = "online/qualification_fixture.rs"]
mod qualification_fixture;
#[cfg(test)]
#[path = "online/qualification_tests.rs"]
mod qualification_tests;

include!("online/store_port.rs");

#[cfg(test)]
#[path = "online/admission_tests.rs"]
mod online_admission_tests;
#[cfg(test)]
#[path = "online/attachment_tests.rs"]
mod online_attachment_tests;
#[cfg(test)]
#[path = "online/begin_admission_tests.rs"]
mod online_begin_admission_tests;
#[cfg(any(test, feature = "test-support"))]
#[path = "online/claim_test_support.rs"]
#[doc(hidden)]
pub mod online_claim_test_support;
#[cfg(test)]
#[path = "online/completion_tests.rs"]
mod online_completion_tests;
#[cfg(test)]
#[path = "online/head_decoder_tests.rs"]
mod online_head_decoder_tests;
#[cfg(test)]
#[path = "online/legacy_cleanup_tests.rs"]
mod online_legacy_cleanup_tests;
#[cfg(test)]
#[path = "online/legacy_cutover_tests.rs"]
mod online_legacy_cutover_tests;
#[cfg(test)]
#[path = "online/migration_provenance_tests.rs"]
mod online_migration_provenance_tests;
#[cfg(test)]
#[path = "online/provenance_tests.rs"]
mod online_provenance_tests;
#[cfg(test)]
#[path = "online/readback_tests.rs"]
mod online_readback_tests;
#[cfg(test)]
#[path = "online/recovery_tests.rs"]
mod online_recovery_tests;
#[cfg(test)]
#[path = "online/replay_tests.rs"]
mod online_replay_tests;
#[cfg(test)]
#[path = "online/retired_cleanup_tests.rs"]
mod online_retired_cleanup_tests;
#[cfg(test)]
#[path = "online/revoke_tests.rs"]
mod online_revoke_tests;
#[cfg(test)]
#[path = "online/safe_projection_tests.rs"]
mod online_safe_projection_tests;
#[cfg(test)]
#[path = "online/test_support.rs"]
pub(crate) mod online_test_support;
#[cfg(test)]
#[path = "online/tests.rs"]
mod online_tests;
#[cfg(test)]
#[path = "online/ticket_expiry_tests.rs"]
mod online_ticket_expiry_tests;
#[cfg(test)]
#[path = "online/verification_binding_tests.rs"]
mod online_verification_binding_tests;
#[cfg(test)]
#[path = "online/verification_context_tests.rs"]
mod online_verification_context_tests;
#[cfg(test)]
#[path = "online/verification_tests.rs"]
mod online_verification_tests;
#[cfg(test)]
#[path = "online/versionless_claim_tests.rs"]
mod online_versionless_claim_tests;
