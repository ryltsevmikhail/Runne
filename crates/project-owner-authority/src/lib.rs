#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![allow(missing_docs)]

//! Core protocol types for solo project-owner authority.

pub(crate) mod backup;
pub(crate) mod backup_codec;
pub(crate) mod backup_validation;
mod canonical;
mod destination_allowlist;
mod destination_allowlist_canonical;
#[cfg(test)]
mod destination_allowlist_recovery_tests;
mod destination_allowlist_wire;
#[cfg(test)]
mod destination_allowlist_wire_tests;
mod error;
mod evidence_envelope_v2;
pub(crate) mod evidence_envelope_v2_codec;
mod evidence_envelope_v2_specialization;
mod evidence_envelope_v2_wire;
#[cfg(test)]
mod evidence_envelope_v2_wire_tests;
pub(crate) mod model;
pub(crate) mod receipt;
mod receipt_lineage;
mod receipt_v2;
mod receipt_v2_wire;
mod receipt_v3;
mod receipt_v3_codec;
mod receipt_v3_v2;
mod receipt_v3_v2_wire;
mod receipt_v3_wire;
pub mod receipt_v4;
mod receipt_v4_admission;
mod receipt_v4_canonical;
mod receipt_v4_context;
mod receipt_v4_prevalidated;
mod receipt_v4_profile;
pub mod receipt_v4_v3;
pub mod receipt_v4_validation;
#[cfg(test)]
mod receipt_v4_validation_tests;
pub mod receipt_v4_wire;
#[cfg(test)]
mod receipt_v4_wire_tests;
mod receipt_v5;
mod receipt_v5_admission;
mod receipt_v5_document_profile;
#[cfg(test)]
mod receipt_v5_pin_tests;
#[cfg(test)]
mod receipt_v5_prevalidation_tests;
mod receipt_v5_validation;
mod receipt_v5_wire;
#[cfg(test)]
mod receipt_v5_wire_tests;
pub(crate) mod receipt_validation;
mod receipt_wire;
mod rotation;
mod rotation_v2;
mod rotation_v2_wire;
mod rotation_v3;
mod rotation_v3_wire;
mod rotation_v4;
#[cfg(test)]
mod rotation_v4_tests;
mod rotation_wire;
#[cfg(test)]
mod stage_admission_recovery_tests;
#[cfg(test)]
mod stage_admission_tests;
mod stage_context;
pub mod stage_envelope;
mod stage_envelope_v2;
mod stage_envelope_v2_wire;
#[cfg(test)]
mod stage_envelope_v2_wire_tests;
pub mod stage_envelope_wire;
pub(crate) mod stage_envelope_wire_codec;
#[cfg(test)]
mod stage_envelope_wire_raw_tests;
#[cfg(test)]
mod stage_envelope_wire_tests;
mod stage_issuer;
mod strict_json;
mod trust;
pub(crate) mod trust_canonical;
mod trust_v2;
mod trust_v2_wire;
mod trust_v3;
mod trust_v3_wire;
mod trust_v4;
mod trust_wire;
mod v5_admission_identity;
mod v5_admission_result;
mod v5_admission_types;
mod v5_context;
mod v5_envelope_admission;
#[cfg(test)]
mod v5_envelope_prevalidation_tests;
#[cfg(test)]
mod v5_envelope_test_support;
mod v5_expectations;
#[cfg(test)]
mod v5_expectations_tests;
mod v5_lineage;
mod v5_raw;
#[cfg(test)]
mod v5_round4_admission_tests;
#[cfg(test)]
mod v5_round5_boundary_recovery_tests;
#[cfg(test)]
mod v5_round5_divergence_tests;
#[cfg(test)]
mod v5_round5_fixtures;
#[cfg(test)]
mod v5_round5_precondition_tests;
#[cfg(test)]
mod v5_round5_receipt_recovery_tests;
#[cfg(test)]
mod v5_round5_test_store;
mod v5_state_validation;

pub use backup::{
    BackupMetadataV1, BackupParameters, BackupPassphrase, BackupRng, decrypt_backup,
    encrypt_backup, key_fingerprint,
};
pub use canonical::{
    SigningDomain, canonical_checked_in_receipt, canonical_unsigned_receipt, framed_transcript,
    signing_transcript,
};
pub use destination_allowlist::{
    DESTINATION_ALLOWLIST_SCHEMA_V1, PrevalidatedDestinationAllowlistV1,
    PrevalidatedRootSignedDestinationAllowlistV1, PublicationDestinationAllowlistV1,
    PublicationDestinationV1, VerifiedDestinationAllowlist,
};
pub use destination_allowlist_canonical::{
    canonical_checked_in_allowlist_v1, canonical_unsigned_allowlist_v1,
};
pub use destination_allowlist_wire::{
    bind_prevalidated_destination_allowlist_v1, prevalidate_destination_allowlist_v1,
    prevalidate_root_signed_destination_allowlist_v1, verify_destination_allowlist_v1,
};
pub use error::AuthorityError;
pub use evidence_envelope_v2::{
    EVIDENCE_ENVELOPE_SCHEMA_V2, EvidenceAuthorityEnvelopeV2, PrevalidatedEvidenceEnvelopeV2,
    VerifiedEvidenceEnvelopeV2, VerifiedRc3FinalReviewEvidence,
};
pub use evidence_envelope_v2_specialization::verify_rc3_final_review_evidence_v2;
pub use evidence_envelope_v2_wire::{
    canonical_checked_in_evidence_envelope_v2, canonical_unsigned_evidence_envelope_v2,
    prevalidate_evidence_envelope_v2, verify_evidence_envelope_v2,
};
pub use model::{
    Document, GitSubject, ProjectOwnerPublicKey, ProjectOwnerSignature, UnsignedReceipt,
};
pub use receipt::{
    DocumentBinding, PurposeProfileV1, SignedReceipt, Signer, sign_receipt,
    v1_platform_scope_schema_digests,
};
pub use receipt_v2::{
    PROFILE_V2, PurposeProfileV2, RECEIPT_SCHEMA_V2, sign_receipt_v2,
    v2_platform_scope_schema_digests, verify_receipt_v2,
};
pub use receipt_v2_wire::verify_receipt_v2_bytes;
pub use receipt_v3::{
    FixtureVerifiedDocumentReconciliation, PROFILE_V3, PurposeProfileV3, RECEIPT_SCHEMA_V3,
    VerifiedDocumentReconciliation, VerifiedInitialAuthorization, v3_reconciliation_schema_digests,
    verify_initial_authorization_v2_bytes,
};
pub use receipt_v3_codec::{
    SignedReceiptV3, UnsignedReceiptV3, canonical_checked_in_receipt_v3,
    canonical_unsigned_receipt_v3, sign_receipt_v3,
};
pub use receipt_v3_v2::sign_receipt_v3_v2;
pub use receipt_v3_v2_wire::verify_receipt_v3_bytes;
pub use receipt_v3_wire::verify_receipt_v3_fixture_bytes;
pub use receipt_v4::{
    DelegationV1, PROFILE_V4, PURPOSE_V4, PromotionBootstrapBindings, PromotionBootstrapV4,
    RECEIPT_SCHEMA_V4, SignedPromotionBootstrapV4, VerifiedPromotionBootstrap,
    canonical_checked_in_promotion_bootstrap, canonical_unsigned_promotion_bootstrap,
    promotion_schema_pins,
};
pub use receipt_v4_admission::admit_prevalidated_promotion_bootstrap_v4;
pub use receipt_v4_context::{
    PromotionBootstrapAdmission, PromotionBootstrapAdmissionScope, PromotionBootstrapValidity,
    PromotionBootstrapVerificationContext, PromotionBootstrapVerificationState,
};
pub use receipt_v4_prevalidated::PrevalidatedPromotionBootstrapV4;
pub use receipt_v4_v3::sign_promotion_bootstrap_v3;
pub use receipt_v4_wire::{prevalidate_promotion_bootstrap_v4, verify_promotion_bootstrap_bytes};
pub use receipt_v5::{
    DelegationV2, ExpectedReceiptV5Bindings, PROFILE_V5, PURPOSE_V5,
    PrevalidatedPromotionAuthorityReceiptV5, PromotionAuthorityReceiptV5, RECEIPT_SCHEMA_V5,
    SignedPromotionAuthorityReceiptV5, V5_EVIDENCE_ROLE_SCOPES, V5_TRANSITION_ROLES,
    VerifiedPromotionAuthorityReceiptV5, VerifiedPromotionBootstrapV5, v5_receipt_schema_pins,
};
pub use receipt_v5_admission::admit_prevalidated_promotion_authority_receipt_v5;
pub use receipt_v5_wire::{
    canonical_checked_in_receipt_v5, canonical_unsigned_receipt_v5,
    prevalidate_promotion_authority_receipt_v5, verify_promotion_authority_receipt_v5,
};
pub use receipt_wire::{
    InspectedReceipt, inspect_receipt_bytes, verify_receipt_bytes,
    verify_receipt_bytes_against_subject,
};
pub use rotation::{
    KeyRotationV1, TrustResetRequired, after_explicit_compromise_declaration,
    rotation_new_pop_payload, rotation_new_pop_transcript, rotation_old_authorization_payload,
    rotation_old_authorization_transcript, verify_rotation, verify_rotation_chain,
};
pub use rotation_v2::{
    KeyRotationV2, canonical_rotation_v2, rotation_v2_new_pop_transcript,
    rotation_v2_old_authorization_transcript, rotation_v2_successor_pop_transcript,
    verify_rotation_v2, verify_trust_upgrade_v1_to_v2,
};
pub use rotation_v3::{
    KeyRotationV3, canonical_rotation_v3, rotation_v3_new_pop_transcript,
    rotation_v3_old_authorization_transcript, verify_trust_upgrade_v2_to_v3,
};
pub use rotation_v4::{
    KeyRotationV4, canonical_rotation_v4, rotation_v4_new_pop_transcript,
    rotation_v4_old_authorization_transcript, verify_trust_upgrade_v3_to_v4,
};
pub use stage_envelope::{
    STAGE_ENVELOPE_SCHEMA_V1, StageAdmission, StageAdmissionRequest, StageAdmissionScope,
    StageAuthorityEnvelopeV1, StageVerificationContext, VerifiedStageAdmission,
    VerifiedStageEnvelope, canonical_checked_in_stage_envelope, canonical_stage_payload,
    canonical_unsigned_stage_envelope,
};
pub use stage_envelope_v2::{
    EnvelopeValidityV2, PrevalidatedStageEnvelopeV2, STAGE_ENVELOPE_SCHEMA_V2,
    StageAuthorityEnvelopeV2, VerifiedStageEnvelopeV2,
};
pub use stage_envelope_v2_wire::{
    canonical_checked_in_stage_envelope_v2, canonical_unsigned_stage_envelope_v2,
    prevalidate_stage_envelope_v2, verify_stage_envelope_v2,
};

pub use stage_envelope_wire::{verify_stage_envelope_bytes, verify_stage_envelope_for_transition};
pub use stage_issuer::VerifiedStageIssuer;
pub use trust::{
    ProjectOwnerTrustConfigV1, SchemaDigest, TrustAnchorState, bootstrap_fingerprint,
    canonical_genesis, canonical_genesis_without_pop, genesis_pop_transcript, key_id,
    verify_active_trust_config, verify_anchor, verify_genesis, verify_trust_config,
};
pub use trust_v2::{
    ProjectOwnerTrustConfigV2, VerifiedTrustConfigV2, canonical_config_v2, v2_trust_schema_digests,
};
pub use trust_v3::{
    ProjectOwnerTrustConfigV3, VerifiedTrustConfigV3, canonical_config_v3, v3_trust_schema_digests,
    verify_v3_config,
};
pub use trust_v4::{
    ProjectOwnerTrustConfigV4, VerifiedTrustConfigV4, canonical_config_v4, v4_trust_schema_digests,
    verify_v4_config,
};
pub use v5_admission_types::{
    AuthorityStateSnapshot, CommandIdentity, DestinationAllowlistAdmissionRequest,
    DurableAdmission, EvidenceEnvelopeAdmissionRequest, ExistingSameReceiptV5,
    NewlyAdmittedReceiptV5, OutcomeIdentity, PersistedAdmission, PromotionIdentity,
    ReceiptV5AdmissionRequest, ReceiptV5RecoveryRequest, ReservationIdentity, RevisionIdentity,
    RoleScopeFloor, RootAuthorityIdentity5D, StageEnvelopeAdmissionRequest,
};
pub use v5_context::{
    DestinationAllowlistAdmissionScope, DestinationAllowlistVerificationContext,
    ReceiptV5AdmissionScope, ReceiptV5Validity, ReceiptV5VerificationContext, V5AdmissionScope,
    V5EnvelopeVerificationContext,
};
pub use v5_envelope_admission::{
    admit_prevalidated_destination_allowlist_v1, admit_prevalidated_evidence_envelope_v2,
    admit_prevalidated_stage_envelope_v2,
};
pub use v5_expectations::{
    GitSubjectResolutionContext, ProductionSecurityReviewVerificationContext, ResolvedGitSubject,
    VerifiedProductionSecurityReviewInstance, expected_receipt_v5_bindings, resolve_git_subject,
    verify_production_security_review_instance,
};
pub use v5_lineage::{PromotionAuthorityReceiptV5Lineage, PromotionBootstrapV4Lineage};
pub use v5_raw::{
    verify_destination_allowlist_v1_bytes, verify_evidence_envelope_v2_bytes,
    verify_promotion_authority_receipt_v5_bytes, verify_stage_envelope_v2_bytes,
};
