//! Contract-level negative guarantees, enforced by compile-fail doctests.
//!
//! ```compile_fail
//! fn require_clone<T: Clone>() {}
//! require_clone::<runne_provider::RawCredentialTicket>();
//! ```
//! ```compile_fail
//! fn require_serialize<T: serde::Serialize>() {}
//! require_serialize::<runne_provider::RawCredentialTicket>();
//! ```
//! ```compile_fail
//! fn require_durable<T: Into<runne_provider::CredentialOperationSnapshot>>() {}
//! require_durable::<runne_provider::RawCredentialTicket>();
//! ```
//! ```compile_fail
//! fn require_clone<T: Clone>() {}
//! require_clone::<runne_provider::CredentialNativeCreateClaim>();
//! ```
//! ```compile_fail
//! fn require_serialize<T: serde::Serialize>() {}
//! require_serialize::<runne_provider::CredentialNativeCreateClaim>();
//! ```
//! ```compile_fail
//! fn require_durable<T: Into<runne_provider::CredentialOperationSnapshot>>() {}
//! require_durable::<runne_provider::CredentialNativeCreateClaim>();
//! ```
//! ```compile_fail
//! fn require_clone<T: Clone>() {}
//! require_clone::<runne_provider::CredentialGcClaim>();
//! ```
//! ```compile_fail
//! fn require_serialize<T: serde::Serialize>() {}
//! require_serialize::<runne_provider::CredentialGcClaim>();
//! ```
//! ```compile_fail
//! fn require_durable<T: Into<runne_provider::CredentialOperationSnapshot>>() {}
//! require_durable::<runne_provider::CredentialGcClaim>();
//! ```
//! ```compile_fail
//! let _ = runne_provider::TransitionCommand::new;
//! ```
//! ```compile_fail
//! let _ = runne_provider::CandidateSourceIdentity::from_measured([1; 32]);
//! ```
//! ```compile_fail
//! let _ = runne_provider::ExpectedInstallMeasurement::from_measured([1; 32]);
//! ```
//! ```compile_fail
//! fn require_clone<T: Clone>() {}
//! require_clone::<runne_provider::CredentialSecretClaimOffer>();
//! require_clone::<runne_provider::PendingCredentialSecretOpening>();
//! require_clone::<runne_provider::SealedCredentialEnvelope>();
//! ```
//! ```compile_fail
//! fn require_serialize<T: serde::Serialize>() {}
//! require_serialize::<runne_provider::CredentialSecretClaimOffer>();
//! require_serialize::<runne_provider::PendingCredentialSecretOpening>();
//! require_serialize::<runne_provider::SealedCredentialEnvelope>();
//! ```
//! ```compile_fail
//! use runne_provider::CredentialSecretClaimOffer;
//! let _ = CredentialSecretClaimOffer {};
//! ```
//! ```compile_fail
//! use runne_provider::CredentialSecretPublicationSigner;
//! let _ = CredentialSecretPublicationSigner::generate([1; 32]);
//! ```
//! ```compile_fail
//! use runne_provider::daemon_credential_publication::CredentialSecretPublicationSigner;
//! let _ = CredentialSecretPublicationSigner::generate([1; 32]);
//! ```
//! ```compile_fail
//! use runne_provider::daemon_credential_publication::CredentialWriterSessionAttestationSigner;
//! use runne_provider::CredentialWriterSessionAttestationClaimsV1;
//! fn attest_twice(
//!     signer: CredentialWriterSessionAttestationSigner,
//!     first: CredentialWriterSessionAttestationClaimsV1,
//!     second: CredentialWriterSessionAttestationClaimsV1,
//! ) {
//!     let _ = signer.sign(first);
//!     let _ = signer.sign(second);
//! }
//! ```
//! ```compile_fail
//! fn require_clone<T: Clone>() {}
//! require_clone::<runne_provider::SignedCredentialWriterSessionAttestationV1>();
//! require_clone::<runne_provider::daemon_credential_publication::CredentialWriterSessionAttestationSigner>();
//! ```
//! ```compile_fail
//! fn require_serialize<T: serde::Serialize>() {}
//! require_serialize::<runne_provider::SignedCredentialWriterSessionAttestationV1>();
//! require_serialize::<runne_provider::daemon_credential_publication::CredentialWriterSessionAttestationSigner>();
//! ```
//! ```compile_fail
//! fn require_clone<T: Clone>() {}
//! require_clone::<runne_provider::CredentialWriterSessionTicketClaimsV1>();
//! ```
//! ```compile_fail
//! fn require_clone<T: Clone>() {}
//! require_clone::<runne_provider::CredentialWriterSessionRuntimeClaimsV1>();
//! ```
//! ```compile_fail
//! fn require_clone<T: Clone>() {}
//! require_clone::<runne_provider::CredentialWriterSessionProcessClaimsV1>();
//! ```
//! ```compile_fail
//! fn require_serialize<T: serde::Serialize>() {}
//! require_serialize::<runne_provider::CredentialWriterSessionTicketClaimsV1>();
//! ```
//! ```compile_fail
//! fn require_serialize<T: serde::Serialize>() {}
//! require_serialize::<runne_provider::CredentialWriterSessionRuntimeClaimsV1>();
//! ```
//! ```compile_fail
//! fn require_serialize<T: serde::Serialize>() {}
//! require_serialize::<runne_provider::CredentialWriterSessionProcessClaimsV1>();
//! ```
//! ```compile_fail
//! fn require_clone<T: Clone>() {}
//! fn post_attestation_signer_is_not_clone(
//!     _: runne_provider::daemon_credential_publication::CredentialSecretPublicationSigner,
//! ) {
//!     require_clone::<runne_provider::daemon_credential_publication::CredentialSecretPublicationSigner>();
//! }
//! ```
//! ```compile_fail
//! fn require_serialize<T: serde::Serialize>() {}
//! fn post_attestation_signer_is_not_serializable(
//!     _: runne_provider::daemon_credential_publication::CredentialSecretPublicationSigner,
//! ) {
//!     require_serialize::<runne_provider::daemon_credential_publication::CredentialSecretPublicationSigner>();
//! }
//! ```
//! ```compile_fail
//! fn post_attestation_signer_cannot_escape_private_key(
//!     signer: runne_provider::daemon_credential_publication::CredentialSecretPublicationSigner,
//! ) {
//!     let _ = signer.into_private_key();
//! }
//! ```
//! ```compile_fail
//! use runne_provider::SignedCredentialWriterSessionAttestationV1;
//! let _ = SignedCredentialWriterSessionAttestationV1 {};
//! ```
//! ```compile_fail
//! use runne_provider::daemon_credential_publication::CredentialWriterSessionAttestationSigner;
//! fn escape(signer: CredentialWriterSessionAttestationSigner) {
//!     let _ = signer.into_private_key();
//! }
//! ```
//! ```compile_fail
//! fn cannot_expose(envelope: runne_provider::SealedCredentialEnvelope) {
//!     let _ = envelope.into_vec();
//! }
//! ```
//! ```compile_fail
//! use runne_provider::CredentialBrokerFrame;
//! fn cannot_mint_seal_capability(frame: CredentialBrokerFrame) {
//!     let CredentialBrokerFrame::ClaimAccepted { .. } = frame else { return };
//!     let _ = frame.seal(Vec::new());
//! }
//! ```
//! ```compile_fail
//! fn cannot_use_generic_secret_callback(envelope: runne_provider::SealedCredentialEnvelope) {
//!     envelope.with_secret(|_| ());
//! }
//! ```
//! ```compile_fail
//! use runne_provider::AuthenticatedCredentialSecretRelaySealer;
//! ```
//! ```compile_fail
//! use runne_provider::{
//!     AuthorizedCredentialSecretOpening, CredentialDecryptedMaterial,
//!     CredentialSecretPublicationVerifier, OpenedCredentialSecretEffect,
//!     VerifiedCredentialSecretOffer,
//! };
//! fn raw_credential_capabilities_are_not_external(
//!     verifier: CredentialSecretPublicationVerifier,
//!     verified: VerifiedCredentialSecretOffer,
//!     authorization: AuthorizedCredentialSecretOpening,
//!     material: CredentialDecryptedMaterial,
//!     effect: OpenedCredentialSecretEffect,
//! ) {
//!     let _ = (verifier, verified, authorization, material, effect);
//! }
//! ```
