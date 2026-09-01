#![forbid(unsafe_code)]
#![deny(missing_docs)]
// TODO: add doc comments to all public items, then remove this allow.
#![allow(missing_docs)]

//! runne-domain — core domain types, commands, events, aggregates.
//!
//! No async, no IO, no external dependencies.

pub mod agent_loop;
pub use agent_loop::{
    LoopDisposition, StepOutcomeRef, StepOutcomeType, WakeCondition, WakeEvidenceRef,
};
pub use context::ContextManifestRef;
pub use plan::PlanRevisionRef;
pub mod command;
pub mod context;
pub mod conversation;
mod digest_equality_matcher;
pub mod error;
pub mod event;
pub mod id;
pub mod message;
pub mod plan;
pub mod project_workspace;
pub mod recovery;
pub mod reference;
pub mod replay;
pub mod security;
pub mod task_run;
pub mod timestamp;
pub mod verification;

#[doc(hidden)]
pub use digest_equality_matcher::DigestEqualityMatcherV1;

/// Compile-fail contract: the digest matcher is move-only and opaque.
///
/// ```compile_fail
/// use runne_domain::DigestEqualityMatcherV1;
/// fn require_clone<T: Clone>() {}
/// require_clone::<DigestEqualityMatcherV1>();
/// ```
///
/// ```compile_fail
/// use runne_domain::DigestEqualityMatcherV1;
/// fn require_copy<T: Copy>() {}
/// require_copy::<DigestEqualityMatcherV1>();
/// ```
///
/// ```compile_fail
/// use runne_domain::DigestEqualityMatcherV1;
/// fn require_debug<T: core::fmt::Debug>() {}
/// require_debug::<DigestEqualityMatcherV1>();
/// ```
///
/// ```compile_fail
/// use runne_domain::DigestEqualityMatcherV1;
/// let _ = DigestEqualityMatcherV1::default();
/// ```
///
/// Compile-fail contract: the matcher has no serialization, hashing or ordering bridge.
///
/// ```compile_fail
/// use runne_domain::DigestEqualityMatcherV1;
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<DigestEqualityMatcherV1>();
/// ```
///
/// ```compile_fail
/// use runne_domain::DigestEqualityMatcherV1;
/// fn require_hash<T: core::hash::Hash>() {}
/// require_hash::<DigestEqualityMatcherV1>();
/// ```
///
/// ```compile_fail
/// use runne_domain::DigestEqualityMatcherV1;
/// fn require_ord<T: Ord>() {}
/// require_ord::<DigestEqualityMatcherV1>();
/// ```
///
/// Compile-fail contract: callers cannot construct fields, extract bytes or convert authority.
///
/// ```compile_fail
/// use runne_domain::DigestEqualityMatcherV1;
/// let _ = DigestEqualityMatcherV1 { expected: [0; 32] };
/// ```
///
/// ```compile_fail
/// use runne_domain::DigestEqualityMatcherV1;
/// fn inspect(value: &DigestEqualityMatcherV1) {
///     let _: &[u8; 32] = value.digest();
/// }
/// ```
///
/// ```compile_fail
/// use runne_domain::DigestEqualityMatcherV1;
/// fn convert(value: DigestEqualityMatcherV1) {
///     let _: [u8; 32] = value.into();
/// }
/// ```
///
/// ```compile_fail
/// use runne_domain::DigestEqualityMatcherV1;
/// fn authorize(value: DigestEqualityMatcherV1) {
///     let _ = value.into_authority();
/// }
/// ```
///
/// Compile-fail contract: the matcher carries no file descriptor.
///
/// ```compile_fail
/// use std::os::fd::{AsFd, AsRawFd, IntoRawFd};
/// use runne_domain::DigestEqualityMatcherV1;
/// fn inspect(value: DigestEqualityMatcherV1) {
///     let _ = value.as_fd();
///     let _ = value.as_raw_fd();
///     let _ = value.into_raw_fd();
/// }
/// ```
const _: () = ();
