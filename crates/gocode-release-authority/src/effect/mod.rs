//! Typed publication-effect fencing without a publication executor.

#[cfg(any(test, feature = "fixture-only"))]
mod machine;
mod types;

#[cfg(any(test, feature = "fixture-only"))]
pub use machine::FixturePublicationEffectMachine;
pub use types::{
    EffectError, EffectSnapshot, EffectState, EffectTransition, InertEffectTransitionValidator,
    PublicationEffectTransitionValidator,
};
#[cfg(any(test, feature = "fixture-only"))]
pub use types::{EffectRequestFixture, PublicationAuthorizedBinding, PublicationEffectRequest};
