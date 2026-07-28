//! Provider effect admission and application coordination.

mod admission;
mod coordinator;

pub use admission::{
    ProviderAdmissionError, ProviderEffectAdmission, ProviderEffectAuthorityRecord,
    ProviderEffectAuthorityRef, ProviderEffectRequest,
};
pub use coordinator::{
    ProviderCoordinatorOutcome, ProviderCoordinatorRequest, ProviderDispatchCoordinator,
};
