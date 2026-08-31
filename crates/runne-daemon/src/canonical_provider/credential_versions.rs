//! Explicitly test-only credential lifecycle fixtures.
//!
//! Production credential composition lives in `credential_reader` and receives
//! reader-only native ports. Keeping this facade free of writer authority makes
//! that boundary regression-testable without deleting lifecycle recovery
//! fixtures used by daemon tests.

#![cfg(test)]

mod fixture_lifecycle;

pub(super) use fixture_lifecycle::compose_credential_lifecycle;
use fixture_lifecycle::{
    LegacyCredentialSource, ProvisionActivation, provision_active_from_legacy_source,
    provision_active_with_material, reconcile_native,
};

mod tests;
pub(crate) use tests::fixture_native;
