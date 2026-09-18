//! Closed provider catalog metadata.
//!
//! The catalog describes provider identity and capability metadata only. It
//! never carries endpoints, credentials, or a dispatch authorization.

mod catalog_data;
mod entries;
mod types;

pub use entries::{provider_catalog, provider_catalog_entry, provider_catalog_snapshot};
pub use types::{
    ProviderAuthKindV1, ProviderCatalogEntryV1, ProviderCatalogRouteV1, ProviderCatalogSnapshotV1,
    ProviderImplementationStatusV1, ProviderProtocolV1, ProviderQuotaPolicyV1,
};

/// Returns the catalog billing discriminator for a provider.
#[must_use]
pub fn is_subscription_provider(provider_id: &str) -> bool {
    provider_catalog_entry(provider_id)
        .is_some_and(|entry| entry.quota == types::ProviderQuotaPolicyV1::SubscriptionWindow)
}
