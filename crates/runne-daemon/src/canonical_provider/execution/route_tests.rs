use super::super::super::SharedTextProviderProfile;
use super::{SelectedRoute, select_route};
use runne_api::ProviderSelectionPolicyV1;
use runne_domain::task_run::SelectedProviderProfile;
use runne_provider::{
    ProviderPricedUsage, ProviderTerminalPricing, ProviderTerminalPricingError, ProviderUsage,
    TextProviderProfile,
};
use std::sync::Arc;

struct FixedPrice(u64);
impl ProviderTerminalPricing for FixedPrice {
    fn price_terminal_usage(
        &self,
        _: &[u8; 32],
        _: &[u8; 32],
        _: i64,
        _: ProviderUsage,
    ) -> Result<ProviderPricedUsage, ProviderTerminalPricingError> {
        ProviderPricedUsage::new(self.0, "USD".into())
    }
}
impl TextProviderProfile for FixedPrice {
    fn profile_id(&self) -> &str {
        "test"
    }
    fn profile_digest(&self) -> [u8; 32] {
        [1; 32]
    }
    fn pricing_revision_digest(&self) -> [u8; 32] {
        [2; 32]
    }
    fn currency(&self) -> &str {
        "USD"
    }
    fn max_input_bytes(&self) -> usize {
        1024
    }
    fn max_input_entries(&self) -> usize {
        1
    }
    fn max_input_entry_bytes(&self) -> usize {
        1024
    }
    fn max_output_tokens(&self) -> u32 {
        10
    }
    fn max_request_bytes(&self) -> usize {
        2048
    }
    fn price_usage_micros(&self, _: ProviderUsage) -> Result<u64, ProviderTerminalPricingError> {
        Ok(self.0)
    }
}

#[test]
fn none_stays_primary_and_secondary_requires_exact_explicit_identity() {
    let primary = SelectedProviderProfile::new("primary".into(), [1; 32]).unwrap();
    let secondary = SelectedProviderProfile::new("secondary".into(), [2; 32]).unwrap();
    let wrong_digest = SelectedProviderProfile::new("secondary".into(), [3; 32]).unwrap();
    let unknown = SelectedProviderProfile::new("unknown".into(), [2; 32]).unwrap();
    let explicit = Some(ProviderSelectionPolicyV1::ExplicitOnly);

    assert_eq!(
        select_route(None, &primary, Some(&secondary), explicit),
        Some(SelectedRoute::Primary)
    );
    assert_eq!(
        select_route(Some(&primary), &primary, Some(&secondary), explicit),
        Some(SelectedRoute::Primary)
    );
    assert_eq!(
        select_route(Some(&secondary), &primary, Some(&secondary), explicit),
        Some(SelectedRoute::Secondary)
    );
    assert_eq!(
        select_route(
            Some(&secondary),
            &primary,
            Some(&secondary),
            Some(ProviderSelectionPolicyV1::DefaultEligible)
        ),
        None
    );
    assert_eq!(
        select_route(Some(&wrong_digest), &primary, Some(&secondary), explicit),
        None
    );
    assert_eq!(
        select_route(Some(&unknown), &primary, Some(&secondary), explicit),
        None
    );
}

#[test]
fn admission_ceiling_uses_the_selected_profile_pricing() {
    let primary = SharedTextProviderProfile::new(Arc::new(FixedPrice(11)));
    let secondary = SharedTextProviderProfile::new(Arc::new(FixedPrice(29)));
    assert_eq!(super::request_ceiling(&primary).unwrap().2, 11);
    assert_eq!(super::request_ceiling(&secondary).unwrap().2, 29);
}
