//! Runtime profile selection for provider-credential enrollment.
//!
//! Task 15 keeps this decision separate from HTTP composition so qualification
//! can later be made explicit without changing route wiring.

#[cfg(feature = "desktop-protected")]
pub(super) fn runtime_capabilities(protected: bool, has_keys: bool) -> &'static [&'static str] {
    if protected && has_keys {
        runne_runtime::bundle::PUBLISHED_RUNTIME_CAPABILITIES
    } else {
        runne_runtime::bundle::BASE_RUNTIME_CAPABILITIES
    }
}

#[cfg(not(feature = "desktop-protected"))]
pub(super) fn runtime_capabilities(_: bool, _: bool) -> &'static [&'static str] {
    runne_runtime::bundle::BASE_RUNTIME_CAPABILITIES
}
