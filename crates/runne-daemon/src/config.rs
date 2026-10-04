include!("config/provider_settings.rs");
include!("config/secondary_profile_catalog.rs");
include!("config/merge.rs");
include!("config/helpers.rs");
include!("config/load.rs");

#[cfg(test)]
#[path = "config/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "config/secondary_profile_catalog_tests.rs"]
mod secondary_profile_catalog_tests;
