include!("config/provider_settings.rs");
include!("config/linux_cli_credential_host.rs");
include!("config/secondary_profile_catalog.rs");
include!("config/d2_safe_tool_loop_budget.rs");
include!("config/merge.rs");
include!("config/helpers.rs");
include!("config/load.rs");

#[cfg(test)]
#[path = "config/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "config/secondary_profile_catalog_tests.rs"]
mod secondary_profile_catalog_tests;

#[cfg(test)]
#[path = "config/d2_safe_tool_loop_budget_tests.rs"]
mod d2_safe_tool_loop_budget_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "config/linux_cli_credential_host_tests.rs"]
mod linux_cli_credential_host_tests;
