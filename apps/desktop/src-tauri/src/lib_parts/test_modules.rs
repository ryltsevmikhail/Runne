#[cfg(test)]
#[path = "../native_root_admission_tests.rs"]
mod native_root_admission_tests;

#[cfg(all(test, feature = "test-support"))]
#[allow(clippy::significant_drop_tightening)]
#[path = "../directory_selection_expiry_tests.rs"]
mod directory_selection_expiry_tests;
#[cfg(all(test, feature = "test-support"))]
#[allow(clippy::significant_drop_tightening)]
#[path = "../directory_selection_internal_tests.rs"]
mod directory_selection_internal_tests;
#[cfg(all(test, feature = "test-support"))]
#[allow(clippy::significant_drop_tightening)]
#[path = "../directory_selection_rollback_tests.rs"]
mod directory_selection_rollback_tests;
#[cfg(all(test, feature = "test-support"))]
#[path = "../directory_selection_test_support.rs"]
mod directory_selection_test_support;
#[cfg(all(test, feature = "test-support"))]
#[allow(clippy::significant_drop_tightening)]
#[path = "../open_selected_workspace_cancellation_tests.rs"]
mod open_selected_workspace_cancellation_tests;
#[cfg(all(test, feature = "test-support"))]
#[allow(clippy::significant_drop_tightening, clippy::too_many_lines)]
#[path = "../open_selected_workspace_explicit_stop_tests.rs"]
mod open_selected_workspace_explicit_stop_tests;
#[cfg(all(test, feature = "test-support"))]
#[allow(clippy::significant_drop_tightening)]
#[path = "../open_selected_workspace_pre_send_cancellation_tests.rs"]
mod open_selected_workspace_pre_send_cancellation_tests;
#[cfg(all(test, feature = "test-support"))]
#[allow(clippy::significant_drop_tightening)]
#[path = "../open_selected_workspace_retention_tests.rs"]
mod open_selected_workspace_retention_tests;
#[cfg(all(test, feature = "test-support"))]
#[allow(clippy::significant_drop_tightening)]
#[path = "../open_selected_workspace_terminal_tests.rs"]
mod open_selected_workspace_terminal_tests;
#[cfg(all(test, feature = "test-support"))]
#[path = "../open_selected_workspace_tests.rs"]
mod open_selected_workspace_tests;

#[cfg(all(test, feature = "test-support"))]
#[allow(clippy::significant_drop_tightening)]
#[path = "../open_selected_workspace_retry_tests.rs"]
mod open_selected_workspace_retry_tests;
