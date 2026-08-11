// Non-Unix builds expose only fail-closed public stubs; Unix implementation
// details are intentionally dormant there.
#![cfg_attr(not(unix), allow(dead_code, clippy::missing_const_for_fn))]

include!("protected_runtime/state_records.rs");
include!("protected_runtime/state_store.rs");
include!("protected_runtime/launcher.rs");
include!("protected_runtime/process.rs");
include!("protected_runtime/supervisor.rs");
include!("protected_runtime/helpers.rs");
include!("protected_runtime/tests.rs");
include!("protected_runtime/renewal.rs");
#[cfg(feature = "test-support")]
include!("protected_runtime/test_root_transport.rs");
include!("protected_runtime/root_handle_transport.rs");
include!("protected_runtime_parts/port_08.rs");
include!("protected_runtime_parts/port_09.rs");
include!("protected_runtime_parts/port_10.rs");
include!("protected_runtime_parts/port_11.rs");
