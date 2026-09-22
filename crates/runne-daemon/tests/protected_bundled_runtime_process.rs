#![cfg(unix)]

#[path = "support/owner_private.rs"]
mod owner_private;
#[path = "support/secret_scan.rs"]
mod secret_scan;

include!("protected_bundled_runtime_process_split_parts/part_01.rs");
include!("protected_bundled_runtime_process_split_parts/part_02.rs");
include!("protected_bundled_runtime_process_split_parts/part_03.rs");
include!("protected_bundled_runtime_process_split_parts/part_04.rs");
include!("protected_bundled_runtime_process_split_parts/part_05.rs");
#[cfg(target_os = "linux")]
#[path = "protected_bundled_runtime_process_split_parts/linux_activation_context.rs"]
mod linux_activation_context;
