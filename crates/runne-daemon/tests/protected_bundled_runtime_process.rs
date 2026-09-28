#![cfg(unix)]

#[allow(dead_code)]
#[path = "support/nm10_rules.rs"]
mod nm10_rules;
#[path = "support/owner_private.rs"]
mod owner_private;
use nm10_rules::secret_scan;

include!("protected_bundled_runtime_process_split_parts/part_01.rs");
include!("protected_bundled_runtime_process_split_parts/part_02.rs");
include!("protected_bundled_runtime_process_split_parts/part_03.rs");
include!("protected_bundled_runtime_process_split_parts/part_04.rs");
include!("protected_bundled_runtime_process_split_parts/part_05.rs");
#[cfg(target_os = "linux")]
#[path = "protected_bundled_runtime_process_split_parts/d14b_hostile.rs"]
mod d14b_hostile;
#[cfg(target_os = "linux")]
#[path = "protected_bundled_runtime_process_split_parts/d16_kill_boundaries.rs"]
mod d16_kill_boundaries;
#[cfg(target_os = "linux")]
#[path = "protected_bundled_runtime_process_split_parts/linux_activation_context.rs"]
mod linux_activation_context;
#[cfg(target_os = "linux")]
#[path = "protected_bundled_runtime_process_split_parts/t1_positive.rs"]
mod t1_positive;
#[cfg(target_os = "linux")]
#[path = "protected_bundled_runtime_process_split_parts/t1_positive_parent.rs"]
mod t1_positive_parent;
#[cfg(target_os = "linux")]
#[path = "protected_bundled_runtime_process_split_parts/t1_restart.rs"]
mod t1_restart;
#[cfg(target_os = "linux")]
#[path = "protected_bundled_runtime_process_split_parts/t1_support.rs"]
mod t1_support;
#[cfg(target_os = "linux")]
#[path = "protected_bundled_runtime_process_split_parts/t1_text_only.rs"]
mod t1_text_only;
#[cfg(target_os = "linux")]
#[path = "protected_bundled_runtime_process_split_parts/t1_text_only_support.rs"]
mod t1_text_only_support;
#[cfg(target_os = "linux")]
#[path = "protected_bundled_runtime_process_split_parts/t1_transport_loss.rs"]
mod t1_transport_loss;
#[cfg(target_os = "linux")]
#[path = "protected_bundled_runtime_process_split_parts/t1_trust_control.rs"]
mod t1_trust_control;
#[cfg(target_os = "linux")]
#[path = "protected_bundled_runtime_process_split_parts/t1_trust_race.rs"]
mod t1_trust_race;
