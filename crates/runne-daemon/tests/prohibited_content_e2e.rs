include!("prohibited_content_e2e_split_parts/part_01.rs");
include!("prohibited_content_e2e_split_parts/part_02.rs");
// The NM-06 replay scenario and its helpers are `test-support`-gated; without
// the gate their items would be dead/unused in a default build.
#[cfg(feature = "test-support")]
include!("prohibited_content_e2e_split_parts/part_04.rs");
#[cfg(feature = "test-support")]
include!("prohibited_content_e2e_split_parts/part_05.rs");
include!("prohibited_content_e2e_split_parts/part_06.rs");
