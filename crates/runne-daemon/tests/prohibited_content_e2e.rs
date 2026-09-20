include!("prohibited_content_e2e_split_parts/part_01.rs");
include!("prohibited_content_e2e_split_parts/part_02.rs");
include!("prohibited_content_e2e_split_parts/part_04.rs");
// Its items are consumed only by the test-support-gated NM-06 scenarios.
#[cfg(feature = "test-support")]
include!("prohibited_content_e2e_split_parts/part_05.rs");
include!("prohibited_content_e2e_split_parts/part_06.rs");
