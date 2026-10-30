#[path = "tests_v2_binding.rs"]
mod binding;
#[path = "tests_v2_lifecycle.rs"]
mod lifecycle;
#[path = "tests_v2_managed_identity.rs"]
mod managed_identity;
#[path = "tests_v2_receipt_codec.rs"]
mod receipt_codec_tests;
#[path = "tests_v2_schema_feature.rs"]
mod schema_feature;
#[path = "tests_v2_support.rs"]
mod support;
#[cfg(target_os = "linux")]
#[path = "tests_v2_writer_restart.rs"]
mod writer_restart;
