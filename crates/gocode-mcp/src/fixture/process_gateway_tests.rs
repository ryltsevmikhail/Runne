use std::sync::{Arc, Mutex};

use gocode_tools::*;
use serde_json::json;

use super::process::derive_process_identity_binding;
use crate::*;

include!("process_gateway_tests/support.rs");
include!("process_gateway_tests/execution_class.rs");
include!("process_gateway_tests/gateway.rs");
include!("process_gateway_tests/binding.rs");
include!("process_gateway_tests/c2b_no_mutation.rs");
include!("process_gateway_tests/concurrency.rs");
include!("process_gateway_tests/r3_visibility.rs");
