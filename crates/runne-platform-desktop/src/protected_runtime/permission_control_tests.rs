use super::*;
use std::{os::unix::net::UnixStream, time::Duration};

#[path = "permission_consent_recovery_tests.rs"]
mod permission_consent_recovery_tests;
#[path = "permission_control_tests/v1_harness.rs"]
mod v1_harness;
#[path = "permission_control_tests/v1_tests.rs"]
mod v1_tests;
#[path = "permission_control_tests/v3_harness.rs"]
mod v3_harness;
#[path = "permission_control_tests/v3_tests.rs"]
mod v3_tests;

use v1_harness::*;
use v3_harness::*;
