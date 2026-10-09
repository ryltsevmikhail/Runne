use super::*;
use crate::permissions_tests::{COMMAND, MemoryIndex, current_status, saved_record, session_info};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};

#[path = "approval_response_tests/decide_tests.rs"]
mod decide_tests;
#[path = "approval_response_tests/fakes.rs"]
mod fakes;
#[path = "approval_response_tests/reopen_tests.rs"]
mod reopen_tests;

use fakes::*;
