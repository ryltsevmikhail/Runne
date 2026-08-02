//! Narrow safe wrapper for legacy macOS Keychain executable ACL APIs.
//!
//! The private implementation part contains the minimal auditable FFI needed
//! to create and verify generic-password decrypt ACLs without credential bytes.

#![cfg(target_os = "macos")]

include!("implementation.inc");
