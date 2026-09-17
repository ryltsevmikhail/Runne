//! Narrow safe wrapper for legacy macOS Keychain executable ACL APIs.
//!
//! The private implementation part contains the minimal auditable FFI needed
//! to create generic-password items (empty or populated in the same atomic
//! creation step) and verify their decrypt ACLs without post-creation
//! modifications, which macOS 27 punishes by erasing the partition ACL.

#![cfg(target_os = "macos")]

include!("implementation.inc");
