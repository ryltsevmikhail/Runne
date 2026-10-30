#![cfg(all(
    target_os = "linux",
    feature = "desktop-protected",
    feature = "test-support"
))]
//! Validate every response mode without starting a server or provider request.
#[path = "../src/protected_activation/terminal_fixture/responses.rs"]
mod responses;
