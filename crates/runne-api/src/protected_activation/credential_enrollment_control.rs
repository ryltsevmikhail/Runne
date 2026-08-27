const ENROLLMENT_CONTROL_MAGIC: &[u8; 8] = b"GCPCECTL";
const ENROLLMENT_CONTROL_DOMAIN: &[u8] = b"gocode/protected-credential-enrollment-control/v1";
const ENROLLMENT_REQUEST_DIGEST_DOMAIN: &[u8] =
    b"gocode/protected-credential-enrollment-request/v1\0";
const REQUEST_PHASE: u8 = 1;
const ADMISSION_PHASE: u8 = 2;
const REQUEST_BYTES: usize = 8 + 1 + (4 * 16) + (5 * 8) + (4 * 32);
const ADMISSION_BYTES: usize = 8 + 1 + (8 * 32) + (4 * 8) + 16;

include!("credential_enrollment_control/auth.rs");
include!("credential_enrollment_control/types.rs");
include!("credential_enrollment_control/wire.rs");

#[cfg(test)]
#[path = "credential_enrollment_control_tests.rs"]
mod credential_enrollment_control_tests;
