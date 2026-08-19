//! Domain identifier newtypes — UUIDv7-based aggregate IDs,
//! bounded strings, integrity digests.

use core::fmt;

include!("id/reason.rs");
include!("id/uuid.rs");
include!("id/values.rs");

#[cfg(test)]
mod tests {
    include!("id/tests.rs");
}
