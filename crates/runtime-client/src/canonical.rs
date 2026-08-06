//! Authenticated canonical command/query transport.

include!("canonical/types.rs");
include!("canonical/client.rs");
include!("canonical/requests.rs");
include!("canonical/errors.rs");
include!("canonical/wire.rs");
include!("canonical/operational_telemetry.rs");

#[cfg(test)]
include!("canonical/operational_telemetry_tests.rs");
