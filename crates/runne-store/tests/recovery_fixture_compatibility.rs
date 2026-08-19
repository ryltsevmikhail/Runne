#[path = "recovery_fixture_compatibility_parts/readers.rs"]
mod fixture_readers;
#[path = "support/recovery/fixtures.rs"]
mod recovery_fixtures;
#[path = "support/validated_reopen.rs"]
mod validated_reopen;

include!("recovery_fixture_compatibility_parts/reads.rs");
include!("recovery_fixture_compatibility_parts/loader_safety.rs");
include!("recovery_fixture_compatibility_parts/manifest_schema.rs");
include!("recovery_fixture_compatibility_parts/tampering.rs");
include!("recovery_fixture_compatibility_parts/provider_vector.rs");
include!("recovery_fixture_compatibility_parts/writers.rs");
