include!("implementation_parts/foundation_and_process_lock.inc");
include!("implementation_parts/item_creation.inc");
include!("implementation_parts/metadata.inc");
include!("implementation_parts/access_control.inc");
include!("implementation_parts/acl_record.inc");
include!("implementation_parts/exact_access_construction.inc");
include!("implementation_parts/access_item_finalization.inc");
include!("implementation_parts/access_authorization_profile.inc");
include!("implementation_parts/item_acl_mutation.inc");
include!("implementation_parts/trusted_applications.inc");
include!("implementation_parts/code_identity_partition.inc");
include!("implementation_parts/code_partition.inc");
include!("implementation_parts/security_profile_seal.inc");
#[cfg(feature = "persistent-reference-probe")]
include!("implementation_parts/persistent_reference_fixture.inc");
#[cfg(feature = "persistent-reference-probe")]
include!("implementation_parts/persistent_reference_probe.inc");
#[cfg(all(test, feature = "persistent-reference-probe"))]
include!("implementation_parts/persistent_reference_fixture_tests.inc");
#[cfg(test)]
include!("implementation_parts/tests.inc");
