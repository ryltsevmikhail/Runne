#![allow(dead_code)]

#[path = "support/pending_public_surface.rs"]
mod pending_public_surface;
#[path = "support/pending_surface_aliases.rs"]
mod pending_surface_aliases;
#[path = "support/pending_surface_allowlist.rs"]
mod pending_surface_allowlist;
#[path = "support/pending_surface_audit.rs"]
mod pending_surface_audit;
#[path = "support/pending_surface_fixture.rs"]
mod pending_surface_fixture;
#[path = "support/pending_surface_sources.rs"]
mod pending_surface_sources;
#[path = "support/pending_surface_types.rs"]
mod pending_surface_types;

use pending_surface_fixture::{BASELINE, audit_fixture};

const ADMISSION: &str = r"
pub struct PendingQualificationAdmission {
    _context: PendingQualificationRunContext,
    _fault: PendingQualificationFault,
}
impl PendingQualificationAdmission {
    pub fn from_admitted_bundle(bytes: Vec<u8>) -> Result<Self, QualificationAdmissionError> { todo!() }
}
";

const REEXPORT: &str =
    "pub use admission::{PendingQualificationAdmission, QualificationAdmissionError};";

fn audit(admission: &str, reexport: &str) -> Vec<String> {
    audit_fixture(
        BASELINE,
        &[("admission.rs", admission), ("lib.rs", reexport)],
    )
}

#[test]
fn exact_admission_wrapper_is_the_only_pending_carrier_exception() {
    let valid = audit(ADMISSION, REEXPORT);
    assert!(valid.is_empty(), "{valid:#?}");
    for (label, admission, reexport) in [
        (
            "public fault field",
            ADMISSION.replace("_fault: Pending", "pub _fault: Pending"),
            REEXPORT.to_owned(),
        ),
        (
            "raw getter",
            ADMISSION.replace(
                "pub fn from_admitted_bundle",
                "pub fn bytes(&self) -> &[u8] { &[] } pub fn from_admitted_bundle",
            ),
            REEXPORT.to_owned(),
        ),
        (
            "borrowed constructor",
            ADMISSION.replace("bytes: Vec<u8>", "bytes: &[u8]"),
            REEXPORT.to_owned(),
        ),
        (
            "renamed reexport",
            ADMISSION.to_owned(),
            "pub use admission::PendingQualificationAdmission as Leak;".to_owned(),
        ),
        (
            "extra glob in exact group",
            ADMISSION.to_owned(),
            "pub use admission::{PendingQualificationAdmission, QualificationAdmissionError, *};"
                .to_owned(),
        ),
        (
            "extra rename in exact group",
            ADMISSION.to_owned(),
            "pub use admission::{PendingQualificationAdmission, QualificationAdmissionError, PendingQualificationAdmission as Leak};"
                .to_owned(),
        ),
        (
            "extra nested path in exact group",
            ADMISSION.to_owned(),
            "pub use admission::{PendingQualificationAdmission, QualificationAdmissionError, nested::PendingQualificationAdmission};"
                .to_owned(),
        ),
    ] {
        assert!(!audit(&admission, &reexport).is_empty(), "{label}");
    }
}
