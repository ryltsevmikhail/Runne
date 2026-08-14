use super::{AdmissionWire, h};

pub(super) fn admission(
    facts: Option<&crate::admission_facts::StoredAdmissionFacts>,
) -> Option<AdmissionWire> {
    facts.and_then(|facts| {
        facts.release_facts().map(|release_facts| AdmissionWire {
            unsigned: h(facts.unsigned),
            manifest: crate::threshold_fixture_wire::hex(facts.manifest()),
            release_facts: release_facts.clone(),
        })
    })
}
