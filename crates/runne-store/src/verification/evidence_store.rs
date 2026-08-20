include!("evidence_store/store.rs");
include!("evidence_store/recorder.rs");
include!("evidence_store/tests.rs");

#[cfg(test)]
mod metadata_contract_tests {
    include!("evidence_store/metadata_contract_tests.rs");
}
