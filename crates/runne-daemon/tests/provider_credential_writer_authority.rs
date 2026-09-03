#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

#[path = "provider_credential_writer_authority/audit.rs"]
mod audit;
#[path = "provider_credential_writer_authority/harness.rs"]
mod harness;
#[path = "provider_credential_writer_authority/keychain.rs"]
mod keychain;
#[path = "provider_credential_writer_authority/leakage.rs"]
mod leakage;
#[path = "provider_credential_writer_authority/native_acl.rs"]
mod native_acl;
#[path = "provider_credential_writer_authority/native_item.rs"]
mod native_item;
#[path = "provider_credential_writer_authority/package.rs"]
mod package;
#[path = "provider_credential_writer_authority/persistent_reference.rs"]
mod persistent_reference;
#[path = "provider_credential_writer_authority/point_of_use.rs"]
mod point_of_use;
#[path = "provider_credential_writer_authority/positive.rs"]
mod positive;
#[path = "provider_credential_writer_authority/process_faults.rs"]
mod process_faults;
#[path = "provider_credential_writer_authority/release_fault_support.rs"]
mod release_fault_support;
#[path = "provider_credential_writer_authority/release_faults.rs"]
mod release_faults;
#[path = "provider_credential_writer_authority/service_process.rs"]
mod service_process;
#[path = "provider_credential_writer_authority/support.rs"]
mod support;

#[test]
fn real_pair_transcript_persists_across_runned_restart() {
    positive::run();
}

#[test]
fn signed_writer_admission_stops_before_secret_and_reaps() {
    harness::dispatch_scenarios(
        "signed_writer_admission_stops_before_secret_and_reaps",
        &["service-joined"],
        |context, _| context.run_positive_transcript(true),
    );
}

#[test]
fn credential_service_real_process_pair_status_and_restart() {
    service_process::run();
}

#[test]
fn persistent_reference_is_bounded_or_fails_closed_on_native_acl_rewrite() {
    persistent_reference::run();
}

#[test]
fn persistent_reference_rejects_unrelated_same_uid_peer() {
    persistent_reference::unrelated_peer_run();
}

#[test]
fn wrong_replaced_and_stale_writer_attempts_have_zero_native_effect() {
    process_faults::run();
}

#[test]
fn daemon_binary_has_no_legacy_native_mutation_and_service_path_completes() {
    native_acl::run();
}

#[test]
fn release_faults_and_process_death_remain_truthful_and_reaped() {
    release_faults::run();
}

#[test]
fn real_process_sinks_and_receipts_contain_no_sensitive_material() {
    leakage::run();
}
