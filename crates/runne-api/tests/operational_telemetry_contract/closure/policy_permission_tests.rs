use super::{lexer, policy_io};

const PERMISSION_PROJECTION: &str =
    "crates/runne-daemon/src/application/http_startup/command_hosts/permission_projection.rs";
const OTHER_CLOSURE_FILE: &str =
    "crates/runne-daemon/src/application/http_startup/command_hosts/other.rs";

const EXACT_MAPPER: &str = "use runne_store::store::{PermissionModeStoreError, StoreTransaction}; fn store_error(value: PermissionModeStoreError) { match value { PermissionModeStoreError::Command(_) => {} } }";
const IMPORT_ONLY: &str = "use runne_store::store::{PermissionModeStoreError};";

fn audit(path: &str, source: &str) -> Result<(), String> {
    policy_io::audit_tokens(path, &lexer::tokenize(source)?)
}

#[test]
fn store_command_variant_label_accepts_only_the_exact_mapper_shape() {
    let synthetic = audit(PERMISSION_PROJECTION, EXACT_MAPPER);
    assert!(synthetic.is_ok(), "{synthetic:?}");
    let actual = include_str!(
        "../../../../runne-daemon/src/application/http_startup/command_hosts/permission_projection.rs"
    );
    let audited = audit(PERMISSION_PROJECTION, actual);
    assert!(audited.is_ok(), "{audited:?}");
}

#[test]
fn store_command_variant_allowance_rejects_every_spoof_and_neighbor() {
    for (path, source) in [
        // std::process::Command itself stays rejected, even in the mapper.
        (PERMISSION_PROJECTION, "use std::process::Command;"),
        (
            PERMISSION_PROJECTION,
            "fn spawn() { let child = Command::new(\"runne\"); }",
        ),
        // Wrong type or bare variant labels are not the audited shape.
        (
            PERMISSION_PROJECTION,
            "fn map(value: Other) { match value { Other::Command(code) => {} } }",
        ),
        (PERMISSION_PROJECTION, "enum Other { Command(u8) }"),
        // The exact qualified label outside the audited mapper file.
        (OTHER_CLOSURE_FILE, EXACT_MAPPER),
        // Foreign module-qualified prefix must not pass by suffix match.
        (
            PERMISSION_PROJECTION,
            "use runne_store::store::{PermissionModeStoreError}; fn map(value: foo::PermissionModeStoreError) { match value { foo::PermissionModeStoreError::Command(_) => {} } }",
        ),
        // Usage without the actual runne_store import binding.
        (
            PERMISSION_PROJECTION,
            "fn map(value: PermissionModeStoreError) { match value { PermissionModeStoreError::Command(_) => {} } }",
        ),
        // Aliased or path-qualified import entries do not bind the symbol.
        (
            PERMISSION_PROJECTION,
            "use runne_store::store::{PermissionModeStoreError as StoreError}; fn map(value: PermissionModeStoreError) { match value { PermissionModeStoreError::Command(_) => {} } }",
        ),
        (
            PERMISSION_PROJECTION,
            "use runne_store::store::{other::PermissionModeStoreError}; fn map(value: PermissionModeStoreError) { match value { PermissionModeStoreError::Command(_) => {} } }",
        ),
        // Nested diagnostic/process escapes under the allowed label stay audited.
        (
            PERMISSION_PROJECTION,
            "use runne_store::store::{PermissionModeStoreError}; fn map(value: PermissionModeStoreError) { match value { PermissionModeStoreError::Command(error) => { debug_assert!(error); } } }",
        ),
        (
            PERMISSION_PROJECTION,
            "use runne_store::store::{PermissionModeStoreError}; fn map(value: PermissionModeStoreError) { match value { PermissionModeStoreError::Command(error) => { let child = Command::new(error); } } }",
        ),
    ] {
        assert!(audit(path, source).is_err(), "{path}: {source}");
    }
    // Control: the import binding alone contributes nothing rejected.
    assert!(audit(PERMISSION_PROJECTION, IMPORT_ONLY).is_ok());
}

#[test]
fn store_command_variant_accepts_only_exact_match_pattern_continuations() {
    for source in [
        "use runne_store::store::{PermissionModeStoreError}; fn map(value: PermissionModeStoreError) { match value { PermissionModeStoreError::Command(Error::StaleRevision) => {} } }",
        "use runne_store::store::{PermissionModeStoreError}; fn map(value: PermissionModeStoreError) { match value { PermissionModeStoreError::Command(_) | PermissionModeStoreError::Unavailable => {} } }",
    ] {
        let accepted = audit(PERMISSION_PROJECTION, source);
        assert!(accepted.is_ok(), "{source}: {accepted:?}");
    }
}

/// Reviewer canaries (H1): std::process::Command bypass shapes. None of
/// these may ever be accepted: a local module alias legally shadowing the
/// enum import, constructor/type/import positions of the qualified path,
/// and pattern-looking uses under a shadowed name.
#[test]
fn store_command_variant_rejects_h1_process_bypass_canaries() {
    for source in [
        // Grouped std alias + qualified constructor chain in one statement.
        "use runne_store::store::{PermissionModeStoreError}; use std::{process as PermissionModeStoreError}; let _ = PermissionModeStoreError::Command::new(\"true\").status();",
        // Ungrouped module alias shadow with a pattern-looking usage.
        "use runne_store::store::{PermissionModeStoreError}; use std::process as PermissionModeStoreError; fn map(value: PermissionModeStoreError) { match value { PermissionModeStoreError::Command(_) => {} } }",
        // Qualified constructor continuation without any alias.
        "use runne_store::store::{PermissionModeStoreError}; fn spawn() { let child = PermissionModeStoreError::Command::new(\"runne\"); }",
        // Type position of the qualified path.
        "use runne_store::store::{PermissionModeStoreError}; fn typed() { let value: PermissionModeStoreError::Command; }",
        // Import position: binds a qualified sub-path, not the enum symbol.
        "use runne_store::store::{PermissionModeStoreError::Command as MakeError}; fn make() { let _ = MakeError; }",
    ] {
        let rejected = audit(PERMISSION_PROJECTION, source);
        assert!(rejected.is_err(), "{source}: {rejected:?}");
    }
}

/// Reviewer canaries (M1): import-binding defects. The binding must be the
/// exact first-level whole-symbol entry of the first
/// `use runne_store::store::{...}` group — no spillover into later imports,
/// no alias targets, no nested groups, no decoy-first tolerance.
#[test]
fn store_command_variant_rejects_m1_import_binding_canaries() {
    for source in [
        // Spillover: the real group lacks the symbol; a later aliased
        // import must not satisfy the binding.
        "use runne_store::store::{StoreTransaction}; use std::{process as PermissionModeStoreError}; fn map(value: PermissionModeStoreError) { match value { PermissionModeStoreError::Command(_) => {} } }",
        // Alias target inside the real import group.
        "use runne_store::store::{StoreError as PermissionModeStoreError}; fn map(value: PermissionModeStoreError) { match value { PermissionModeStoreError::Command(_) => {} } }",
        // Nested group entry is not a direct first-level symbol.
        "use runne_store::store::{other::{PermissionModeStoreError}}; fn map(value: PermissionModeStoreError) { match value { PermissionModeStoreError::Command(_) => {} } }",
        // Decoy first group before the real one: fail closed.
        "use runne_store::store::{StoreTransaction}; use runne_store::store::{PermissionModeStoreError}; fn map(value: PermissionModeStoreError) { match value { PermissionModeStoreError::Command(_) => {} } }",
    ] {
        let rejected = audit(PERMISSION_PROJECTION, source);
        assert!(rejected.is_err(), "{source}: {rejected:?}");
    }
}
