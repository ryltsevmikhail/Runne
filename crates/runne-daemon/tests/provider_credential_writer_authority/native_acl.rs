use std::fs;
use std::path::Path;

const PASSWORD_CAPABLE_SYMBOL: &[u8] = b"SecKeychainItemSetAccessWithPassword";
const DISPOSABLE_PASSWORD: &[u8] = b"slice-e-disposable";

pub(super) fn run() {
    super::harness::dispatch(
        "reader_and_unrelated_processes_cannot_mutate_or_read_native_item",
        inner,
    );
}

fn inner(context: &super::support::InnerContext) -> Result<(), &'static str> {
    assert_reader_source_boundary()?;
    assert_reader_binary_boundary(context.daemon())?;
    context.run_positive_transcript_with_probe(Some(unrelated_probe))
}

fn unrelated_probe(context: &super::support::InnerContext) -> Result<&'static str, &'static str> {
    super::native_item::assert_unrelated_denied(context.root(), context.runtime_root())
}

fn assert_reader_source_boundary() -> Result<(), &'static str> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("repository-root")?;
    for relative in [
        "crates/runne-daemon/src/canonical_provider/credential_reader.rs",
        "crates/runne-daemon/src/canonical_provider/composition/credential_reader.rs",
    ] {
        let source = fs::read(repository.join(relative)).map_err(|_| "reader-source")?;
        for forbidden in [
            b"NativeProviderCredentialWriters".as_slice(),
            b"BrokeredProviderCredentialWriter".as_slice(),
            b"create_version".as_slice(),
            b"delete_version".as_slice(),
            b"set_password".as_slice(),
            b"SetAccessWithPassword".as_slice(),
        ] {
            if contains(&source, forbidden) {
                return Err("reader-writer-api");
            }
        }
    }

    let acl_root = repository.join("crates/runne-macos-keychain-acl/src");
    let implementation =
        fs::read(acl_root.join("implementation.inc")).map_err(|_| "acl-implementation-source")?;
    if contains(&implementation, b"local_test_keychain.inc") {
        return Err("local-finalizer-present");
    }
    let declaration =
        fs::read(acl_root.join("implementation_parts/foundation_and_process_lock.inc"))
            .map_err(|_| "acl-declaration-source")?;
    if contains(&declaration, PASSWORD_CAPABLE_SYMBOL) {
        return Err("acl-password-symbol-present");
    }
    Ok(())
}

fn assert_reader_binary_boundary(path: &Path) -> Result<(), &'static str> {
    let binary = fs::read(path).map_err(|_| "runned-binary")?;
    if contains(&binary, PASSWORD_CAPABLE_SYMBOL) || contains(&binary, DISPOSABLE_PASSWORD) {
        return Err("runned-password-capability");
    }
    Ok(())
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    find(haystack, needle).is_some()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    (!needle.is_empty())
        .then(|| {
            haystack
                .windows(needle.len())
                .position(|part| part == needle)
        })
        .flatten()
}

#[test]
fn unrelated_probe_uses_passwordless_access_replacement() {
    let source = include_bytes!("native_access.rs");
    assert!(contains(source, b"SecKeychainItemSetAccess("));
    assert!(contains(source, b"SecAccessCreateWithOwnerAndACL("));
    assert!(contains(source, b"SecACLCreateWithSimpleContents("));
    assert!(contains(source, b"SecACLUpdateAuthorizations("));
    assert!(!contains(source, b"SecAccessCreateFromOwnerAndACL("));
    assert!(!contains(source, b"SecAccessGetOwnerAndACL("));
    assert!(!contains(source, PASSWORD_CAPABLE_SYMBOL));
}

#[test]
fn password_population_follows_access_finalization() {
    let population = include_bytes!(
        "../../../runne-secure-store/src/macos/implementation_parts/keyring_and_codec.inc"
    );
    let finalized = find(population, b".finalize(exact_access)").unwrap();
    let populated = find(population, b".set_password(encoded)").unwrap();
    assert!(finalized < populated);

    let creation = include_bytes!(
        "../../../runne-macos-keychain-acl/src/implementation_parts/item_creation.inc"
    );
    assert!(!contains(creation, b"fn item_mut"));
}

#[test]
fn writer_graph_has_no_password_acl_mutation_seam() {
    let declaration = include_bytes!(
        "../../../runne-macos-keychain-acl/src/implementation_parts/foundation_and_process_lock.inc"
    );
    let implementation = include_bytes!(
        "../../../runne-macos-keychain-acl/src/implementation_parts/access_item_finalization.inc"
    );
    assert!(!contains(declaration, PASSWORD_CAPABLE_SYMBOL));
    assert!(!contains(implementation, PASSWORD_CAPABLE_SYMBOL));
}
