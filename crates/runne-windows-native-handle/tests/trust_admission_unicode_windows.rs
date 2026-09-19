#![cfg(windows)]

//! Windows regressions pinning the filesystem half of the T1 deny-set
//! contract: how the native layer (`NtCreateFile` with
//! `OBJ_CASE_INSENSITIVE`) resolves Unicode variants of frozen denied names
//! against NTFS.
//!
//! Observed on the qualification platform (NTFS, per-directory
//! case-insensitive): the NTFS upcase table folds ASCII case only. Unicode
//! variants of denied names (`ı` U+0131, `ſ` U+017F, `K` U+212A, `İ`
//! U+0130) are distinct objects — creating one never collides with the
//! denied name, and a lookup for the variant never resolves to the denied
//! file. The admission policy (ASCII-only fold) admits those variant names;
//! these tests prove the admitted variant therefore opens exactly its own
//! object and never the denied file's content. All content is synthetic.

use std::fs;
use std::io::Write as _;
use std::path::Path;

use runne_windows_native_handle::{DirectoryHandle, NativeHandleError};

const DENIED_ID_RSA: &[u8] = b"runne-synthetic-denied id_rsa v1\n";
const DENIED_HOST_KEY: &[u8] = b"runne-synthetic-denied host.key v1\n";
const DENIED_DOT_SSH: &[u8] = b"runne-synthetic-denied .ssh v1\n";
const DENIED_DOT_AWS: &[u8] = b"runne-synthetic-denied .aws v1\n";
const DENIED_CREDENTIALS: &[u8] = b"runne-synthetic-denied credentials.json v1\n";
const VARIANT_OWN: &[u8] = b"runne-synthetic-variant own content v1\n";

const DOTLESS_I: &str = "\u{0131}";
const CAPITAL_I_WITH_DOT: &str = "\u{0130}";
const LONG_S: &str = "\u{017F}";
const KELVIN_SIGN: &str = "\u{212A}";

fn open_root(path: &Path) -> DirectoryHandle {
    DirectoryHandle::open(path).expect("root directory handle")
}

fn read_via_native(root: &Path, name: &str) -> Result<Vec<u8>, NativeHandleError> {
    DirectoryHandle::open(root)
        .expect("root directory handle")
        .read_relative_file(Path::new(name), 4096)
}

/// Writes through the plain filesystem, which resolves names with the same
/// NTFS upcase table as the native layer.
fn write_plain(root: &Path, name: &str, content: &[u8]) {
    fs::write(root.join(name), content).unwrap_or_else(|error| panic!("create {name}: {error}"));
}

/// Non-destructive probe: a successful probe creation is removed again so
/// the fixture state stays exactly as the test arranged it.
fn creation_collides(root: &Path, name: &str) -> bool {
    let opened = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join(name));
    let collided = opened.is_err();
    if !collided {
        drop(opened);
        let _ = fs::remove_file(root.join(name));
    }
    collided
}

/// Creates a file that must name a distinct NTFS object; a collision would
/// otherwise silently replace the fixture through `CREATE_ALWAYS` semantics.
fn write_distinct(root: &Path, name: &str, content: &[u8]) {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join(name))
        .unwrap_or_else(|error| panic!("{name} must be distinct on NTFS: {error}"))
        .write_all(content)
        .unwrap_or_else(|error| panic!("fill {name}: {error}"));
}

/// Asserts the variant names a distinct object (`create_new` fails loudly on
/// a collision, so `CREATE_ALWAYS` can never silently replace the fixture),
/// and both names open their own content.
fn assert_distinct_pair(root: &Path, denied: &str, variant: &str, denied_content: &[u8]) {
    write_distinct(root, variant, VARIANT_OWN);

    assert_eq!(
        read_via_native(root, denied).expect("denied file must open by canonical name"),
        denied_content
    );
    assert_eq!(
        read_via_native(root, variant).expect("variant must open its own object"),
        VARIANT_OWN
    );
}

#[test]
fn control_ascii_case_variant_resolves_to_denied_file() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    write_plain(root, "id_rsa", DENIED_ID_RSA);

    assert!(creation_collides(root, "ID_RSA"), "ASCII case must collide");
    assert_eq!(
        read_via_native(root, "ID_RSA").expect("ASCII variant must open the denied file"),
        DENIED_ID_RSA
    );
}

#[test]
fn dotless_i_variants_are_distinct_from_id_rsa_and_fold_among_themselves() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    write_plain(root, "id_rsa", DENIED_ID_RSA);
    // `ı` upcases to itself on NTFS: the variant object is distinct from the
    // denied name, while ASCII case inside the rest of the name still folds.
    assert_distinct_pair(root, "id_rsa", &format!("{DOTLESS_I}d_rsa"), DENIED_ID_RSA);
    assert!(
        creation_collides(root, &format!("{DOTLESS_I}D_RSA")),
        "ASCII case inside the variant must fold onto the same object"
    );
}

#[test]
fn dotless_i_lookup_without_a_physical_file_misses_the_denied_file() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    write_plain(root, "id_rsa", DENIED_ID_RSA);

    match read_via_native(root, &format!("{DOTLESS_I}d_rsa")) {
        Ok(bytes) => panic!(
            "U+0131 lookup must not deliver denied content; got {} bytes",
            bytes.len()
        ),
        Err(NativeHandleError::Rejected) => {}
        Err(error) => panic!("unexpected native error: {error:?}"),
    }
}

#[test]
fn capital_i_with_dot_above_stays_distinct_from_id_rsa() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    write_plain(root, "id_rsa", DENIED_ID_RSA);
    assert_distinct_pair(
        root,
        "id_rsa",
        &format!("{CAPITAL_I_WITH_DOT}d_rsa"),
        DENIED_ID_RSA,
    );
}

#[test]
fn kelvin_sign_key_suffix_stays_distinct_from_denied_key() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    write_plain(root, "host.key", DENIED_HOST_KEY);
    assert_distinct_pair(
        root,
        "host.key",
        &format!("host.{KELVIN_SIGN}ey"),
        DENIED_HOST_KEY,
    );
}

#[test]
fn long_s_component_variants_stay_distinct_from_denied_files() {
    let cases: [(&str, &str, &[u8]); 3] = [
        (".ssh", &format!(".{LONG_S}sh"), DENIED_DOT_SSH),
        (".aws", &format!(".aw{LONG_S}"), DENIED_DOT_AWS),
        (
            "credentials.json",
            &format!("credential{LONG_S}.json"),
            DENIED_CREDENTIALS,
        ),
    ];
    for (denied, variant, content) in cases {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory.path();
        write_plain(root, denied, content);
        assert_distinct_pair(root, denied, variant, content);
    }
}

#[test]
fn long_s_extension_variant_stays_distinct_from_denied_credentials() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    write_plain(root, "credentials.json", DENIED_CREDENTIALS);
    assert_distinct_pair(
        root,
        "credentials.json",
        &format!("credentials.j{LONG_S}on"),
        DENIED_CREDENTIALS,
    );
}

#[test]
fn variant_only_directory_delivers_variant_content_under_its_own_name() {
    // A hostile workspace can also ship only the variant file: admission
    // admits the name, and the native layer opens exactly that object. The
    // delivered bytes are the variant's own synthetic content — never the
    // denied name's bytes, because no NTFS object carries them.
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    write_plain(root, &format!("{DOTLESS_I}d_rsa"), VARIANT_OWN);

    let entries = open_root(root).list_entries(16).expect("entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(
        read_via_native(root, &format!("{DOTLESS_I}d_rsa")).expect("variant opens under its name"),
        VARIANT_OWN
    );
}

#[test]
fn fixture_directory_is_case_insensitive() {
    // The matrix above is only meaningful on a case-insensitive directory;
    // per-directory case sensitivity (WSL) would change every expectation.
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    write_plain(root, "case_probe", VARIANT_OWN);
    assert!(
        creation_collides(root, "CASE_PROBE"),
        "fixture directory must be case-insensitive for these regressions"
    );
}
