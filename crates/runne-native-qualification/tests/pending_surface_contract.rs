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
#[path = "support/pending_surface_root_tests.rs"]
mod pending_surface_root_tests;
#[path = "support/pending_surface_sources.rs"]
mod pending_surface_sources;
#[path = "support/pending_surface_types.rs"]
mod pending_surface_types;

use std::path::Path;

use pending_surface_audit::audit_crate;
use pending_surface_fixture::{
    BASELINE, appended, audit_fixture, reject_all, reject_public_all, require_violations,
};

#[test]
fn production_pending_carrier_has_the_exact_ast_surface() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let violations = audit_crate(&root);
    assert!(violations.is_empty(), "{violations:#?}");
}

#[test]
fn reviewed_baseline_is_accepted() {
    assert_eq!(audit_fixture(BASELINE, &[]), Vec::<String>::new());
}

#[test]
fn reviewer_alias_raw_and_return_mutations_are_rejected() {
    let changed_return = BASELINE.replace(
        "Result<VerifiedQualificationFault, QualificationFaultError>",
        "Result<(VerifiedQualificationFault, Vec<u8>), QualificationFaultError>",
    );
    let replacement = r"
pub struct Carrier { bytes: Vec<u8> }
pub type PendingQualificationFault = Carrier;
impl Carrier { pub fn ticket(&self) -> &[u8] { &self.bytes } }
";
    require_violations(
        "raw exact impl",
        &BASELINE.replace(
            "impl PendingQualificationFault",
            "impl r#PendingQualificationFault",
        ),
        &["raw pending carrier identifier"],
    );
    require_violations(
        "raw direct struct",
        &BASELINE.replacen(
            "pub struct PendingQualificationFault",
            "pub struct r#PendingQualificationFault",
            1,
        ),
        &["must be a direct public struct"],
    );
    require_violations(
        "type alias trait",
        &appended(
            "type Carrier = PendingQualificationFault; impl AsRef<[u8]> for Carrier { fn as_ref(&self) -> &[u8] { &self.bytes } }",
        ),
        &["forbidden type alias", "trait impl"],
    );
    require_violations(
        "use alias trait",
        &appended(
            "use self::PendingQualificationFault as Carrier; impl AsRef<[u8]> for Carrier { fn as_ref(&self) -> &[u8] { &self.bytes } }",
        ),
        &["forbidden use alias", "trait impl"],
    );
    require_violations(
        "return tuple",
        &changed_return,
        &["non-exact visible pending method verify_and_consume"],
    );
    require_violations(
        "alias declaration",
        replacement,
        &[
            "forbidden type alias",
            "expected one direct public",
            "method ticket",
        ],
    );
}

#[test]
fn reusable_raw_and_borrowed_mutations_are_rejected() {
    reject_all(&[
        (
            "raw getter",
            appended(
                "impl PendingQualificationFault { pub fn ticket(&self) -> &[u8] { &self.bytes } }",
            ),
        ),
        (
            "unsafe getter",
            appended(
                "impl PendingQualificationFault { pub unsafe fn ticket(&self) -> &[u8] { &self.bytes } }",
            ),
        ),
        (
            "restricted getter",
            appended(
                "impl PendingQualificationFault { pub(crate) fn ticket(&self) -> &[u8] { &self.bytes } }",
            ),
        ),
        (
            "public expiry predicate",
            BASELINE.replace(
                "pub(crate) const fn expires_no_earlier_than",
                "pub const fn expires_no_earlier_than",
            ),
        ),
        (
            "qualified getter",
            appended(
                "impl self::PendingQualificationFault { pub fn ticket(&self) -> &[u8] { &self.bytes } }",
            ),
        ),
        (
            "AsRef",
            appended(
                "impl AsRef<[u8]> for PendingQualificationFault { fn as_ref(&self) -> &[u8] { &self.bytes } }",
            ),
        ),
        (
            "Borrow",
            appended(
                "impl std::borrow::Borrow<[u8]> for PendingQualificationFault { fn borrow(&self) -> &[u8] { &self.bytes } }",
            ),
        ),
        (
            "Deref",
            appended(
                "impl std::ops::Deref for PendingQualificationFault { type Target = [u8]; fn deref(&self) -> &[u8] { &self.bytes } }",
            ),
        ),
        (
            "Into",
            appended(
                "impl Into<Vec<u8>> for PendingQualificationFault { fn into(self) -> Vec<u8> { self.bytes } }",
            ),
        ),
        (
            "Clone",
            BASELINE.replacen("pub struct", "#[derive(Clone)] pub struct", 1),
        ),
        (
            "borrowed verify",
            BASELINE.replace("verify_and_consume(self,", "verify_and_consume(&self,"),
        ),
        (
            "borrowed encode",
            BASELINE.replace("encode_relay(self,", "encode_relay(&self,"),
        ),
        (
            "public field",
            BASELINE.replace("bytes: Vec<u8>", "pub bytes: Vec<u8>"),
        ),
        (
            "public associated const",
            appended("impl PendingQualificationFault { pub const RAW: &'static [u8] = &[]; }"),
        ),
        (
            "macro-generated trait impl",
            appended(
                "macro_rules! leak { () => { impl AsRef<[u8]> for PendingQualificationFault { fn as_ref(&self) -> &[u8] { &self.bytes } } }; } leak!();",
            ),
        ),
        (
            "path-substituted module",
            appended("#[path = \"outside.rs\"] mod substituted;"),
        ),
        (
            "conditional path-substituted module",
            appended("#[cfg_attr(test, path = \"outside.rs\")] mod substituted;"),
        ),
    ]);
}

#[test]
fn comments_and_literals_cannot_hide_public_items() {
    reject_all(&[
        (
            "string brace",
            appended(
                r#"impl PendingQualificationFault { const MASK: &'static str = "}"; pub fn ticket(&self) -> &[u8] { &self.bytes } }"#,
            ),
        ),
        (
            "raw string brace",
            appended(
                r##"impl PendingQualificationFault { const MASK: &'static str = r#"}"#; pub fn ticket(&self) -> &[u8] { &self.bytes } }"##,
            ),
        ),
        (
            "nested comment brace",
            appended(
                "impl PendingQualificationFault { /* nested /* } */ comment */ pub fn ticket(&self) -> &[u8] { &self.bytes } }",
            ),
        ),
    ]);
}

#[test]
fn whole_crate_public_escape_mutations_are_rejected() {
    reject_public_all(&[
        (
            "public consuming free function",
            "pub fn into_bytes(_: PendingQualificationFault) -> Vec<u8> { todo!() }".to_owned(),
        ),
        (
            "public nested wrapper",
            "pub struct Wrapper { pending: Option<Box<PendingQualificationFault>> }".to_owned(),
        ),
        (
            "public enum wrapper",
            "pub enum Wrapper { Pending(Option<Box<PendingQualificationFault>>) }".to_owned(),
        ),
        (
            "public union wrapper",
            "pub union Wrapper { pending: std::mem::ManuallyDrop<PendingQualificationFault> }"
                .to_owned(),
        ),
        (
            "public nested type alias",
            "pub type Wrapper = Option<Box<PendingQualificationFault>>;".to_owned(),
        ),
        (
            "public const wrapper",
            "pub const LEAK: Option<PendingQualificationFault> = None;".to_owned(),
        ),
        (
            "public trait signature",
            "pub trait Leak { fn consume(_: PendingQualificationFault); }".to_owned(),
        ),
        (
            "public associated wrapper",
            "struct Other; impl Other { pub fn consume(_: Option<PendingQualificationFault>) {} }"
                .to_owned(),
        ),
        (
            "reexported private helper",
            "struct Helper(PendingQualificationFault); pub use self::Helper as Exported;"
                .to_owned(),
        ),
        (
            "trait impl for boxed carrier",
            "trait Leak {} impl Leak for Box<PendingQualificationFault> {}".to_owned(),
        ),
        (
            "nested type alias trait",
            "type Carrier = Option<Box<PendingQualificationFault>>; impl AsRef<[u8]> for Carrier { fn as_ref(&self) -> &[u8] { &[] } }".to_owned(),
        ),
        (
            "private nested type alias",
            "type Carrier = Option<Box<PendingQualificationFault>>;".to_owned(),
        ),
        (
            "carrier in implemented trait path",
            "trait Leak<T> {} struct Other; impl Leak<PendingQualificationFault> for Other {}"
                .to_owned(),
        ),
        (
            "macro type in public signature",
            "pub fn leak(_: carrier_type!(PendingQualificationFault)) {}".to_owned(),
        ),
        (
            "macro associated item",
            "struct Other; impl Other { expose_pending!(PendingQualificationFault); }".to_owned(),
        ),
        (
            "foreign function",
            "unsafe extern \"C\" { pub fn leak(value: PendingQualificationFault); }".to_owned(),
        ),
        (
            "public trait alias",
            "pub trait Leak = Iterator<Item = PendingQualificationFault>;".to_owned(),
        ),
    ]);
}
