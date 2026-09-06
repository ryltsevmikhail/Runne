use std::{fs, path::Path};
use syn::visit::{self, Visit};

#[path = "support/qualification_issue_regressions.rs"]
mod regressions;
#[path = "support/qualification_issue_sources.rs"]
mod source_graph;
use source_graph::sources;

const MINT: &str = "issue_committed_qualification_receipt";
const STORE: &str = "runne-store/src/provider/credential_lifecycle/online/qualification_issue.rs";
const DAEMON: &str = "runne-daemon/src/application/provider_credential_enrollment/control_facade/protected_session/qualification.rs";

#[derive(Default)]
struct Audit<'a> {
    source: &'a str,
    method: String,
    mint: usize,
    fenced: usize,
    errors: Vec<String>,
}

impl<'ast> Visit<'ast> for Audit<'_> {
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        let previous = std::mem::take(&mut self.method);
        if matches!(item.vis, syn::Visibility::Public(_)) {
            let mut sensitive = Sensitive::default();
            sensitive.visit_return_type(&item.sig.output);
            if sensitive.0 {
                self.errors
                    .push("unreviewed public free qualification factory".into());
            }
        }
        visit::visit_item_fn(self, item);
        self.method = previous;
    }

    fn visit_item(&mut self, item: &'ast syn::Item) {
        let test = match item {
            syn::Item::Fn(value) => test_only(&value.attrs),
            syn::Item::Mod(value) => test_only(&value.attrs),
            syn::Item::Impl(value) => test_only(&value.attrs),
            _ => false,
        };
        if !test {
            visit::visit_item(self, item);
        }
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if test_only(&item.attrs) {
            return;
        }
        let previous = std::mem::replace(&mut self.method, item.sig.ident.to_string());
        if matches!(item.vis, syn::Visibility::Public(_)) {
            let mut sensitive = Sensitive::default();
            sensitive.visit_return_type(&item.sig.output);
            if sensitive.0 && !exact_factory(self.source, item) {
                self.errors
                    .push("unreviewed public qualification factory".into());
            }
        }
        visit::visit_impl_item_fn(self, item);
        self.method = previous;
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == MINT {
            self.mint += 1;
            if self.source != STORE {
                self.errors
                    .push("mint outside trusted committed store".into());
            }
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if path
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == MINT)
        {
            self.mint += 1;
            if self.source != STORE {
                self.errors
                    .push("qualified mint outside trusted committed store".into());
            }
        }
        visit::visit_expr_path(self, path);
    }

    fn visit_expr_struct(&mut self, value: &'ast syn::ExprStruct) {
        if value
            .path
            .segments
            .last()
            .is_some_and(|part| part.ident == "FencedQualificationAdmission")
        {
            self.fenced += 1;
            if self.source != DAEMON || self.method != "accept_qualification_fence" {
                self.errors
                    .push("fenced carrier outside consuming transition".into());
            }
        }
        visit::visit_expr_struct(self, value);
    }
}

fn exact_factory(source: &str, method: &syn::ImplItemFn) -> bool {
    if source != "runne-provider/src/credential/enrollment/authority/qualification.rs" {
        return false;
    }
    let expected = match method.sig.ident.to_string().as_str() {
        "measure_qualification_admission" => {
            "pub fn measure_qualification_admission(&self, facts: VerifiedQualificationFenceFacts, binding: QualificationSessionBinding, operation: CredentialOperationId, verified_at_unix_seconds: u64) -> Result<MeasuredQualificationAdmission, CredentialEnrollmentError> {}"
        }
        "issue_committed_qualification_receipt" => {
            "pub fn issue_committed_qualification_receipt(&self, admission: MeasuredQualificationAdmission, issued: &crate::IssuedCredentialTicketAttempt) -> Result<crate::ProviderQualificationAdmissionFenceReceipt, CredentialEnrollmentError> {}"
        }
        _ => return false,
    };
    let expected: syn::ImplItemFn = syn::parse_str(expected).unwrap();
    let mut signature = method.sig.clone();
    signature.inputs.pop_punct();
    signature == expected.sig && method.vis == expected.vis
}

#[derive(Default)]
struct Sensitive(bool);
impl<'ast> Visit<'ast> for Sensitive {
    fn visit_type_path(&mut self, path: &'ast syn::TypePath) {
        self.0 |= path.path.segments.iter().any(|segment| {
            matches!(
                segment.ident.to_string().as_str(),
                "MeasuredQualificationAdmission" | "ProviderQualificationAdmissionFenceReceipt"
            )
        });
        visit::visit_type_path(self, path);
    }
}

fn test_only(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && attr
                .parse_args::<syn::Path>()
                .is_ok_and(|path| path.is_ident("test"))
    })
}

#[test]
fn recursive_source_audit_allows_one_committed_store_mint_and_one_consuming_transition() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut files = Vec::new();
    for package in ["runne-provider", "runne-store", "runne-daemon"] {
        sources(&crates.join(package).join("src"), &mut files);
    }
    let (mut mints, mut fenced) = (0, 0);
    for path in files {
        let source = path.strip_prefix(crates).unwrap().to_str().unwrap();
        let text = fs::read_to_string(&path).unwrap();
        if ![
            MINT,
            "FencedQualificationAdmission",
            "MeasuredQualificationAdmission",
            "ProviderQualificationAdmissionFenceReceipt",
        ]
        .iter()
        .any(|token| text.contains(token))
        {
            continue;
        }
        let mut audit = Audit {
            source,
            ..Default::default()
        };
        audit.visit_file(
            &syn::parse_file(&text).unwrap_or_else(|error| panic!("{source}: {error}")),
        );
        assert!(audit.errors.is_empty(), "{source}: {:?}", audit.errors);
        mints += audit.mint;
        fenced += audit.fenced;
        if source == STORE {
            assert!(text.find("transaction.commit()").unwrap() < text.find(MINT).unwrap());
        }
    }
    assert_eq!((mints, fenced), (1, 1));
}

#[test]
fn source_audit_rejects_foreign_mint_raw_factory_and_duplicate_fenced_escape() {
    for text in [
        "fn fake(a: A) { a.issue_committed_qualification_receipt(raw, issued); }",
        "impl Receipt { pub fn raw() -> Option<ProviderQualificationAdmissionFenceReceipt> { todo!() } }",
        "impl Receipt { pub fn issue_committed_qualification_receipt() -> ProviderQualificationAdmissionFenceReceipt { todo!() } }",
        "impl Carrier { fn forge() { FencedQualificationAdmission { _admission: raw, _receipt: receipt }; } }",
    ] {
        let mut audit = Audit {
            source: "runne-daemon/src/unreviewed.rs",
            ..Default::default()
        };
        audit.visit_file(&syn::parse_file(text).unwrap());
        assert!(!audit.errors.is_empty());
    }
}
