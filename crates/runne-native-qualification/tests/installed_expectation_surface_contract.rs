use std::fs;
use std::path::{Path, PathBuf};

use syn::visit::{self, Visit};
use syn::{Fields, ImplItem, Item, Type, Visibility};

const FACTS: &str = "VerifiedInstalledEnrollmentMeasurementFacts";
const EXPECTATION: &str = "QualificationRuntimeInstalledExpectation";

#[derive(Default)]
struct Audit {
    facts: usize,
    mint_methods: usize,
    mint_calls: usize,
    violations: Vec<String>,
    source: String,
}

impl<'ast> Visit<'ast> for Audit {
    fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
        if item.ident == FACTS {
            self.facts += 1;
            if !matches!(item.vis, Visibility::Public(_))
                || !matches!(item.fields, Fields::Named(_))
                || item
                    .fields
                    .iter()
                    .any(|field| !matches!(field.vis, Visibility::Inherited))
                || item.attrs.iter().any(|attr| attr.path().is_ident("derive"))
            {
                self.violations
                    .push(format!("{}: unsealed installed facts", self.source));
            }
        } else if matches!(item.vis, Visibility::Public(_))
            && item
                .fields
                .iter()
                .any(|field| mentions(&field.ty, EXPECTATION))
        {
            self.violations.push(format!(
                "{}: public wrapper around installed expectation",
                self.source
            ));
        }
        visit::visit_item_struct(self, item);
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        let owner_is_facts = type_is(&item.self_ty, FACTS);
        if owner_is_facts && item.trait_.is_some() {
            self.violations
                .push(format!("{}: trait impl for installed facts", self.source));
        }
        for member in &item.items {
            if let ImplItem::Fn(method) = member
                && mentions(&method.sig, EXPECTATION)
            {
                if owner_is_facts && exact_mint_signature(&method.sig) {
                    self.mint_methods += 1;
                } else {
                    self.violations.push(format!(
                        "{}: non-exact expectation method {}",
                        self.source, method.sig.ident
                    ));
                }
            }
        }
        visit::visit_item_impl(self, item);
    }

    fn visit_item(&mut self, item: &'ast Item) {
        match item {
            Item::Fn(value)
                if matches!(value.vis, Visibility::Public(_))
                    && mentions(&value.sig, EXPECTATION) =>
            {
                self.violations
                    .push(format!("{}: public free-function escape", self.source));
            }
            Item::Type(value) if mentions(&value.ty, EXPECTATION) => self
                .violations
                .push(format!("{}: expectation alias", self.source)),
            Item::Use(value)
                if matches!(value.vis, Visibility::Public(_))
                    && format!("{:?}", value.tree).contains(EXPECTATION) =>
            {
                self.violations
                    .push(format!("{}: expectation re-export", self.source));
            }
            _ => {}
        }
        visit::visit_item(self, item);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func
            && path
                .path
                .segments
                .iter()
                .any(|segment| segment.ident == EXPECTATION)
        {
            let method = path
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string());
            if self.source.ends_with("measurement_facts.rs")
                && method.as_deref() == Some("from_verified_release_session")
            {
                self.mint_calls += 1;
            } else {
                self.violations.push(format!(
                    "{}: unreviewed expectation construction",
                    self.source
                ));
            }
        }
        visit::visit_expr_call(self, call);
    }
}

#[test]
fn installed_expectation_has_one_recursive_sealed_minting_surface() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .canonicalize()
        .unwrap();
    let mut paths = Vec::new();
    collect(&root, &mut paths);
    let mut audit = Audit::default();
    for path in paths {
        audit.source = path.strip_prefix(&root).unwrap().display().to_string();
        if audit.source.starts_with("runne-native-qualification/") {
            continue;
        }
        let source = fs::read_to_string(&path).unwrap();
        if !source.contains(FACTS) && !source.contains(EXPECTATION) {
            continue;
        }
        let parsed =
            syn::parse_file(&source).unwrap_or_else(|error| panic!("{}: {error}", audit.source));
        audit.visit_file(&parsed);
    }
    assert_eq!(audit.facts, 1, "{:?}", audit.violations);
    assert_eq!(audit.mint_methods, 1, "{:?}", audit.violations);
    assert_eq!(audit.mint_calls, 1, "{:?}", audit.violations);
    assert!(audit.violations.is_empty(), "{:#?}", audit.violations);
}

fn exact_mint_signature(actual: &syn::Signature) -> bool {
    let expected: syn::ImplItemFn = syn::parse_str(
        "pub fn qualification_runtime_installed_expectation(&self, owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3) -> Option<runne_native_qualification::QualificationRuntimeInstalledExpectation> {}",
    )
    .unwrap();
    let mut actual = actual.clone();
    let mut expected = expected.sig;
    actual.inputs.pop_punct();
    expected.inputs.pop_punct();
    actual == expected
}

fn type_is(value: &Type, name: &str) -> bool {
    matches!(value, Type::Path(path) if path.path.segments.last().is_some_and(|segment| segment.ident == name))
}

fn mentions<T: std::fmt::Debug>(value: &T, name: &str) -> bool {
    format!("{value:?}").contains(name)
}

fn collect(root: &Path, paths: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect(&path, paths);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            paths.push(path);
        }
    }
}
