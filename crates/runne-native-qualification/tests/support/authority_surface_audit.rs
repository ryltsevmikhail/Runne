use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use syn::{Fields, ImplItem, Item, Visibility};

use crate::authority_surface_expected::{SENSITIVE, expected_methods, expected_signature};
use crate::authority_surface_types::{
    is_public, is_raw, node_mentions, plain_ident, sensitive_ident, signature_mentions,
    type_mentions, type_name,
};
use crate::authority_use_audit;

pub fn audit_crate(root: &Path) -> Vec<String> {
    let mut sources = Vec::new();
    collect(root, &mut sources);
    let owned = sources
        .into_iter()
        .map(|path| {
            let name = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .display()
                .to_string();
            (name, fs::read_to_string(path).expect("read Rust source"))
        })
        .collect::<Vec<_>>();
    audit(
        &owned
            .iter()
            .map(|(name, text)| (name.as_str(), text.as_str()))
            .collect::<Vec<_>>(),
        true,
    )
}

pub fn audit_sources(sources: &[(&str, &str)]) -> Vec<String> {
    audit(sources, false)
}

fn audit(sources: &[(&str, &str)], require_complete: bool) -> Vec<String> {
    let mut audit = Audit::default();
    for (source, text) in sources {
        match syn::parse_file(text) {
            Ok(file) => audit.items(&file.items, source, 0),
            Err(error) => audit.violations.push(format!("{source}: parse: {error}")),
        }
    }
    if require_complete {
        audit.require_complete();
    }
    audit.violations
}

fn collect(root: &Path, paths: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(root).expect("read source tree") {
        let path = entry.expect("source entry").path();
        if path.is_dir() {
            collect(&path, paths);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            paths.push(path);
        }
    }
}

#[derive(Default)]
struct Audit {
    declarations: BTreeMap<String, usize>,
    methods: BTreeMap<(String, String), usize>,
    violations: Vec<String>,
}

impl Audit {
    fn items(&mut self, items: &[Item], source: &str, depth: usize) {
        for item in items {
            self.item(item, source, depth);
        }
    }

    fn item(&mut self, item: &Item, source: &str, depth: usize) {
        match item {
            Item::Struct(value) if sensitive_ident(&value.ident) => {
                let name = plain_ident(&value.ident);
                *self.declarations.entry(name.clone()).or_default() += 1;
                if is_raw(&value.ident)
                    || !matches!(value.vis, Visibility::Public(_))
                    || matches!(value.fields, Fields::Unit)
                    || value
                        .fields
                        .iter()
                        .any(|field| !matches!(field.vis, Visibility::Inherited))
                    || value.attrs.iter().any(|attr| !attr.path().is_ident("doc"))
                    || !value.generics.params.is_empty()
                    || value.generics.where_clause.is_some()
                {
                    self.violations
                        .push(format!("{source}: unsafe {name} declaration"));
                }
            }
            Item::Impl(value) => self.inspect_impl(value, source),
            Item::Struct(value)
                if is_public(&value.vis)
                    && (value.fields.iter().any(|field| type_mentions(&field.ty))
                        || node_mentions(&value.generics)) =>
            {
                self.violations
                    .push(format!("{source}: public wrapper around guarded authority"));
            }
            Item::Enum(value)
                if is_public(&value.vis)
                    && (value
                        .variants
                        .iter()
                        .flat_map(|variant| variant.fields.iter())
                        .any(|field| type_mentions(&field.ty))
                        || node_mentions(&value.generics)) =>
            {
                self.violations
                    .push(format!("{source}: public enum wraps guarded authority"));
            }
            Item::Union(value)
                if is_public(&value.vis)
                    && value
                        .fields
                        .named
                        .iter()
                        .any(|field| type_mentions(&field.ty)) =>
            {
                self.violations
                    .push(format!("{source}: public union wraps guarded authority"));
            }
            Item::Type(value) if type_mentions(&value.ty) => self
                .violations
                .push(format!("{source}: alias involving guarded authority")),
            Item::Fn(value) if is_public(&value.vis) && signature_mentions(&value.sig) => {
                self.violations.push(format!(
                    "{source}: public function exposes guarded authority"
                ));
            }
            Item::Const(value) if is_public(&value.vis) && type_mentions(&value.ty) => self
                .violations
                .push(format!("{source}: public const exposes guarded authority")),
            Item::Static(value) if is_public(&value.vis) && type_mentions(&value.ty) => self
                .violations
                .push(format!("{source}: public static exposes guarded authority")),
            Item::Trait(value) if is_public(&value.vis) && node_mentions(value) => self
                .violations
                .push(format!("{source}: public trait exposes guarded authority")),
            Item::TraitAlias(value) if is_public(&value.vis) && node_mentions(value) => {
                self.violations.push(format!(
                    "{source}: public trait alias exposes guarded authority"
                ));
            }
            Item::ForeignMod(value) if node_mentions(value) => self.violations.push(format!(
                "{source}: foreign signature exposes guarded authority"
            )),
            Item::Use(value) => {
                if let Some(violation) = authority_use_audit::violation(value, source, depth) {
                    self.violations.push(violation);
                }
            }
            Item::Mod(value) => {
                if value
                    .attrs
                    .iter()
                    .any(|attr| attr.path().is_ident("path") || attr.path().is_ident("cfg_attr"))
                {
                    self.violations
                        .push(format!("{source}: path-substituted module"));
                }
                if let Some((_, nested)) = &value.content {
                    self.items(nested, source, depth + 1);
                }
            }
            Item::Macro(_) | Item::Verbatim(_) => self
                .violations
                .push(format!("{source}: opaque module item")),
            _ => {}
        }
    }

    fn inspect_impl(&mut self, item: &syn::ItemImpl, source: &str) {
        let owner = type_name(&item.self_ty);
        let guarded_owner = owner
            .as_deref()
            .is_some_and(|name| SENSITIVE.contains(&name));
        if guarded_owner && item.trait_.is_some()
            || item
                .trait_
                .as_ref()
                .is_some_and(|(_, path, _)| node_mentions(path))
        {
            self.violations
                .push(format!("{source}: trait impl exposes guarded authority"));
            return;
        }
        for member in &item.items {
            match member {
                ImplItem::Fn(method) if is_public(&method.vis) => {
                    if test_support_only(&method.attrs) {
                        continue;
                    }
                    if guarded_owner {
                        self.inspect_guarded_method(owner.as_deref().unwrap(), method, source);
                    } else if signature_mentions(&method.sig) {
                        self.violations.push(format!(
                            "{source}: public associated function exposes guarded authority"
                        ));
                    }
                }
                ImplItem::Const(value) if is_public(&value.vis) && type_mentions(&value.ty) => {
                    self.violations.push(format!(
                        "{source}: associated const exposes guarded authority"
                    ));
                }
                ImplItem::Type(value) if is_public(&value.vis) && type_mentions(&value.ty) => {
                    self.violations.push(format!(
                        "{source}: associated type exposes guarded authority"
                    ));
                }
                ImplItem::Macro(_) | ImplItem::Verbatim(_) => self
                    .violations
                    .push(format!("{source}: opaque associated item")),
                _ => {}
            }
        }
    }

    fn inspect_guarded_method(&mut self, owner: &str, method: &syn::ImplItemFn, source: &str) {
        let name = plain_ident(&method.sig.ident);
        let exact = expected_signature(owner, &name)
            .is_some_and(|expected| signatures_match(&method.sig, &expected));
        if is_raw(&method.sig.ident)
            || !exact
            || method
                .attrs
                .iter()
                .any(|attr| !attr.path().is_ident("doc") && !attr.path().is_ident("must_use"))
        {
            self.violations
                .push(format!("{source}: forbidden visible {owner}::{name}"));
        } else {
            *self.methods.entry((owner.to_owned(), name)).or_default() += 1;
        }
    }

    fn require_complete(&mut self) {
        for name in SENSITIVE {
            if self.declarations.get(*name) != Some(&1) {
                self.violations
                    .push(format!("expected one direct {name} declaration"));
            }
        }
        for (owner, method) in expected_methods() {
            if self.methods.get(&(owner.to_owned(), method.to_owned())) != Some(&1) {
                self.violations
                    .push(format!("expected one exact {owner}::{method}"));
            }
        }
    }
}

fn test_support_only(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attribute| {
        if !attribute.path().is_ident("cfg") {
            return false;
        }
        let mut test = false;
        let mut feature = false;
        let parsed = attribute.parse_nested_meta(|meta| {
            if meta.path.is_ident("any") {
                meta.parse_nested_meta(|nested| {
                    if nested.path.is_ident("test") {
                        test = true;
                    } else if nested.path.is_ident("feature") {
                        let value: syn::LitStr = nested.value()?.parse()?;
                        feature = value.value() == "test-support";
                    }
                    Ok(())
                })?;
            }
            Ok(())
        });
        parsed.is_ok() && test && feature
    })
}

fn signatures_match(actual: &syn::Signature, expected: &syn::Signature) -> bool {
    let mut actual = actual.clone();
    let mut expected = expected.clone();
    actual.inputs.pop_punct();
    expected.inputs.pop_punct();
    actual == expected
}
