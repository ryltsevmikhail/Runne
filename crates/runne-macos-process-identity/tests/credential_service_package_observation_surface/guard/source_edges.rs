use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use super::source_edge_macros::{
    IncludeTemplate, MacroDefinitions, include_templates, include_token_present,
};
use super::syntax::{is_test_only, parse_source};
use syn::visit::{self, Visit};
use syn::{Attribute, Expr, ExprLit, Lit, LitStr, Meta};

macro_rules! visit_non_test_items {
    ($($method:ident: $item:ty => $delegate:ident),* $(,)?) => {
        $(fn $method(&mut self, node: &'ast $item) {
            if !is_test_only(&node.attrs) { visit::$delegate(self, node); }
        })*
    };
}

pub(super) fn validate_source_edges(path: &Path, source: &str, inventory: &HashSet<PathBuf>) {
    for target in source_edges(path, source) {
        assert!(
            inventory.contains(&target),
            "source edge escaped production inventory: {}",
            target.display()
        );
    }
}

pub(super) fn source_edges(path: &Path, source: &str) -> Vec<PathBuf> {
    let file = parse_source(source);
    let mut definitions = MacroDefinitions::default();
    definitions.visit_file(&file);
    let mut edges = Vec::new();
    SourceEdgeCollector {
        source: path,
        definitions: &definitions.items,
        edges: &mut edges,
    }
    .visit_file(&file);
    edges
}

struct SourceEdgeCollector<'a> {
    source: &'a Path,
    definitions: &'a HashMap<String, Vec<IncludeTemplate>>,
    edges: &'a mut Vec<PathBuf>,
}

impl SourceEdgeCollector<'_> {
    fn add_target(&mut self, target: &Path, edge: &str) {
        let kind = std::fs::symlink_metadata(target).unwrap_or_else(|error| {
            panic!("cannot inspect {edge} target {}: {error}", target.display())
        });
        assert!(
            !kind.file_type().is_symlink(),
            "symlink {edge} is unsupported: {}",
            target.display()
        );
        assert!(
            target
                .extension()
                .is_some_and(|ext| ext == "rs" || ext == "inc"),
            "unsupported {edge} from {}: {}",
            self.source.display(),
            target.display()
        );
        let canonical = std::fs::canonicalize(target).unwrap_or_else(|error| {
            panic!(
                "cannot resolve {edge} from {} to {}: {error}",
                self.source.display(),
                target.display()
            )
        });
        self.edges.push(canonical);
    }

    fn add_literal(&mut self, literal: &str, edge: &str) {
        let target = self
            .source
            .parent()
            .unwrap_or_else(|| panic!("source has no parent: {}", self.source.display()))
            .join(literal);
        self.add_target(&target, edge);
    }

    fn add_templates(&mut self, templates: &[IncludeTemplate], tokens: &proc_macro2::TokenStream) {
        for template in templates {
            match template {
                IncludeTemplate::Literal(path) => self.add_literal(path, "macro include edge"),
                IncludeTemplate::Forwarded => {
                    let literal = syn::parse2::<LitStr>(tokens.clone()).unwrap_or_else(|error| {
                        panic!("unsupported forwarded include argument: {error}")
                    });
                    self.add_literal(&literal.value(), "macro include edge");
                }
            }
        }
    }

    fn validate_module(&mut self, node: &syn::ItemMod) {
        if node.content.is_some() || is_test_only(&node.attrs) {
            return;
        }
        let parent = self.source.parent().expect("source has no parent");
        let candidates = if let Some(path) = module_path(&node.attrs) {
            vec![parent.join(path)]
        } else {
            let nested = module_directory(self.source);
            let primary = [
                nested.join(format!("{}.rs", node.ident)),
                nested.join(node.ident.to_string()).join("mod.rs"),
            ];
            if primary.iter().any(|path| path.is_file()) {
                primary.to_vec()
            } else {
                vec![
                    parent.join(format!("{}.rs", node.ident)),
                    parent.join(node.ident.to_string()).join("mod.rs"),
                ]
            }
        };
        let existing = candidates
            .iter()
            .filter(|path| path.is_file())
            .collect::<Vec<_>>();
        assert_eq!(
            existing.len(),
            1,
            "unresolved or ambiguous module source from {}: {}",
            self.source.display(),
            node.ident
        );
        self.add_target(existing[0], "module edge");
    }
}

fn module_directory(source: &Path) -> PathBuf {
    let parent = source.parent().expect("source has no parent");
    if source
        .extension()
        .is_some_and(|extension| extension == "inc")
    {
        return parent.to_path_buf();
    }
    match source.file_stem().and_then(|stem| stem.to_str()) {
        Some("mod" | "lib" | "main" | "build") => parent.to_path_buf(),
        _ => parent.join(source.file_stem().expect("source has no stem")),
    }
}

fn module_path(attributes: &[Attribute]) -> Option<String> {
    let mut result = None;
    for attribute in attributes {
        if attribute.path().is_ident("path") {
            let Meta::NameValue(value) = &attribute.meta else {
                panic!("unsupported path attribute")
            };
            let Expr::Lit(ExprLit {
                lit: Lit::Str(path),
                ..
            }) = &value.value
            else {
                panic!("unsupported path attribute")
            };
            assert!(result.is_none(), "multiple path attributes are unsupported");
            result = Some(path.value());
        } else if attribute
            .path()
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "path")
        {
            panic!("unsupported qualified path attribute")
        } else if attribute.path().is_ident("cfg_attr")
            && matches!(&attribute.meta, Meta::List(list) if list.tokens.to_string().contains("path"))
        {
            panic!("unsupported conditional path attribute")
        }
    }
    result
}

impl<'ast> Visit<'ast> for SourceEdgeCollector<'_> {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if !is_test_only(&node.attrs) {
            self.validate_module(node);
            visit::visit_item_mod(self, node);
        }
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let name = node
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string());
        if name.as_deref() == Some("include") {
            let literal = syn::parse2::<LitStr>(node.tokens.clone())
                .unwrap_or_else(|error| panic!("unsupported include argument: {error}"));
            self.add_literal(&literal.value(), "include edge");
        } else if let Some(templates) = name.as_deref().and_then(|name| self.definitions.get(name))
        {
            self.add_templates(templates, &node.tokens);
        } else if include_token_present(node.tokens.clone()) {
            panic!("unsupported macro-wrapped include edge")
        }
        visit::visit_macro(self, node);
    }

    fn visit_item_macro(&mut self, node: &'ast syn::ItemMacro) {
        if is_test_only(&node.attrs) {
            return;
        }
        if node.mac.path.is_ident("include") {
            let literal = syn::parse2::<LitStr>(node.mac.tokens.clone())
                .unwrap_or_else(|error| panic!("unsupported include argument: {error}"));
            self.add_literal(&literal.value(), "include edge");
        } else if node.ident.is_some() {
            for template in include_templates(node.mac.tokens.clone()) {
                if let IncludeTemplate::Literal(path) = template {
                    self.add_literal(&path, "macro include edge");
                }
            }
        } else if let Some(templates) = node
            .mac
            .path
            .segments
            .last()
            .and_then(|name| self.definitions.get(&name.ident.to_string()))
        {
            self.add_templates(templates, &node.mac.tokens);
        } else if include_token_present(node.mac.tokens.clone()) {
            panic!("unsupported macro-wrapped include edge")
        }
    }

    visit_non_test_items! {
        visit_impl_item_const: syn::ImplItemConst => visit_impl_item_const,
        visit_impl_item_fn: syn::ImplItemFn => visit_impl_item_fn,
        visit_impl_item_macro: syn::ImplItemMacro => visit_impl_item_macro,
        visit_impl_item_type: syn::ImplItemType => visit_impl_item_type,
        visit_item_const: syn::ItemConst => visit_item_const,
        visit_item_enum: syn::ItemEnum => visit_item_enum,
        visit_item_fn: syn::ItemFn => visit_item_fn,
        visit_item_impl: syn::ItemImpl => visit_item_impl,
        visit_item_static: syn::ItemStatic => visit_item_static,
        visit_item_struct: syn::ItemStruct => visit_item_struct,
        visit_item_trait: syn::ItemTrait => visit_item_trait,
        visit_item_union: syn::ItemUnion => visit_item_union,
        visit_trait_item_const: syn::TraitItemConst => visit_trait_item_const,
        visit_trait_item_fn: syn::TraitItemFn => visit_trait_item_fn,
        visit_trait_item_macro: syn::TraitItemMacro => visit_trait_item_macro,
        visit_trait_item_type: syn::TraitItemType => visit_trait_item_type,
    }
}
