use std::path::Path;

use super::source_edge_macros::{MacroDefinitions, ResolvedSourceEdge};
use super::source_edge_paths::{
    is_builtin_include, is_builtin_source_free, module_directory, module_path,
};
use super::source_model::{
    OpaqueSourceMacro, SourceEdgeKind, SourceEdgeRecord, SourceOrigin, SyntaxId,
};
use super::syntax::{expr_is_test_only, is_test_only};
use syn::visit::{self, Visit};
use syn::{Expr, LitStr};

#[path = "source_edges/collection.rs"]
mod collection;
#[path = "source_edges/validation.rs"]
mod validation;

pub(super) use collection::{source_edge_collection, source_edge_records};
pub(super) use validation::{source_edges, validate_source_edges};

macro_rules! visit_non_test_items {
    ($($method:ident: $item:ty => $delegate:ident),* $(,)?) => {
        $(fn $method(&mut self, node: &'ast $item) {
            if !is_test_only(&node.attrs) { visit::$delegate(self, node); }
        })*
    };
}

struct SourceEdgeCollector<'a> {
    source: &'a Path,
    definitions: &'a MacroDefinitions,
    scope: Vec<String>,
    site_ordinal: u32,
    macro_position: u32,
    edges: &'a mut Vec<SourceEdgeRecord>,
    opaque_source_macros: &'a mut Vec<OpaqueSourceMacro>,
}

impl SourceEdgeCollector<'_> {
    fn add_target(
        &mut self,
        target: &Path,
        edge: &str,
        kind: SourceEdgeKind,
        origin: SourceOrigin,
    ) {
        let metadata = std::fs::symlink_metadata(target).unwrap_or_else(|error| {
            panic!("cannot inspect {edge} target {}: {error}", target.display())
        });
        assert!(
            !metadata.file_type().is_symlink(),
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
        self.edges.push(SourceEdgeRecord {
            from: self.source.to_path_buf(),
            from_module_scope: self.scope.clone(),
            target: canonical,
            kind,
            origin,
        });
        self.site_ordinal += 1;
    }

    fn add_literal(&mut self, literal: &str, edge: &str, origin: SourceOrigin) {
        let target = self
            .source
            .parent()
            .unwrap_or_else(|| panic!("source has no parent: {}", self.source.display()))
            .join(literal);
        self.add_target(
            &target,
            edge,
            SourceEdgeKind::Include {
                expansion_site: SyntaxId(self.site_ordinal),
            },
            origin,
        );
    }

    fn add_resolved_edges(&mut self, edges: Vec<ResolvedSourceEdge>, origin: SourceOrigin) {
        for edge in edges {
            match edge {
                ResolvedSourceEdge::Include(path) => {
                    self.add_literal(&path, "macro include edge", origin);
                }
                ResolvedSourceEdge::Module { name, path } => self.add_module(&name, path, origin),
            }
        }
    }

    fn add_module(&mut self, name: &str, explicit_path: Option<String>, origin: SourceOrigin) {
        let parent = self.source.parent().expect("source has no parent");
        let candidates = if let Some(path) = explicit_path {
            vec![parent.join(path)]
        } else {
            let nested = module_directory(self.source);
            let primary = [
                nested.join(format!("{name}.rs")),
                nested.join(name).join("mod.rs"),
            ];
            if primary.iter().any(|path| path.is_file()) {
                primary.to_vec()
            } else {
                vec![
                    parent.join(format!("{name}.rs")),
                    parent.join(name).join("mod.rs"),
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
            name
        );
        self.add_target(
            existing[0],
            "module edge",
            SourceEdgeKind::Module {
                declared_name: name.to_owned(),
            },
            origin,
        );
    }

    fn validate_module(&mut self, node: &syn::ItemMod) {
        if node.content.is_none() && !is_test_only(&node.attrs) {
            self.add_module(
                &node.ident.to_string(),
                module_path(&node.attrs),
                SourceOrigin::RustModule,
            );
        }
    }

    fn visit_source_macro(&mut self, node: &syn::Macro, item_position: bool, source_position: u32) {
        match self.definitions.resolve(
            self.source,
            &self.scope,
            &node.path,
            &node.tokens,
            source_position,
        ) {
            Ok(Some(edges)) => self.add_resolved_edges(edges, SourceOrigin::ResolvedInclude),
            Ok(None) if is_builtin_include(&node.path) => {
                match syn::parse2::<LitStr>(node.tokens.clone()) {
                    Ok(literal) => self.add_literal(
                        &literal.value(),
                        "include edge",
                        SourceOrigin::ResolvedInclude,
                    ),
                    Err(_) => self.record_opaque_source_macro(node),
                }
            }
            Ok(None) => match self.definitions.nested_edges(
                self.source,
                &self.scope,
                node.tokens.clone(),
                source_position,
            ) {
                Ok(edges) => {
                    self.add_resolved_edges(edges, SourceOrigin::OpaqueMacroInclude);
                    if item_position && !is_builtin_source_free(&node.path) {
                        self.record_opaque_source_macro(node);
                    }
                }
                Err(_) => self.record_opaque_source_macro(node),
            },
            Err(_) => self.record_opaque_source_macro(node),
        }
    }

    fn record_opaque_source_macro(&mut self, node: &syn::Macro) {
        self.opaque_source_macros.push(OpaqueSourceMacro {
            from: self.source.to_path_buf(),
            macro_path: node
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect::<Vec<_>>()
                .join("::"),
        });
    }

    const fn next_macro_position(&mut self) -> u32 {
        let current = self.macro_position;
        self.macro_position = self
            .macro_position
            .checked_add(1)
            .expect("macro source position exceeds u32");
        current
    }
}

impl<'ast> Visit<'ast> for SourceEdgeCollector<'_> {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if !is_test_only(&node.attrs) {
            self.validate_module(node);
            if node.content.is_some() {
                self.scope.push(node.ident.to_string());
            }
            visit::visit_item_mod(self, node);
            if node.content.is_some() {
                self.scope.pop();
            }
        }
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let source_position = self.next_macro_position();
        self.visit_source_macro(node, false, source_position);
        visit::visit_macro(self, node);
    }

    fn visit_item_macro(&mut self, node: &'ast syn::ItemMacro) {
        let source_position = self.next_macro_position();
        if is_test_only(&node.attrs) {
            return;
        }
        if node.ident.is_none() {
            self.visit_source_macro(&node.mac, true, source_position);
        }
    }

    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        self.next_macro_position();
        visit::visit_item_use(self, node);
    }

    fn visit_expr(&mut self, node: &'ast Expr) {
        if !expr_is_test_only(node) {
            visit::visit_expr(self, node);
        }
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        if !is_test_only(&node.attrs) {
            visit::visit_local(self, node);
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
