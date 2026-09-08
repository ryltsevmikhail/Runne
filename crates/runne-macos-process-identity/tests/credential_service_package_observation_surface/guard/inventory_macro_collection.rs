use std::path::Path;

use super::inventory_include_aliases::use_aliases;
use super::inventory_macro_resolution::{
    MacroAlias, MacroDefinition, MacroDefinitions, MacroInvocation,
};
use super::inventory_macro_rules::macro_arms;
use super::syntax::is_test_only;
use syn::visit::{self, Visit};

pub(super) fn collect(path: &Path, source: &str, definitions: &mut MacroDefinitions) {
    DefinitionCollector {
        source: path,
        scope: Vec::new(),
        source_position: 0,
        definitions,
    }
    .visit_file(&super::syntax::parse_source(source));
}

pub(super) fn invocation_position(
    definitions: &MacroDefinitions,
    source: &Path,
    scope: &[String],
    path: &syn::Path,
    tokens: &proc_macro2::TokenStream,
) -> Option<u32> {
    let path = path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>();
    let tokens = tokens.to_string();
    let matches = definitions
        .invocations
        .iter()
        .filter(|site| {
            site.source == source
                && scope.ends_with(&site.scope)
                && site.path == path
                && site.tokens == tokens
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [site] => Some(site.source_position),
        _ => None,
    }
}

struct DefinitionCollector<'a> {
    source: &'a Path,
    scope: Vec<String>,
    source_position: u32,
    definitions: &'a mut MacroDefinitions,
}

impl<'ast> Visit<'ast> for DefinitionCollector<'_> {
    fn visit_expr(&mut self, node: &'ast syn::Expr) {
        if !super::syntax::expr_is_test_only(node) {
            visit::visit_expr(self, node);
        }
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        if !is_test_only(&node.attrs) {
            visit::visit_local(self, node);
        }
    }

    fn visit_stmt_macro(&mut self, node: &'ast syn::StmtMacro) {
        let source_position = self.next_position();
        if !is_test_only(&node.attrs) {
            self.record_invocation(&node.mac, source_position);
        }
    }

    fn visit_item_macro(&mut self, node: &'ast syn::ItemMacro) {
        let source_position = self.next_position();
        if !is_test_only(&node.attrs)
            && let Some(name) = &node.ident
        {
            let ordinal =
                u32::try_from(self.definitions.items.values().map(Vec::len).sum::<usize>())
                    .expect("macro definition count exceeds u32");
            self.definitions
                .items
                .entry(name.to_string())
                .or_default()
                .push(MacroDefinition {
                    ordinal,
                    exported: node
                        .attrs
                        .iter()
                        .any(|attribute| attribute.path().is_ident("macro_export")),
                    source_position,
                    source: self.source.to_path_buf(),
                    scope: self.scope.clone(),
                    arms: macro_arms(node.mac.tokens.clone()),
                });
        } else if !is_test_only(&node.attrs) {
            self.record_invocation(&node.mac, source_position);
        }
    }

    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        let source_position = self.next_position();
        if !is_test_only(&node.attrs) {
            for alias in use_aliases(&node.tree) {
                self.definitions
                    .aliases
                    .entry(alias.name)
                    .or_default()
                    .push(MacroAlias {
                        source_position,
                        source: self.source.to_path_buf(),
                        scope: self.scope.clone(),
                        target: alias.target,
                    });
            }
        }
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let source_position = self.next_position();
        self.record_invocation(node, source_position);
        visit::visit_macro(self, node);
    }

    fn visit_pat(&mut self, node: &'ast syn::Pat) {
        if let syn::Pat::Macro(pattern) = node {
            let source_position = self.next_position();
            self.record_invocation(&pattern.mac, source_position);
            return;
        }
        visit::visit_pat(self, node);
    }

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if !is_test_only(&node.attrs) && node.content.is_some() {
            self.scope.push(node.ident.to_string());
            visit::visit_item_mod(self, node);
            self.scope.pop();
        }
    }
}

impl DefinitionCollector<'_> {
    const fn next_position(&mut self) -> u32 {
        let current = self.source_position;
        self.source_position = self
            .source_position
            .checked_add(1)
            .expect("macro source position exceeds u32");
        current
    }

    fn record_invocation(&mut self, node: &syn::Macro, source_position: u32) {
        self.definitions.invocations.push(MacroInvocation {
            source: self.source.to_path_buf(),
            scope: self.scope.clone(),
            path: node
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect(),
            tokens: node.tokens.to_string(),
            source_position,
        });
    }
}
