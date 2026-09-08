use std::path::{Path, PathBuf};

use syn::visit::{self, Visit};

use super::{MacroDefinitions, MacroResolution, ResolvedMacroInvocation, UnresolvedReason};
use crate::guard::inventory_include_aliases::use_aliases;
use crate::guard::inventory_macro_resolution::{MacroAlias, MacroDefinition};
use crate::guard::inventory_macro_rules::macro_arms;
use crate::guard::syntax::is_test_only;

pub(super) fn resolve(
    definitions: &MacroDefinitions,
    parent: &ResolvedMacroInvocation,
    items: &[syn::Item],
    invocation: &syn::Macro,
) -> MacroResolution {
    let Some(parent_definition) = definitions
        .items
        .values()
        .flatten()
        .find(|definition| super::macro_id(definition) == parent.definition)
    else {
        return MacroResolution::Unresolved(UnresolvedReason::MissingDefinition);
    };
    let source = generated_source(parent_definition);
    let mut expanded = definitions.clone();
    crate::guard::inventory_macro_scope::inherit_source_contexts(
        &mut expanded,
        &parent_definition.source,
        &source,
    );
    let Some(site) = collect_generated(
        &source,
        &parent.definition_scope,
        items,
        invocation,
        &mut expanded,
    ) else {
        return MacroResolution::Unresolved(UnresolvedReason::MissingDefinition);
    };
    let Some((target_scope, name)) =
        crate::guard::inventory_macro_scope::macro_path_scope(&site.scope, &invocation.path)
    else {
        return MacroResolution::Unresolved(UnresolvedReason::MissingDefinition);
    };
    let exact = invocation.path.segments.len() > 1;
    match expanded.resolve_semantic_definition(
        &source,
        &target_scope,
        &name,
        site.position,
        exact,
        &mut Vec::new(),
    ) {
        Ok(Some(definition)) => MacroDefinitions::resolve_known_definition(
            definition,
            &invocation.tokens,
            &source,
            &site.scope,
            site.position,
        ),
        Ok(None) => resolve_from_parent(
            definitions,
            parent,
            parent_definition,
            invocation,
            &name,
            exact,
        ),
        Err(reason) => MacroResolution::Unresolved(reason),
    }
}

fn resolve_from_parent(
    definitions: &MacroDefinitions,
    parent: &ResolvedMacroInvocation,
    parent_definition: &MacroDefinition,
    invocation: &syn::Macro,
    name: &str,
    exact: bool,
) -> MacroResolution {
    let definition_rooted = invocation
        .path
        .segments
        .first()
        .is_some_and(|segment| segment.ident == super::DEFINITION_CRATE_MARKER);
    let (source, base_scope, source_position) = if definition_rooted {
        (
            &parent_definition.source,
            parent_definition.scope.as_slice(),
            parent_definition.source_position,
        )
    } else {
        (
            &parent.invocation_source,
            parent.invocation_scope.as_slice(),
            parent.invocation_position,
        )
    };
    let Some((scope, _)) =
        crate::guard::inventory_macro_scope::macro_path_scope(base_scope, &invocation.path)
    else {
        return MacroResolution::Unresolved(UnresolvedReason::MissingDefinition);
    };
    match definitions.resolve_semantic_definition(
        source,
        &scope,
        name,
        source_position,
        exact,
        &mut Vec::new(),
    ) {
        Ok(Some(definition)) => MacroDefinitions::resolve_known_definition(
            definition,
            &invocation.tokens,
            source,
            base_scope,
            source_position,
        ),
        Ok(None) => MacroResolution::Unresolved(UnresolvedReason::MissingDefinition),
        Err(reason) => MacroResolution::Unresolved(reason),
    }
}

struct GeneratedSite {
    scope: Vec<String>,
    position: u32,
}

fn generated_source(definition: &MacroDefinition) -> PathBuf {
    PathBuf::from("/__runne_generated_macro__").join(definition.ordinal.to_string())
}

fn collect_generated(
    source: &Path,
    scope: &[String],
    items: &[syn::Item],
    invocation: &syn::Macro,
    definitions: &mut MacroDefinitions,
) -> Option<GeneratedSite> {
    let mut collector = GeneratedCollector {
        source,
        scope: scope.to_vec(),
        position: 0,
        target: std::ptr::from_ref(invocation),
        site: None,
        definitions,
    };
    for item in items {
        collector.visit_item(item);
    }
    collector.site
}

struct GeneratedCollector<'a> {
    source: &'a Path,
    scope: Vec<String>,
    position: u32,
    target: *const syn::Macro,
    site: Option<GeneratedSite>,
    definitions: &'a mut MacroDefinitions,
}

impl<'ast> Visit<'ast> for GeneratedCollector<'_> {
    fn visit_item_macro(&mut self, node: &'ast syn::ItemMacro) {
        let position = self.next_position();
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
                    exported: false,
                    source_position: position,
                    source: self.source.to_path_buf(),
                    scope: self.scope.clone(),
                    arms: macro_arms(node.mac.tokens.clone()),
                });
        } else {
            self.record_target(&node.mac, position);
        }
    }

    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        let position = self.next_position();
        if !is_test_only(&node.attrs) {
            for alias in use_aliases(&node.tree) {
                self.definitions
                    .aliases
                    .entry(alias.name)
                    .or_default()
                    .push(MacroAlias {
                        source_position: position,
                        source: self.source.to_path_buf(),
                        scope: self.scope.clone(),
                        target: alias.target,
                    });
            }
        }
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let position = self.next_position();
        self.record_target(node, position);
        visit::visit_macro(self, node);
    }

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if !is_test_only(&node.attrs) && node.content.is_some() {
            self.scope.push(node.ident.to_string());
            visit::visit_item_mod(self, node);
            self.scope.pop();
        }
    }
}

impl GeneratedCollector<'_> {
    const fn next_position(&mut self) -> u32 {
        let position = self.position;
        self.position = self
            .position
            .checked_add(1)
            .expect("macro position exceeds u32");
        position
    }

    fn record_target(&mut self, node: &syn::Macro, position: u32) {
        if std::ptr::eq(node, self.target) {
            assert!(self.site.is_none(), "generated macro appears twice");
            self.site = Some(GeneratedSite {
                scope: self.scope.clone(),
                position,
            });
        }
    }
}

#[cfg(test)]
#[path = "generated/tests.rs"]
mod tests;
