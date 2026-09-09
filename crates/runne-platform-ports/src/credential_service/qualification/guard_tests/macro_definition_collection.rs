use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Block, Item, Stmt, UseTree};

use super::super::macro_scope;
use super::super::macro_tokens::{
    macro_attribute_names, macro_contains_import_item, macro_contains_untrusted_nested_call,
    macro_mentions_qualification, macro_mentions_variable_qualification, named_macro_calls,
    qualified_attribute_roots, qualified_macro_roots,
};
use super::super::syntax::normalized_ident;
use super::super::{item_attrs, item_is_test_only};
use super::{Definition, Import, Index};

pub(super) fn all_macro_rule_names(items: &[Item]) -> std::collections::BTreeSet<String> {
    struct Names(std::collections::BTreeSet<String>);
    impl<'ast> Visit<'ast> for Names {
        fn visit_macro(&mut self, mac: &'ast syn::Macro) {
            if mac.path.is_ident("macro_rules")
                && let Some(name) = macro_rules_name(mac)
            {
                self.0.insert(name);
            }
            syn::visit::visit_macro(self, mac);
        }
    }
    let mut names = Names(std::collections::BTreeSet::new());
    for item in items {
        names.visit_item(item);
    }
    names.0
}

pub(super) fn collect_items(items: &[Item], scope: &[String], index: &mut Index) {
    for item in items {
        if item_is_test_only(item_attrs(item)) {
            continue;
        }
        match item {
            Item::Use(item) => collect_imports(&item.tree, scope, &mut index.imports),
            Item::Macro(item) if item.mac.path.is_ident("macro_rules") => {
                if let Some(name) = &item.ident {
                    index.definitions.push(Definition {
                        name: name.to_string(),
                        scope: scope.to_vec(),
                        position: macro_scope::position(item.span()),
                        tokens: item.mac.tokens.clone(),
                        relevant: false,
                        context_relevant: false,
                    });
                }
            }
            Item::Mod(item) => {
                if let Some((_, nested)) = &item.content {
                    let nested_scope =
                        macro_scope::child(scope, &item.ident.to_string(), item.span());
                    collect_items(nested, &nested_scope, index);
                }
            }
            Item::Fn(item) => {
                let function_scope =
                    macro_scope::child(scope, &item.sig.ident.to_string(), item.span());
                collect_block(&item.block, &function_scope, index);
            }
            _ => {}
        }
    }
}

fn collect_block(block: &Block, scope: &[String], index: &mut Index) {
    let owned_scope = macro_scope::child(scope, "block", block.span());
    let scope = owned_scope.as_slice();
    for statement in &block.stmts {
        match statement {
            Stmt::Item(item) => collect_items(std::slice::from_ref(item), scope, index),
            Stmt::Macro(item) if item.mac.path.is_ident("macro_rules") => {
                if let Some(name) = macro_rules_name(&item.mac) {
                    index.definitions.push(Definition {
                        name,
                        scope: scope.to_vec(),
                        position: macro_scope::position(item.span()),
                        tokens: item.mac.tokens.clone(),
                        relevant: false,
                        context_relevant: false,
                    });
                }
            }
            Stmt::Expr(expression, _) => collect_expression_blocks(expression, scope, index),
            Stmt::Local(_) | Stmt::Macro(_) => {}
        }
    }
}

fn macro_rules_name(mac: &syn::Macro) -> Option<String> {
    mac.tokens
        .clone()
        .into_iter()
        .find_map(|token| match token {
            proc_macro2::TokenTree::Ident(name) => Some(name.to_string()),
            _ => None,
        })
}

fn collect_imports(tree: &UseTree, scope: &[String], imports: &mut Vec<Import>) {
    collect_imports_with_root(tree, scope, imports, None);
}

fn collect_imports_with_root(
    tree: &UseTree,
    scope: &[String],
    imports: &mut Vec<Import>,
    root: Option<String>,
) {
    match tree {
        UseTree::Rename(rename) => imports.push(Import {
            name: normalized_ident(&rename.rename),
            root,
            scope: scope.to_vec(),
            glob: false,
        }),
        UseTree::Path(path) => collect_imports_with_root(
            &path.tree,
            scope,
            imports,
            root.or_else(|| Some(normalized_ident(&path.ident))),
        ),
        UseTree::Group(group) => {
            for tree in &group.items {
                collect_imports_with_root(tree, scope, imports, root.clone());
            }
        }
        UseTree::Name(name) => imports.push(Import {
            name: normalized_ident(&name.ident),
            root,
            scope: scope.to_vec(),
            glob: false,
        }),
        UseTree::Glob(_) => imports.push(Import {
            name: "*".to_owned(),
            root,
            scope: scope.to_vec(),
            glob: true,
        }),
    }
}

pub(super) fn resolve_relevance(index: &mut Index) {
    let escape_risks = qualification_escape_risks(index);
    for (definition, (imported_attribute_risk, qualified_root_risk)) in
        index.definitions.iter_mut().zip(escape_risks)
    {
        definition.relevant = macro_mentions_qualification(&definition.tokens)
            || macro_contains_import_item(&definition.tokens)
            || macro_contains_untrusted_nested_call(&definition.tokens)
            || qualified_root_risk
            || imported_attribute_risk;
        definition.context_relevant = macro_mentions_variable_qualification(&definition.tokens);
    }
    loop {
        let previous = index
            .definitions
            .iter()
            .map(|definition| definition.relevant)
            .collect::<Vec<_>>();
        let next = index
            .definitions
            .iter()
            .enumerate()
            .map(|(position, definition)| {
                previous[position]
                    || named_macro_calls(&definition.tokens).iter().any(|name| {
                        let resolved = index
                            .definitions
                            .iter()
                            .enumerate()
                            .filter(|(_, candidate)| {
                                candidate.name == *name
                                    && definition.scope.starts_with(&candidate.scope)
                                    && candidate.position < definition.position
                            })
                            .max_by_key(|(_, candidate)| {
                                (candidate.scope.len(), candidate.position)
                            });
                        resolved.map_or_else(
                            || index.has_import(name, &definition.scope),
                            |(candidate, _)| previous[candidate],
                        )
                    })
            })
            .collect::<Vec<_>>();
        for (definition, relevant) in index.definitions.iter_mut().zip(next) {
            definition.relevant = relevant;
        }
        let context_previous = index
            .definitions
            .iter()
            .map(|definition| definition.context_relevant)
            .collect::<Vec<_>>();
        let context_next = index
            .definitions
            .iter()
            .enumerate()
            .map(|(position, definition)| {
                context_previous[position]
                    || named_macro_calls(&definition.tokens).iter().any(|name| {
                        index
                            .definitions
                            .iter()
                            .enumerate()
                            .any(|(candidate, nested)| {
                                candidate != position
                                    && nested.name == *name
                                    && context_previous[candidate]
                            })
                    })
            })
            .collect::<Vec<_>>();
        for (definition, relevant) in index.definitions.iter_mut().zip(context_next) {
            definition.context_relevant = relevant;
        }
        if previous
            == index
                .definitions
                .iter()
                .map(|definition| definition.relevant)
                .collect::<Vec<_>>()
        {
            return;
        }
    }
}

fn qualification_escape_risks(index: &Index) -> Vec<(bool, bool)> {
    index
        .definitions
        .iter()
        .map(|definition| {
            let imported_attribute = macro_attribute_names(&definition.tokens)
                .iter()
                .any(|name| index.has_untrusted_attribute_import(name, &definition.scope));
            let qualified_root = qualified_macro_roots(&definition.tokens)
                .into_iter()
                .chain(qualified_attribute_roots(&definition.tokens))
                .any(|root| index.root_is_shadowed(&root, &definition.scope));
            (imported_attribute, qualified_root)
        })
        .collect()
}

fn collect_expression_blocks(expression: &syn::Expr, scope: &[String], index: &mut Index) {
    struct Blocks<'a> {
        scope: &'a [String],
        index: &'a mut Index,
    }
    impl<'ast> Visit<'ast> for Blocks<'_> {
        fn visit_block(&mut self, block: &'ast Block) {
            collect_block(block, self.scope, self.index);
        }
    }
    Blocks { scope, index }.visit_expr(expression);
}
