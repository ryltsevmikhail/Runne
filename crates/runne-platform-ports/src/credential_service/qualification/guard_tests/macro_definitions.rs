use proc_macro2::TokenStream;
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Block, Item, Stmt, UseTree};

use super::macro_scope;
use super::visitor::{macro_mentions_qualification, named_macro_calls};
use super::{item_attrs, item_is_test_only};

pub(super) struct Index {
    definitions: Vec<Definition>,
    imports: Vec<Import>,
}

struct Definition {
    name: String,
    scope: Vec<String>,
    position: usize,
    tokens: TokenStream,
    relevant: bool,
}

struct Import {
    name: String,
    scope: Vec<String>,
}

pub(super) fn index(items: &[Item]) -> Index {
    let mut index = Index {
        definitions: Vec::new(),
        imports: Vec::new(),
    };
    collect_items(items, &[], &mut index);
    resolve_relevance(&mut index);
    index
}

pub(super) fn is_relevant(
    index: &Index,
    name: &str,
    unqualified: bool,
    context: bool,
    selects_qualification: bool,
    scope: &[String],
    position: usize,
) -> bool {
    if !context {
        return false;
    }
    if selects_qualification || !unqualified {
        return true;
    }
    index.definition_before(name, scope, position).map_or_else(
        || index.has_import(name, scope) || !index.has_definition(name, scope),
        |definition| definition.relevant,
    )
}

impl Index {
    fn definition_before(
        &self,
        name: &str,
        scope: &[String],
        position: usize,
    ) -> Option<&Definition> {
        self.definitions
            .iter()
            .filter(|definition| {
                definition.name == name
                    && definition.position < position
                    && scope.starts_with(&definition.scope)
            })
            .max_by_key(|definition| (definition.scope.len(), definition.position))
    }

    fn has_import(&self, name: &str, scope: &[String]) -> bool {
        self.imports.iter().any(|import| {
            (import.name == name || import.name == "*") && scope.starts_with(&import.scope)
        })
    }

    fn has_definition(&self, name: &str, scope: &[String]) -> bool {
        self.definitions
            .iter()
            .any(|definition| definition.name == name && scope.starts_with(&definition.scope))
    }
}

fn collect_items(items: &[Item], scope: &[String], index: &mut Index) {
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
    match tree {
        UseTree::Rename(rename) => imports.push(Import {
            name: rename.rename.to_string(),
            scope: scope.to_vec(),
        }),
        UseTree::Path(path) => collect_imports(&path.tree, scope, imports),
        UseTree::Group(group) => {
            for tree in &group.items {
                collect_imports(tree, scope, imports);
            }
        }
        UseTree::Name(name) => imports.push(Import {
            name: name.ident.to_string(),
            scope: scope.to_vec(),
        }),
        UseTree::Glob(_) => imports.push(Import {
            name: "*".to_owned(),
            scope: scope.to_vec(),
        }),
    }
}

fn resolve_relevance(index: &mut Index) {
    for definition in &mut index.definitions {
        definition.relevant = macro_mentions_qualification(&definition.tokens);
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
