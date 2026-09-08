use std::collections::HashMap;

use syn::visit::{self, Visit};

use super::semantic_index::{NodeAddress, SemanticIndex};
use super::source_model::{ScopeId, SyntaxId};
use super::symbols::{BodySyntax, SyntaxContext};

pub(super) fn register_body_contexts(index: &mut SemanticIndex) {
    let mut syntax = index
        .items
        .iter()
        .map(|item| item.syntax.0)
        .chain(index.bodies.iter().map(|body| body.syntax.0))
        .max()
        .unwrap_or(0)
        + 1;
    let mut scope = index
        .modules
        .iter()
        .map(|module| module.scope.0)
        .max()
        .unwrap_or(0)
        + 1;
    let mut contexts = HashMap::new();
    let mut scope_parents = HashMap::new();
    for body in &index.bodies {
        let mut visitor = ContextCollector {
            syntax: &mut syntax,
            scope: &mut scope,
            current_scope: body.scope,
            contexts: &mut contexts,
            scope_parents: &mut scope_parents,
        };
        match body.syntax_tree.as_ref() {
            BodySyntax::Function { block, .. } => visitor.visit_block(block),
            BodySyntax::Initializer { expression, .. } => visitor.visit_expr(expression),
        }
    }
    index.node_contexts = contexts;
    index.scope_parents = scope_parents;
}

struct ContextCollector<'a> {
    syntax: &'a mut u32,
    scope: &'a mut u32,
    current_scope: ScopeId,
    contexts: &'a mut HashMap<NodeAddress, SyntaxContext>,
    scope_parents: &'a mut HashMap<ScopeId, ScopeId>,
}

impl ContextCollector<'_> {
    fn record<T>(&mut self, kind: u8, node: &T) {
        self.contexts.insert(
            NodeAddress {
                kind,
                address: std::ptr::from_ref(node).addr(),
            },
            SyntaxContext {
                syntax: SyntaxId(*self.syntax),
                scope: self.current_scope,
            },
        );
        *self.syntax += 1;
    }

    fn with_child_scope(&mut self, visit: impl FnOnce(&mut Self)) {
        let parent = self.current_scope;
        let child = ScopeId(*self.scope);
        self.scope_parents.insert(child, parent);
        self.current_scope = child;
        *self.scope += 1;
        visit(self);
        self.current_scope = parent;
    }
}

impl<'ast> Visit<'ast> for ContextCollector<'_> {
    fn visit_block(&mut self, node: &'ast syn::Block) {
        self.with_child_scope(|visitor| {
            visitor.record(1, node);
            visit::visit_block(visitor, node);
        });
    }

    fn visit_stmt(&mut self, node: &'ast syn::Stmt) {
        if stmt_is_production(node) {
            self.record(2, node);
            visit::visit_stmt(self, node);
        }
    }

    fn visit_expr(&mut self, node: &'ast syn::Expr) {
        if super::cfg_projection::is_production(expr_attributes(node)) {
            self.record(3, node);
            visit::visit_expr(self, node);
        }
    }

    fn visit_pat(&mut self, node: &'ast syn::Pat) {
        self.record(4, node);
        visit::visit_pat(self, node);
    }

    fn visit_arm(&mut self, node: &'ast syn::Arm) {
        if super::cfg_projection::is_production(&node.attrs) {
            visit::visit_arm(self, node);
        }
    }

    fn visit_field(&mut self, node: &'ast syn::Field) {
        if super::cfg_projection::is_production(&node.attrs) {
            visit::visit_field(self, node);
        }
    }

    fn visit_variant(&mut self, node: &'ast syn::Variant) {
        if super::cfg_projection::is_production(&node.attrs) {
            visit::visit_variant(self, node);
        }
    }
}

fn stmt_is_production(statement: &syn::Stmt) -> bool {
    match statement {
        syn::Stmt::Local(local) => super::cfg_projection::is_production(&local.attrs),
        syn::Stmt::Item(item) => super::cfg_projection::is_production(item_attributes(item)),
        syn::Stmt::Expr(expression, _) => {
            super::cfg_projection::is_production(expr_attributes(expression))
        }
        syn::Stmt::Macro(node) => super::cfg_projection::is_production(&node.attrs),
    }
}

fn item_attributes(item: &syn::Item) -> &[syn::Attribute] {
    match item {
        syn::Item::Const(item) => &item.attrs,
        syn::Item::Enum(item) => &item.attrs,
        syn::Item::ExternCrate(item) => &item.attrs,
        syn::Item::Fn(item) => &item.attrs,
        syn::Item::ForeignMod(item) => &item.attrs,
        syn::Item::Impl(item) => &item.attrs,
        syn::Item::Macro(item) => &item.attrs,
        syn::Item::Mod(item) => &item.attrs,
        syn::Item::Static(item) => &item.attrs,
        syn::Item::Struct(item) => &item.attrs,
        syn::Item::Trait(item) => &item.attrs,
        syn::Item::TraitAlias(item) => &item.attrs,
        syn::Item::Type(item) => &item.attrs,
        syn::Item::Union(item) => &item.attrs,
        syn::Item::Use(item) => &item.attrs,
        _ => &[],
    }
}

fn expr_attributes(expression: &syn::Expr) -> &[syn::Attribute] {
    match expression {
        syn::Expr::Array(node) => &node.attrs,
        syn::Expr::Assign(node) => &node.attrs,
        syn::Expr::Async(node) => &node.attrs,
        syn::Expr::Await(node) => &node.attrs,
        syn::Expr::Binary(node) => &node.attrs,
        syn::Expr::Block(node) => &node.attrs,
        syn::Expr::Break(node) => &node.attrs,
        syn::Expr::Call(node) => &node.attrs,
        syn::Expr::Cast(node) => &node.attrs,
        syn::Expr::Closure(node) => &node.attrs,
        syn::Expr::Const(node) => &node.attrs,
        syn::Expr::Continue(node) => &node.attrs,
        syn::Expr::Field(node) => &node.attrs,
        syn::Expr::ForLoop(node) => &node.attrs,
        syn::Expr::Group(node) => &node.attrs,
        syn::Expr::If(node) => &node.attrs,
        syn::Expr::Index(node) => &node.attrs,
        syn::Expr::Infer(node) => &node.attrs,
        syn::Expr::Let(node) => &node.attrs,
        syn::Expr::Lit(node) => &node.attrs,
        syn::Expr::Loop(node) => &node.attrs,
        syn::Expr::Macro(node) => &node.attrs,
        syn::Expr::Match(node) => &node.attrs,
        syn::Expr::MethodCall(node) => &node.attrs,
        syn::Expr::Paren(node) => &node.attrs,
        syn::Expr::Path(node) => &node.attrs,
        syn::Expr::Range(node) => &node.attrs,
        syn::Expr::RawAddr(node) => &node.attrs,
        syn::Expr::Reference(node) => &node.attrs,
        syn::Expr::Repeat(node) => &node.attrs,
        syn::Expr::Return(node) => &node.attrs,
        syn::Expr::Struct(node) => &node.attrs,
        syn::Expr::Try(node) => &node.attrs,
        syn::Expr::TryBlock(node) => &node.attrs,
        syn::Expr::Tuple(node) => &node.attrs,
        syn::Expr::Unary(node) => &node.attrs,
        syn::Expr::Unsafe(node) => &node.attrs,
        syn::Expr::While(node) => &node.attrs,
        syn::Expr::Yield(node) => &node.attrs,
        _ => &[],
    }
}
