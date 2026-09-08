use std::collections::BTreeSet;

use proc_macro2::{TokenStream, TokenTree};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use super::macro_scope;
use super::metadata;
use super::syntax::{
    arm_is_test_only, expr_is_test_only, impl_item_is_test_only, stmt_is_test_only,
    trait_item_is_test_only,
};
use super::visitor_types::{collect_pattern_names, type_mentions_names, unwrap_receiver};

pub(super) enum Call {
    Method {
        from_qualification_body: bool,
        qualification_context: bool,
    },
    Macro {
        name: String,
        unqualified: bool,
        qualification_context: bool,
        selects_qualification: bool,
        scope: Vec<String>,
        position: usize,
    },
    Path {
        qualifier: Option<String>,
        subject: Option<String>,
        qself: bool,
        qualification_context: bool,
    },
}

pub(super) struct CallVisitor {
    pub(super) calls: Vec<Call>,
    from_qualification_body: bool,
    qualification_context: bool,
    qualification_names: BTreeSet<String>,
    qualification_receivers: BTreeSet<String>,
    scope: Vec<String>,
}

impl CallVisitor {
    pub(super) fn new() -> Self {
        Self {
            calls: Vec::new(),
            from_qualification_body: false,
            qualification_context: false,
            qualification_names: BTreeSet::new(),
            qualification_receivers: BTreeSet::new(),
            scope: Vec::new(),
        }
    }

    pub(super) fn qualification_body() -> Self {
        Self {
            calls: Vec::new(),
            from_qualification_body: true,
            qualification_context: true,
            qualification_names: BTreeSet::new(),
            qualification_receivers: BTreeSet::new(),
            scope: Vec::new(),
        }
    }

    pub(super) fn qualification_context() -> Self {
        Self {
            calls: Vec::new(),
            from_qualification_body: false,
            qualification_context: true,
            qualification_names: BTreeSet::new(),
            qualification_receivers: BTreeSet::new(),
            scope: Vec::new(),
        }
    }

    pub(super) fn for_function(
        names: &BTreeSet<String>,
        qualification_context: bool,
        scope: Vec<String>,
    ) -> Self {
        Self {
            calls: Vec::new(),
            from_qualification_body: false,
            qualification_context,
            qualification_names: names.clone(),
            qualification_receivers: BTreeSet::new(),
            scope,
        }
    }

    pub(super) fn seed_typed_receivers(&mut self, block: &syn::Block) {
        struct Locals<'a> {
            names: &'a BTreeSet<String>,
            receivers: &'a mut BTreeSet<String>,
        }
        impl<'ast> Visit<'ast> for Locals<'_> {
            fn visit_local(&mut self, local: &'ast syn::Local) {
                if let syn::Pat::Type(typed) = &local.pat
                    && type_mentions_names(&typed.ty, self.names)
                {
                    collect_pattern_names(&typed.pat, self.receivers);
                }
                visit::visit_local(self, local);
            }
        }
        Locals {
            names: &self.qualification_names,
            receivers: &mut self.qualification_receivers,
        }
        .visit_block(block);
    }
}

impl<'ast> Visit<'ast> for CallVisitor {
    fn visit_stmt(&mut self, statement: &'ast syn::Stmt) {
        if let syn::Stmt::Local(local) = statement
            && let syn::Pat::Type(typed) = &local.pat
            && type_mentions_names(&typed.ty, &self.qualification_names)
        {
            collect_pattern_names(&typed.pat, &mut self.qualification_receivers);
        }
        if !stmt_is_test_only(statement) && !is_macro_rules_definition(statement) {
            visit::visit_stmt(self, statement);
        }
    }

    fn visit_expr(&mut self, expression: &'ast syn::Expr) {
        if !expr_is_test_only(expression) {
            visit::visit_expr(self, expression);
        }
    }

    fn visit_arm(&mut self, arm: &'ast syn::Arm) {
        if !arm_is_test_only(arm) {
            visit::visit_arm(self, arm);
        }
    }

    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        if !trait_item_is_test_only(item) {
            visit::visit_trait_item(self, item);
        }
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        if !impl_item_is_test_only(item) {
            visit::visit_impl_item(self, item);
        }
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.calls.push(Call::Macro {
            name: mac
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string())
                .unwrap_or_default(),
            unqualified: mac.path.segments.len() == 1,
            qualification_context: self.qualification_context
                || macro_mentions_names(&mac.tokens, &self.qualification_receivers),
            selects_qualification: macro_mentions_qualification(&mac.tokens),
            scope: self.scope.clone(),
            position: macro_scope::position(mac.span()),
        });
        visit::visit_macro(self, mac);
    }

    fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
        if expression.method == "qualify" {
            let receiver_is_qualification = match unwrap_receiver(expression.receiver.as_ref()) {
                syn::Expr::Path(path) => path
                    .path
                    .get_ident()
                    .is_some_and(|name| self.qualification_receivers.contains(&name.to_string())),
                _ => false,
            };
            self.calls.push(Call::Method {
                from_qualification_body: self.from_qualification_body,
                qualification_context: self.qualification_context || receiver_is_qualification,
            });
        }
        visit::visit_expr_method_call(self, expression);
    }

    fn visit_expr_path(&mut self, expression: &'ast syn::ExprPath) {
        let mut segments = expression.path.segments.iter().rev();
        let Some(method) = segments.next() else {
            return;
        };
        if method.ident == "qualify" || expression.qself.is_some() {
            self.calls.push(Call::Path {
                qualifier: segments.next().map(|segment| segment.ident.to_string()),
                subject: expression
                    .qself
                    .as_ref()
                    .and_then(|qself| metadata::type_name(&qself.ty)),
                qself: expression.qself.is_some(),
                qualification_context: self.qualification_context,
            });
        }
        visit::visit_expr_path(self, expression);
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if let syn::Pat::Type(typed) = &local.pat
            && type_mentions_names(&typed.ty, &self.qualification_names)
        {
            collect_pattern_names(&typed.pat, &mut self.qualification_receivers);
        }
        visit::visit_local(self, local);
    }

    fn visit_expr_closure(&mut self, closure: &'ast syn::ExprClosure) {
        let saved = self.qualification_receivers.clone();
        for input in &closure.inputs {
            if let syn::Pat::Type(typed) = input
                && type_mentions_names(&typed.ty, &self.qualification_names)
            {
                collect_pattern_names(&typed.pat, &mut self.qualification_receivers);
            }
        }
        self.visit_expr(&closure.body);
        self.qualification_receivers = saved;
    }

    fn visit_block(&mut self, block: &'ast syn::Block) {
        let saved = self.scope.clone();
        self.scope = macro_scope::child(&saved, "block", block.span());
        visit::visit_block(self, block);
        self.scope = saved;
    }
}

fn is_macro_rules_definition(statement: &syn::Stmt) -> bool {
    match statement {
        syn::Stmt::Macro(macro_) => macro_.mac.path.is_ident("macro_rules"),
        syn::Stmt::Item(syn::Item::Macro(macro_)) => macro_.mac.path.is_ident("macro_rules"),
        _ => false,
    }
}

pub(super) fn macro_mentions_qualification(tokens: &TokenStream) -> bool {
    macro_mentions_names(tokens, &BTreeSet::from(["qualify".to_owned()]))
}

pub(super) fn macro_mentions_names(tokens: &TokenStream, names: &BTreeSet<String>) -> bool {
    let tokens = tokens.clone().into_iter().collect::<Vec<_>>();
    tokens.iter().enumerate().any(|(index, token)| match token {
        TokenTree::Ident(identifier) => {
            names.contains(&identifier.to_string())
                && !matches!(
                    index.checked_sub(1).and_then(|previous| tokens.get(previous)),
                    Some(TokenTree::Punct(punctuation)) if punctuation.as_char() == '$'
                )
        }
        TokenTree::Group(group) => macro_mentions_names(&group.stream(), names),
        _ => false,
    })
}

pub(super) fn named_macro_calls(tokens: &TokenStream) -> BTreeSet<String> {
    let tokens = tokens.clone().into_iter().collect::<Vec<_>>();
    let mut calls = BTreeSet::new();
    for pair in tokens.windows(2) {
        if let [TokenTree::Ident(name), TokenTree::Punct(punctuation)] = pair
            && punctuation.as_char() == '!'
        {
            calls.insert(name.to_string());
        }
    }
    for token in tokens {
        if let TokenTree::Group(group) = token {
            calls.extend(named_macro_calls(&group.stream()));
        }
    }
    calls
}
