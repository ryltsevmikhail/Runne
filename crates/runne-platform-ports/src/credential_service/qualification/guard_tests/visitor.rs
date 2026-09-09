use std::collections::BTreeSet;

use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use super::macro_scope;
use super::macro_tokens::{
    macro_contains_opaque_expansion, macro_contains_untrusted_nested_call, macro_mentions_carrier,
    macro_mentions_names, payload_contains_import_escape,
};
use super::macro_trust;
use super::metadata;
use super::syntax::{
    arm_is_test_only, expr_is_test_only, impl_item_is_test_only, normalized_ident,
    stmt_is_test_only, trait_item_is_test_only,
};
use super::visitor_types::{
    collect_pattern_names, expression_constructs_named_type, is_macro_rules_definition,
    type_mentions_names, unwrap_receiver,
};

pub(super) use super::visitor_state::{Call, CallVisitor, MacroDisposition};

impl<'ast> Visit<'ast> for CallVisitor {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        if super::item_is_test_only(super::item_attrs(item)) {
            return;
        }
        if self.collect_nested_items {
            super::attributes::collect_opaque_attribute(
                super::item_attrs(item),
                super::attributes::AttributeTarget::Other,
                &mut self.calls,
            );
        }
        visit::visit_item(self, item);
    }

    fn visit_stmt(&mut self, statement: &'ast syn::Stmt) {
        if stmt_is_test_only(statement) {
            return;
        }
        if let syn::Stmt::Local(local) = statement
            && let syn::Pat::Type(typed) = &local.pat
            && type_mentions_names(&typed.ty, &self.qualification_names)
        {
            collect_pattern_names(&typed.pat, &mut self.qualification_receivers);
        }
        if is_macro_rules_definition(statement) {
            if let syn::Stmt::Item(item) = statement {
                super::attributes::collect_opaque_attribute(
                    super::item_attrs(item),
                    super::attributes::AttributeTarget::Other,
                    &mut self.calls,
                );
            }
            return;
        }
        visit::visit_stmt(self, statement);
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
            super::attributes::collect_opaque_attribute(
                super::attributes::trait_item_attrs(item),
                super::attributes::AttributeTarget::Other,
                &mut self.calls,
            );
            visit::visit_trait_item(self, item);
        }
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        if !impl_item_is_test_only(item) {
            super::attributes::collect_opaque_attribute(
                super::attributes::impl_item_attrs(item),
                super::attributes::AttributeTarget::Other,
                &mut self.calls,
            );
            visit::visit_impl_item(self, item);
        }
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let name = mac
            .path
            .segments
            .last()
            .map(|segment| normalized_ident(&segment.ident))
            .unwrap_or_default();
        let unambiguous_types = self
            .qualification_names
            .difference(&self.unrelated_type_names)
            .cloned()
            .collect();
        let qualification_context = self.qualification_context
            || macro_mentions_names(&mac.tokens, &self.qualification_receivers)
            || macro_mentions_names(&mac.tokens, &unambiguous_types);
        let unrelated_context =
            !qualification_context && macro_mentions_names(&mac.tokens, &self.unrelated_type_names);
        let trusted_path = macro_trust::trusted_external_path(&mac.path);
        let trusted_outer =
            trusted_path.is_some() || macro_trust::trusted_bare_root(&name).is_some();
        let payload_is_opaque = macro_contains_opaque_expansion(&mac.tokens)
            || payload_contains_import_escape(&mac.tokens);
        let payload_carrier = macro_mentions_carrier(&mac.tokens);
        let builtin_spelling = super::macro_definitions::is_compiler_builtin_macro(&name);
        let disposition = if (payload_carrier && !builtin_spelling)
            || (trusted_outer && macro_contains_untrusted_nested_call(&mac.tokens))
            || (!trusted_outer && payload_is_opaque)
        {
            MacroDisposition::Direct
        } else if unrelated_context
            || (name == "stringify"
                && matches!(
                    trusted_path.as_deref(),
                    Some("core::stringify" | "std::stringify")
                ))
        {
            MacroDisposition::Unrelated
        } else if mac.path.segments.len() > 1 && trusted_path.is_none() {
            MacroDisposition::OpaqueExternal
        } else if !builtin_spelling
            && macro_mentions_names(&mac.tokens, &BTreeSet::from(["qualify".to_owned()]))
        {
            MacroDisposition::Direct
        } else if qualification_context && mac.path.segments.len() == 1 {
            MacroDisposition::ResolveContext
        } else if qualification_context {
            MacroDisposition::Direct
        } else if mac.path.segments.len() == 1 {
            MacroDisposition::ResolveLocal
        } else {
            MacroDisposition::Unrelated
        };
        self.calls.push(Call::Macro {
            name,
            trusted_path,
            disposition,
            scope: self.scope.clone(),
            position: macro_scope::position(mac.span()),
            payload: Some(mac.tokens.clone()),
        });
        visit::visit_macro(self, mac);
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if super::item_is_test_only(&item.attrs) {
            return;
        }
        let scope = macro_scope::child(&self.scope, &item.sig.ident.to_string(), item.span());
        let qualification_context = super::call_provenance::signature_mentions(
            &item.sig,
            &self.qualification_names,
            &self.qualified_names,
        );
        let mut nested = Self::for_function(
            &self.qualification_names,
            &self.qualified_names,
            qualification_context,
            scope,
            &BTreeSet::new(),
            &self.unrelated_type_names,
        );
        nested.seed_signature_receivers(&item.sig);
        nested.seed_typed_receivers(&item.block);
        visit::visit_block(&mut nested, &item.block);
        self.calls.extend(nested.calls);
    }

    fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
        if normalized_ident(&expression.method) == "qualify" {
            let receiver = unwrap_receiver(expression.receiver.as_ref());
            let receiver_is_qualification = receiver_root_ident(receiver).map_or_else(
                || {
                    expression_constructs_named_type(receiver, &self.qualification_names)
                        || !matches!(receiver, syn::Expr::Lit(_))
                },
                |name| {
                    self.qualification_receivers.contains(&name)
                        || !self.unrelated_receivers.contains(&name)
                },
            );
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
        if normalized_ident(&method.ident) == "qualify" || expression.qself.is_some() {
            self.calls.push(Call::Path {
                qualifier: segments
                    .next()
                    .map(|segment| normalized_ident(&segment.ident)),
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
        let typed_qualification = matches!(&local.pat, syn::Pat::Type(typed) if
        super::call_provenance::type_mentions_qualification(
            &typed.ty,
            &self.qualification_names,
            &self.qualified_names,
        ));
        let inferred_qualification = local.init.as_ref().is_some_and(|initializer| {
            super::call_provenance::expression_mentions_qualification_type(
                &initializer.expr,
                &self.qualification_names,
                &self.qualified_names,
            )
        });
        if typed_qualification || inferred_qualification {
            collect_pattern_names(&local.pat, &mut self.qualification_receivers);
        }
        visit::visit_local(self, local);
    }

    fn visit_expr_closure(&mut self, closure: &'ast syn::ExprClosure) {
        let saved = self.qualification_receivers.clone();
        let saved_context = self.qualification_context;
        for input in &closure.inputs {
            if let syn::Pat::Type(typed) = input
                && super::call_provenance::type_mentions_qualification(
                    &typed.ty,
                    &self.qualification_names,
                    &self.qualified_names,
                )
            {
                collect_pattern_names(&typed.pat, &mut self.qualification_receivers);
                self.qualification_context = true;
            }
        }
        self.visit_expr(&closure.body);
        self.qualification_receivers = saved;
        self.qualification_context = saved_context;
    }

    fn visit_block(&mut self, block: &'ast syn::Block) {
        let saved = self.scope.clone();
        self.scope = macro_scope::child(&saved, "block", block.span());
        visit::visit_block(self, block);
        self.scope = saved;
    }
}

fn receiver_root_ident(expression: &syn::Expr) -> Option<String> {
    match unwrap_receiver(expression) {
        syn::Expr::Path(path) => path.path.get_ident().map(normalized_ident),
        syn::Expr::Field(value) => receiver_root_ident(&value.base),
        syn::Expr::Index(value) => receiver_root_ident(&value.expr),
        syn::Expr::Reference(value) => receiver_root_ident(&value.expr),
        syn::Expr::Unary(value) => receiver_root_ident(&value.expr),
        syn::Expr::Await(value) => receiver_root_ident(&value.base),
        syn::Expr::Try(value) => receiver_root_ident(&value.expr),
        syn::Expr::Cast(value) => receiver_root_ident(&value.expr),
        syn::Expr::MethodCall(value) => receiver_root_ident(&value.receiver),
        _ => None,
    }
}
