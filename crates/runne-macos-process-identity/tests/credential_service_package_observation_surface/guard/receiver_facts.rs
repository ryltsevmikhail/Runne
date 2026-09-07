use std::collections::HashSet;

use super::calls::{TargetMethod, type_targets};
use super::receiver_helpers::{
    collect_function_use_tree, collect_pattern_names, expression_produces_target, ident_pattern,
    target_function_item,
};
use super::syntax::is_test_only;
use syn::visit::{self, Visit};
use syn::{Expr, File, FnArg, Pat, Signature};

macro_rules! visit_non_test_items {
    ($($method:ident: $item:ty => $delegate:ident),* $(,)?) => {
        $(fn $method(&mut self, node: &'ast $item) {
            if !is_test_only(&node.attrs) { visit::$delegate(self, node); }
        })*
    };
}

pub(super) struct Facts {
    pub(super) capture: HashSet<String>,
    pub(super) verify: HashSet<String>,
    pub(super) variables: HashSet<String>,
}

pub(super) fn discover(file: &File, known: &HashSet<String>) -> Facts {
    let mut facts = TargetFacts::new(known);
    loop {
        let before = facts.state();
        facts.visit_file(file);
        if facts.state() == before {
            break;
        }
    }
    Facts {
        capture: facts.capture,
        verify: facts.verify,
        variables: facts.variables,
    }
}

struct TargetFacts<'a> {
    known: &'a HashSet<String>,
    capture: HashSet<String>,
    verify: HashSet<String>,
    variables: HashSet<String>,
}

impl<'a> TargetFacts<'a> {
    fn new(known: &'a HashSet<String>) -> Self {
        Self {
            known,
            capture: HashSet::new(),
            verify: HashSet::new(),
            variables: HashSet::new(),
        }
    }

    fn state(&self) -> (usize, usize, usize) {
        (self.capture.len(), self.verify.len(), self.variables.len())
    }

    fn add_alias(&mut self, method: TargetMethod, pattern: &Pat) {
        let names = match method {
            TargetMethod::Capture => &mut self.capture,
            TargetMethod::Verify => &mut self.verify,
        };
        collect_pattern_names(pattern, names);
    }

    fn add_arguments(&mut self, signature: &Signature) {
        for argument in &signature.inputs {
            if let FnArg::Typed(argument) = argument
                && type_targets(&argument.ty, self.known)
            {
                collect_pattern_names(&argument.pat, &mut self.variables);
            }
        }
    }
}

impl<'ast> Visit<'ast> for TargetFacts<'_> {
    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        if !is_test_only(&node.attrs) {
            collect_function_use_tree(
                &node.tree,
                &[],
                self.known,
                &mut self.capture,
                &mut self.verify,
            );
        }
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if !is_test_only(&node.attrs) {
            self.add_arguments(&node.sig);
            visit::visit_item_fn(self, node);
        }
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if !is_test_only(&node.attrs) {
            self.add_arguments(&node.sig);
            visit::visit_impl_item_fn(self, node);
        }
    }

    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        if !is_test_only(&node.attrs) {
            self.add_arguments(&node.sig);
            visit::visit_trait_item_fn(self, node);
        }
    }

    fn visit_item_const(&mut self, node: &'ast syn::ItemConst) {
        if !is_test_only(&node.attrs) {
            if let Some(method) =
                target_function_item(&node.expr, self.known, &self.capture, &self.verify)
            {
                self.add_alias(method, &ident_pattern(&node.ident));
            }
            visit::visit_item_const(self, node);
        }
    }

    fn visit_item_static(&mut self, node: &'ast syn::ItemStatic) {
        if !is_test_only(&node.attrs) {
            if let Some(method) =
                target_function_item(&node.expr, self.known, &self.capture, &self.verify)
            {
                self.add_alias(method, &ident_pattern(&node.ident));
            }
            visit::visit_item_static(self, node);
        }
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        if let Some(initializer) = &node.init {
            if let Some(method) =
                target_function_item(&initializer.expr, self.known, &self.capture, &self.verify)
            {
                self.add_alias(method, &node.pat);
            }
            if expression_produces_target(
                &initializer.expr,
                self.known,
                &self.capture,
                &self.verify,
            ) {
                collect_pattern_names(&node.pat, &mut self.variables);
            }
        }
        visit::visit_local(self, node);
    }

    fn visit_expr_assign(&mut self, node: &'ast syn::ExprAssign) {
        if let Some(method) =
            target_function_item(&node.right, self.known, &self.capture, &self.verify)
            && let Expr::Path(path) = node.left.as_ref()
            && let Some(name) = path.path.segments.last()
        {
            self.add_alias(method, &ident_pattern(&name.ident));
        }
        visit::visit_expr_assign(self, node);
    }

    visit_non_test_items! {
        visit_impl_item_const: syn::ImplItemConst => visit_impl_item_const,
        visit_impl_item_macro: syn::ImplItemMacro => visit_impl_item_macro,
        visit_impl_item_type: syn::ImplItemType => visit_impl_item_type,
        visit_item_enum: syn::ItemEnum => visit_item_enum,
        visit_item_impl: syn::ItemImpl => visit_item_impl,
        visit_item_macro: syn::ItemMacro => visit_item_macro,
        visit_item_mod: syn::ItemMod => visit_item_mod,
        visit_item_struct: syn::ItemStruct => visit_item_struct,
        visit_item_trait: syn::ItemTrait => visit_item_trait,
        visit_item_union: syn::ItemUnion => visit_item_union,
        visit_trait_item_const: syn::TraitItemConst => visit_trait_item_const,
        visit_trait_item_macro: syn::TraitItemMacro => visit_trait_item_macro,
        visit_trait_item_type: syn::TraitItemType => visit_trait_item_type,
    }
}
