use std::collections::BTreeSet;

use syn::visit::{self, Visit};

use super::visitor_types::{
    collect_pattern_names, expression_constructs_named_type, type_mentions_names,
};

#[derive(Debug)]
pub(super) enum Call {
    Method {
        from_qualification_body: bool,
        qualification_context: bool,
    },
    Macro {
        name: String,
        trusted_path: Option<String>,
        disposition: MacroDisposition,
        scope: Vec<String>,
        position: usize,
        payload: Option<proc_macro2::TokenStream>,
    },
    Path {
        qualifier: Option<String>,
        subject: Option<String>,
        qself: bool,
        qualification_context: bool,
    },
}

#[derive(Clone, Copy, Debug)]
pub(super) enum MacroDisposition {
    OpaqueExternal,
    Unrelated,
    Direct,
    ResolveLocal,
    ResolveContext,
    ResolveTrusted,
}

pub(super) struct CallVisitor {
    pub(super) calls: Vec<Call>,
    pub(super) from_qualification_body: bool,
    pub(super) qualification_context: bool,
    pub(super) qualification_names: BTreeSet<String>,
    pub(super) qualified_names: BTreeSet<String>,
    pub(super) qualification_receivers: BTreeSet<String>,
    pub(super) unrelated_receivers: BTreeSet<String>,
    pub(super) unrelated_type_names: BTreeSet<String>,
    pub(super) scope: Vec<String>,
    pub(super) collect_nested_items: bool,
}

impl CallVisitor {
    pub(super) fn new() -> Self {
        Self {
            calls: Vec::new(),
            from_qualification_body: false,
            qualification_context: false,
            qualification_names: BTreeSet::new(),
            qualified_names: BTreeSet::new(),
            qualification_receivers: BTreeSet::new(),
            unrelated_receivers: BTreeSet::new(),
            unrelated_type_names: BTreeSet::new(),
            scope: Vec::new(),
            collect_nested_items: false,
        }
    }

    pub(super) fn qualification_body() -> Self {
        Self {
            calls: Vec::new(),
            from_qualification_body: true,
            qualification_context: true,
            qualification_names: BTreeSet::new(),
            qualified_names: BTreeSet::new(),
            qualification_receivers: BTreeSet::new(),
            unrelated_receivers: BTreeSet::new(),
            unrelated_type_names: BTreeSet::new(),
            scope: Vec::new(),
            collect_nested_items: true,
        }
    }

    pub(super) fn qualification_context() -> Self {
        Self {
            calls: Vec::new(),
            from_qualification_body: false,
            qualification_context: true,
            qualification_names: BTreeSet::new(),
            qualified_names: BTreeSet::new(),
            qualification_receivers: BTreeSet::new(),
            unrelated_receivers: BTreeSet::new(),
            unrelated_type_names: BTreeSet::new(),
            scope: Vec::new(),
            collect_nested_items: true,
        }
    }

    pub(super) fn for_function(
        names: &BTreeSet<String>,
        qualified_names: &BTreeSet<String>,
        qualification_context: bool,
        scope: Vec<String>,
        _opaque_container_names: &BTreeSet<String>,
        unrelated_type_names: &BTreeSet<String>,
    ) -> Self {
        Self {
            calls: Vec::new(),
            from_qualification_body: false,
            qualification_context,
            qualification_names: names.clone(),
            qualified_names: qualified_names.clone(),
            qualification_receivers: BTreeSet::new(),
            unrelated_receivers: BTreeSet::new(),
            unrelated_type_names: unrelated_type_names.clone(),
            scope,
            collect_nested_items: true,
        }
    }

    pub(super) fn seed_typed_receivers(&mut self, block: &syn::Block) {
        struct Locals<'a> {
            names: &'a BTreeSet<String>,
            qualified_names: &'a BTreeSet<String>,
            receivers: &'a mut BTreeSet<String>,
        }
        impl<'ast> Visit<'ast> for Locals<'_> {
            fn visit_stmt(&mut self, statement: &'ast syn::Stmt) {
                if !super::syntax::stmt_is_test_only(statement) {
                    visit::visit_stmt(self, statement);
                }
            }

            fn visit_local(&mut self, local: &'ast syn::Local) {
                if let syn::Pat::Type(typed) = &local.pat
                    && type_mentions_names(&typed.ty, self.names)
                {
                    collect_pattern_names(&typed.pat, self.receivers);
                } else if let Some(initializer) = &local.init
                    && (expression_constructs_named_type(&initializer.expr, self.names)
                        || super::call_provenance::expression_mentions_qualification_type(
                            &initializer.expr,
                            self.names,
                            self.qualified_names,
                        ))
                {
                    collect_pattern_names(&local.pat, self.receivers);
                }
                visit::visit_local(self, local);
            }
        }
        Locals {
            names: &self.qualification_names,
            qualified_names: &self.qualified_names,
            receivers: &mut self.qualification_receivers,
        }
        .visit_block(block);
    }

    pub(super) fn seed_signature_receivers(&mut self, signature: &syn::Signature) {
        for input in &signature.inputs {
            let syn::FnArg::Typed(input) = input else {
                continue;
            };
            let target = if type_mentions_names(&input.ty, &self.qualification_names) {
                &mut self.qualification_receivers
            } else if type_mentions_names(&input.ty, &self.unrelated_type_names) {
                &mut self.unrelated_receivers
            } else {
                continue;
            };
            collect_pattern_names(&input.pat, target);
        }
    }
}
