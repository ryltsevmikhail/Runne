use syn::visit::{self, Visit};

use super::metadata;

pub(super) enum Call {
    Method {
        from_qualification_body: bool,
    },
    Macro,
    TraitBound {
        name: String,
    },
    Path {
        qualifier: Option<String>,
        subject: Option<String>,
        qself: bool,
    },
}

pub(super) struct CallVisitor {
    pub(super) calls: Vec<Call>,
    from_qualification_body: bool,
}

impl CallVisitor {
    pub(super) fn new() -> Self {
        Self {
            calls: Vec::new(),
            from_qualification_body: false,
        }
    }

    pub(super) fn qualification_body() -> Self {
        Self {
            calls: Vec::new(),
            from_qualification_body: true,
        }
    }
}

impl<'ast> Visit<'ast> for CallVisitor {
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if macro_mentions_qualification(mac) {
            self.calls.push(Call::Macro);
        }
        visit::visit_macro(self, mac);
    }

    fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
        if expression.method == "qualify" {
            self.calls.push(Call::Method {
                from_qualification_body: self.from_qualification_body,
            });
        }
        visit::visit_expr_method_call(self, expression);
    }

    fn visit_trait_bound(&mut self, bound: &'ast syn::TraitBound) {
        if let Some(name) = metadata::last_path_segment(&bound.path) {
            self.calls.push(Call::TraitBound { name });
        }
        visit::visit_trait_bound(self, bound);
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
            });
        }
        visit::visit_expr_path(self, expression);
    }
}

pub(super) fn macro_mentions_qualification(mac: &syn::Macro) -> bool {
    mac.tokens
        .to_string()
        .split(|character: char| !character.is_alphanumeric() && character != '_')
        .any(|token| token == "qualify")
}
