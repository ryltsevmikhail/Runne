use syn::buffer::{Cursor, TokenBuffer};
use syn::parse::{Parse, ParseStream};
use syn::visit::Visit;
use syn::{Ident, ItemMacro, LitStr, Token};

use super::syntax;

pub fn reject_associated_macros(file: &syn::File) -> Result<(), String> {
    let mut visitor = AssociatedMacros { error: None };
    visitor.visit_file(file);
    visitor.error.map_or(Ok(()), Err)
}

struct AssociatedMacros {
    error: Option<String>,
}

impl AssociatedMacros {
    fn reject(&mut self, mac: &syn::Macro) {
        let name = mac
            .path
            .segments
            .iter()
            .map(|part| part.ident.to_string())
            .collect::<Vec<_>>()
            .join("::");
        self.error
            .get_or_insert_with(|| format!("unexpanded associated-item macro: {name}!"));
    }
}

impl<'ast> Visit<'ast> for AssociatedMacros {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        if !syntax::item_is_test_only(item) {
            syn::visit::visit_item(self, item);
        }
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        if syntax::impl_item_is_test_only(item) {
            return;
        }
        // The file loader cannot preserve an included member's impl owner.
        // Reject all associated macros, including opaque external wrappers;
        // source literal/extension recognition is deliberately not required.
        if let syn::ImplItem::Macro(item) = item {
            self.reject(&item.mac);
        }
        syn::visit::visit_impl_item(self, item);
    }

    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        if syntax::trait_item_is_test_only(item) {
            return;
        }
        if let syn::TraitItem::Macro(item) = item {
            self.reject(&item.mac);
        }
        syn::visit::visit_trait_item(self, item);
    }
}

// This is source-edge modeling, not macro expansion. Only a single literal
// forwarding include rule is supported; computed, indirect, and multi-arm
// definitions fail closed even when some other literal happens to name a file.
pub fn source_literals(item: &ItemMacro) -> Result<Vec<String>, String> {
    let buffer = TokenBuffer::new2(item.mac.tokens.clone());
    let mut literals = Vec::new();
    let mut nested_macro = false;
    scan(buffer.begin(), &mut literals, &mut nested_macro);
    if item.ident.is_some() && nested_macro {
        syn::parse2::<LiteralIncludeWrapper>(item.mac.tokens.clone())
            .map_err(|error| format!("unexpanded source-bearing macro definition: {error}"))?;
        return Ok(Vec::new());
    }
    let direct_include = item
        .mac
        .path
        .segments
        .last()
        .is_some_and(|p| p.ident == "include");
    if direct_include {
        let path = syn::parse2::<LitStr>(item.mac.tokens.clone())
            .map_err(|error| format!("unresolved include argument: {error}"))?;
        return Ok(vec![path.value()]);
    }
    if nested_macro {
        return Err("unexpanded source-bearing macro invocation".into());
    }
    Ok(literals)
}

fn scan(mut cursor: Cursor<'_>, literals: &mut Vec<String>, nested_macro: &mut bool) {
    while !cursor.eof() {
        if let Some((group, _, _, rest)) = cursor.any_group() {
            scan(group, literals, nested_macro);
            cursor = rest;
        } else if let Some((literal, rest)) = cursor.literal() {
            if let Ok(value) = syn::parse_str::<LitStr>(&literal.to_string()) {
                literals.push(value.value());
            }
            cursor = rest;
        } else if let Some((_, rest)) = cursor.ident() {
            *nested_macro |= rest
                .punct()
                .is_some_and(|(punct, _)| punct.as_char() == '!');
            cursor = rest;
        } else if let Some((_, rest)) = cursor.token_tree() {
            cursor = rest;
        }
    }
}

struct LiteralIncludeWrapper;

impl Parse for LiteralIncludeWrapper {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let matcher;
        syn::parenthesized!(matcher in input);
        matcher.parse::<Token![$]>()?;
        let parameter = matcher.parse::<Ident>()?;
        matcher.parse::<Token![:]>()?;
        let fragment = matcher.parse::<Ident>()?;
        if fragment != "literal" || !matcher.is_empty() {
            return Err(matcher.error("expected one literal parameter"));
        }
        input.parse::<Token![=>]>()?;
        let body;
        syn::braced!(body in input);
        let invocation = body.parse::<syn::Macro>()?;
        if !invocation
            .path
            .segments
            .last()
            .is_some_and(|p| p.ident == "include")
        {
            return Err(body.error("expected direct include"));
        }
        let argument = syn::parse2::<ForwardedParameter>(invocation.tokens)?;
        if argument.0 != parameter {
            return Err(body.error("include must forward the literal parameter"));
        }
        if body.peek(Token![;]) {
            body.parse::<Token![;]>()?;
        }
        if !body.is_empty() {
            return Err(body.error("unsupported wrapper body"));
        }
        if input.peek(Token![;]) {
            input.parse::<Token![;]>()?;
        }
        Ok(Self)
    }
}

struct ForwardedParameter(Ident);

impl Parse for ForwardedParameter {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        input.parse::<Token![$]>()?;
        Ok(Self(input.parse()?))
    }
}
