use proc_macro2::TokenStream;

use super::macro_definitions::{self, Index};
use super::source_parse::ParsedSource;
use super::visitor::MacroDisposition;

#[derive(Clone, Copy)]
pub(super) struct Context<'a> {
    pub(super) source: &'a ParsedSource,
    pub(super) parsed: &'a [ParsedSource],
    pub(super) definitions: &'a Index,
}

pub(super) struct Invocation {
    pub(super) name: String,
    pub(super) trusted_path: Option<String>,
    pub(super) disposition: MacroDisposition,
    pub(super) scope: Vec<String>,
    pub(super) position: usize,
    pub(super) payload: Option<TokenStream>,
}

pub(super) fn is_relevant(context: Context<'_>, call: Invocation) -> bool {
    let Context {
        source,
        parsed,
        definitions,
    } = context;
    let Invocation {
        name,
        trusted_path,
        disposition,
        scope,
        position,
        payload,
    } = call;
    let nested_root_is_untrusted = payload.as_ref().is_some_and(|payload| {
        super::macro_tokens::qualified_macro_paths(payload)
            .into_iter()
            .any(|path| {
                super::include_macro_resolution::qualified_path_is_untrusted(
                    source,
                    parsed,
                    &source.unit.trusted_external_roots,
                    &path,
                )
            })
    });
    let disposition = super::resolved_macro_disposition(
        source,
        parsed,
        definitions,
        &name,
        trusted_path.as_deref(),
        disposition,
        &scope,
    );
    let local_relevant = macro_definitions::is_relevant(
        definitions,
        &name,
        disposition,
        &scope,
        position,
        payload.as_ref(),
    );
    let included_relevance =
        super::include_macro_resolution::relevance(super::include_macro_resolution::MacroCall {
            source,
            parsed,
            local: definitions,
            name: &name,
            scope: &scope,
            payload: payload.as_ref(),
            call_position: position,
            disposition,
        });
    nested_root_is_untrusted || included_relevance.unwrap_or(local_relevant)
}
