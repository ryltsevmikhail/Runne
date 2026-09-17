//! Binding check for the audited writer-stage diagnostics module.
//!
//! The disclosure sink policy forbids every emission macro in production
//! broker sources. The single sanctioned capacity is the feature-gated
//! `writer_stage` live twin, and only when the broker declares it with the
//! exact mutually exclusive pair of cfg-gated `#[path]` declarations below.
//! A bare literal whitelist applied tree-wide is explicitly NOT the policy:
//! outside the bound live module every sink stays rejected, whatever it
//! prints.

use std::path::PathBuf;

use syn::{Item, ItemMod, Lit, Meta};

pub const AUDITED_STAGE_MODULE: &str = "writer_stage";
const ENROLLMENT_FEATURE: &str = "local-native-enrollment-test";
const LIVE_TWIN_PATH: &str = "provider_credential_broker/writer_stage_live.rs";
const SILENT_TWIN_PATH: &str = "provider_credential_broker/writer_stage_silent.rs";

/// The closed vocabulary of stage literals the live twin may emit. Each
/// entry is one argument-free literal, so no runtime value can be formatted.
pub const AUDITED_STAGE_EMISSIONS: &[&str] = &[
    "writer-stage=secret-inspect",
    "writer-stage=endpoint-receive",
    "writer-stage=session-observe",
    "writer-stage=authenticated-run",
    "writer-stage-failed=secret-inspect",
    "writer-stage-failed=endpoint-receive",
    "writer-stage-failed=session-observe",
    "writer-stage-failed=authenticated-run",
];

/// Read-only view of the audited emission vocabulary for sync tests.
pub const fn audited_stage_emissions() -> &'static [&'static str] {
    AUDITED_STAGE_EMISSIONS
}

/// True only for a bare `eprintln!` whose whole argument list is exactly one
/// audited stage literal (no format arguments, no nested macros).
pub fn is_audited_stage_emission(node: &syn::Macro) -> bool {
    node.path.is_ident("eprintln")
        && syn::parse2::<syn::LitStr>(node.tokens.clone())
            .is_ok_and(|literal| AUDITED_STAGE_EMISSIONS.contains(&literal.value().as_str()))
}

/// Checks the broker source for the exact `writer_stage` twin declarations:
/// `#[cfg(feature = "local-native-enrollment-test")] #[path = LIVE]` and
/// `#[cfg(not(feature = "local-native-enrollment-test"))] #[path = SILENT]`.
/// Returns binding violations plus the live twin path relative to the
/// `src/cli` boundary when (and only when) the binding is exact.
#[must_use]
pub fn stage_module_binding(broker_source: &str) -> (Vec<String>, Option<PathBuf>) {
    let file = match syn::parse_file(broker_source) {
        Ok(file) => file,
        Err(error) => {
            return (vec![format!("broker source does not parse: {error}")], None);
        }
    };
    let declarations: Vec<&ItemMod> = file
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Mod(module)
                if module.ident == AUDITED_STAGE_MODULE && module.content.is_none() =>
            {
                Some(module)
            }
            _ => None,
        })
        .collect();
    if declarations.len() != 2 {
        return (
            vec![format!(
                "expected exactly two {AUDITED_STAGE_MODULE} module declarations (feature-gated live twin and mutually exclusive silent twin), found {}",
                declarations.len()
            )],
            None,
        );
    }
    let mut violations = Vec::new();
    let mut live = false;
    let mut silent = false;
    for module in declarations {
        match declaration_kind(module) {
            DeclarationKind::LiveTwin => live = true,
            DeclarationKind::SilentTwin => silent = true,
            DeclarationKind::Unreviewed(detail) => violations.push(detail),
        }
    }
    if !violations.is_empty() || !live || !silent {
        if violations.is_empty() {
            violations.push(format!(
                "{AUDITED_STAGE_MODULE} declarations must include both the feature-gated live twin and the not-feature silent twin"
            ));
        }
        return (violations, None);
    }
    (Vec::new(), Some(PathBuf::from(LIVE_TWIN_PATH)))
}

enum DeclarationKind {
    LiveTwin,
    SilentTwin,
    Unreviewed(String),
}

fn declaration_kind(module: &ItemMod) -> DeclarationKind {
    if module.attrs.len() != 2 {
        return DeclarationKind::Unreviewed(format!(
            "{AUDITED_STAGE_MODULE} declaration must carry exactly one cfg and one path attribute"
        ));
    }
    let mut cfg = None;
    let mut path = None;
    for attribute in &module.attrs {
        if let Some(literal) = path_attribute_value(attribute) {
            path = Some(literal);
        } else if let Some(kind) = cfg_attribute_kind(attribute) {
            cfg = Some(kind);
        } else {
            return DeclarationKind::Unreviewed(format!(
                "{AUDITED_STAGE_MODULE} declaration carries an unrelated attribute"
            ));
        }
    }
    match (cfg, path.as_deref()) {
        (Some(CfgKind::Feature), Some(LIVE_TWIN_PATH)) => DeclarationKind::LiveTwin,
        (Some(CfgKind::NotFeature), Some(SILENT_TWIN_PATH)) => DeclarationKind::SilentTwin,
        _ => DeclarationKind::Unreviewed(format!(
            "{AUDITED_STAGE_MODULE} declaration must pair the exact enrollment-feature cfg with its audited twin path"
        )),
    }
}

enum CfgKind {
    Feature,
    NotFeature,
}

fn cfg_attribute_kind(attribute: &syn::Attribute) -> Option<CfgKind> {
    let Meta::List(list) = &attribute.meta else {
        return None;
    };
    if !list.path.is_ident("cfg") {
        return None;
    }
    let inner = syn::parse2::<Meta>(list.tokens.clone()).ok()?;
    match &inner {
        Meta::NameValue(value)
            if value.path.is_ident("feature")
                && matches!(&value.value, syn::Expr::Lit(syn::ExprLit {
                    lit: Lit::Str(text),
                    ..
                }) if text.value() == ENROLLMENT_FEATURE) =>
        {
            Some(CfgKind::Feature)
        }
        Meta::List(not)
            if not.path.is_ident("not")
                && syn::parse2::<Meta>(not.tokens.clone()).is_ok_and(|nested| {
                    matches!(&nested,
                        Meta::NameValue(value)
                            if value.path.is_ident("feature")
                                && matches!(&value.value, syn::Expr::Lit(syn::ExprLit {
                                    lit: Lit::Str(text),
                                    ..
                                }) if text.value() == ENROLLMENT_FEATURE))
                }) =>
        {
            Some(CfgKind::NotFeature)
        }
        _ => None,
    }
}

fn path_attribute_value(attribute: &syn::Attribute) -> Option<String> {
    let Meta::NameValue(value) = &attribute.meta else {
        return None;
    };
    if !value.path.is_ident("path") {
        return None;
    }
    match &value.value {
        syn::Expr::Lit(syn::ExprLit {
            lit: Lit::Str(text),
            ..
        }) => Some(text.value()),
        _ => None,
    }
}
