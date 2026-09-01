use syn::{Attribute, Block, Expr, Item, Meta, Pat, Stmt};

pub fn broker_branch_violations(source: &str) -> Vec<String> {
    let file = match syn::parse_file(source) {
        Ok(file) => file,
        Err(error) => return vec![format!("broker source does not parse: {error}")],
    };
    let functions: Vec<_> = file
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Fn(function) if function.sig.ident == "run_provider_credential_broker" => {
                Some(function)
            }
            _ => None,
        })
        .collect();
    if functions.len() != 1 {
        return vec![format!(
            "expected one run_provider_credential_broker, found {}",
            functions.len()
        )];
    }
    let function = functions[0];
    let mut violations = Vec::new();
    if !matches!(function.vis, syn::Visibility::Inherited) {
        violations.push("broker entry point must remain private".to_owned());
    }
    if function.block.stmts.len() != 4 {
        violations
            .push("broker must contain exactly two argv gates and two cfg branches".to_owned());
        return violations;
    }
    if !is_expect_token(&function.block.stmts[0]) {
        violations.push("broker must first validate the fixed mode token".to_owned());
    }
    if !is_expect_end(&function.block.stmts[1]) {
        violations.push("broker must validate argv end before either platform branch".to_owned());
    }
    match cfg_block(&function.block.stmts[2], CfgKind::MacOs) {
        Some(block) if is_exact_macos_block(block) => {}
        _ => violations
            .push("macOS branch must receive one named handoff then stay unsupported".to_owned()),
    }
    match cfg_block(&function.block.stmts[3], CfgKind::NotMacOs) {
        Some(block) if is_exact_non_macos_block(block) => {}
        _ => violations.push("non-macOS branch must only return typed unsupported".to_owned()),
    }
    violations
}

fn is_expect_token(statement: &Stmt) -> bool {
    let Some(call) = tried_call(statement, "expect_token") else {
        return false;
    };
    call.args.len() == 2
        && is_reference_to(&call.args[0], "arguments", true)
        && is_path(&call.args[1], &["PROVIDER_CREDENTIAL_BROKER_MODE_V1"])
}

fn is_expect_end(statement: &Stmt) -> bool {
    let Some(call) = tried_call(statement, "expect_end") else {
        return false;
    };
    call.args.len() == 1 && is_reference_to(&call.args[0], "arguments", false)
}

fn tried_call<'a>(statement: &'a Stmt, function: &str) -> Option<&'a syn::ExprCall> {
    let Stmt::Expr(Expr::Try(tried), Some(_)) = statement else {
        return None;
    };
    let Expr::Call(call) = tried.expr.as_ref() else {
        return None;
    };
    (tried.attrs.is_empty() && call.attrs.is_empty() && is_path(call.func.as_ref(), &[function]))
        .then_some(call)
}

fn is_reference_to(expression: &Expr, name: &str, mutable: bool) -> bool {
    let Expr::Reference(reference) = expression else {
        return false;
    };
    reference.attrs.is_empty()
        && reference.mutability.is_some() == mutable
        && is_path(reference.expr.as_ref(), &[name])
}

#[derive(Clone, Copy)]
enum CfgKind {
    MacOs,
    NotMacOs,
}

fn cfg_block(statement: &Stmt, expected: CfgKind) -> Option<&Block> {
    let Stmt::Expr(Expr::Block(block), None) = statement else {
        return None;
    };
    (block.label.is_none() && block.attrs.len() == 1 && cfg_matches(&block.attrs[0], expected))
        .then_some(&block.block)
}

fn cfg_matches(attribute: &Attribute, expected: CfgKind) -> bool {
    let Meta::List(cfg) = &attribute.meta else {
        return false;
    };
    if !cfg.path.is_ident("cfg") {
        return false;
    }
    let Ok(meta) = syn::parse2::<Meta>(cfg.tokens.clone()) else {
        return false;
    };
    match expected {
        CfgKind::MacOs => is_target_macos(&meta),
        CfgKind::NotMacOs => match meta {
            Meta::List(not) if not.path.is_ident("not") => {
                syn::parse2::<Meta>(not.tokens).is_ok_and(|inner| is_target_macos(&inner))
            }
            _ => false,
        },
    }
}

fn is_target_macos(meta: &Meta) -> bool {
    let Meta::NameValue(value) = meta else {
        return false;
    };
    if !value.path.is_ident("target_os") {
        return false;
    }
    matches!(
        &value.value,
        Expr::Lit(literal) if matches!(&literal.lit, syn::Lit::Str(value) if value.value() == "macos")
    )
}

fn is_exact_macos_block(block: &Block) -> bool {
    block.stmts.len() == 3
        && is_handoff_local(&block.stmts[0])
        && is_pinned_local(&block.stmts[1])
        && is_error(&block.stmts[2], "UnsupportedCredentialBackend")
}

fn is_handoff_local(statement: &Stmt) -> bool {
    let Stmt::Local(local) = statement else {
        return false;
    };
    let Pat::Ident(binding) = &local.pat else {
        return false;
    };
    if !local.attrs.is_empty()
        || !binding.attrs.is_empty()
        || binding.ident != "handoff"
        || binding.by_ref.is_some()
        || binding.mutability.is_some()
        || binding.subpat.is_some()
    {
        return false;
    }
    let Some(initializer) = &local.init else {
        return false;
    };
    if initializer.diverge.is_some() {
        return false;
    }
    let Expr::Try(tried) = initializer.expr.as_ref() else {
        return false;
    };
    let Expr::MethodCall(map_error_call) = tried.expr.as_ref() else {
        return false;
    };
    if !tried.attrs.is_empty()
        || !map_error_call.attrs.is_empty()
        || map_error_call.method != "map_err"
        || map_error_call.turbofish.is_some()
        || map_error_call.args.len() != 1
    {
        return false;
    }
    let Expr::Call(receive) = map_error_call.receiver.as_ref() else {
        return false;
    };
    let receive_path = [
        "runne_native_enrollment_authority",
        "UntrustedProviderCredentialWriterEndpointHandoffV1",
        "receive_from_stdin",
    ];
    if !receive.attrs.is_empty()
        || !receive.args.is_empty()
        || !is_path(receive.func.as_ref(), &receive_path)
    {
        return false;
    }
    let Some(Expr::Closure(error_mapper)) = map_error_call.args.first() else {
        return false;
    };
    error_mapper.attrs.is_empty()
        && error_mapper.inputs.len() == 1
        && matches!(error_mapper.inputs.first(), Some(Pat::Wild(_)))
        && is_path(
            error_mapper.body.as_ref(),
            &["CliError", "CredentialOperation"],
        )
}

fn is_pinned_local(statement: &Stmt) -> bool {
    let Stmt::Local(local) = statement else {
        return false;
    };
    let Pat::Ident(binding) = &local.pat else {
        return false;
    };
    if !local.attrs.is_empty()
        || !binding.attrs.is_empty()
        || binding.ident != "_pinned"
        || binding.by_ref.is_some()
        || binding.mutability.is_some()
        || binding.subpat.is_some()
    {
        return false;
    }
    let Some(initializer) = &local.init else {
        return false;
    };
    if initializer.diverge.is_some() {
        return false;
    }
    let Expr::Try(tried) = initializer.expr.as_ref() else {
        return false;
    };
    let Expr::MethodCall(map_error_call) = tried.expr.as_ref() else {
        return false;
    };
    let Expr::MethodCall(observe) = map_error_call.receiver.as_ref() else {
        return false;
    };
    tried.attrs.is_empty()
        && map_error_call.attrs.is_empty()
        && map_error_call.method == "map_err"
        && map_error_call.turbofish.is_none()
        && map_error_call.args.len() == 1
        && observe.attrs.is_empty()
        && observe.method == "observe_current_pinned_writer_session"
        && observe.turbofish.is_none()
        && observe.args.is_empty()
        && is_path(observe.receiver.as_ref(), &["handoff"])
        && matches!(map_error_call.args.first(), Some(Expr::Closure(error_mapper))
            if error_mapper.attrs.is_empty()
                && error_mapper.inputs.len() == 1
                && matches!(error_mapper.inputs.first(), Some(Pat::Wild(_)))
                && is_path(error_mapper.body.as_ref(), &["CliError", "CredentialOperation"]))
}

fn is_exact_non_macos_block(block: &Block) -> bool {
    block.stmts.len() == 1 && is_error(&block.stmts[0], "UnsupportedCredentialBackend")
}

fn is_error(statement: &Stmt, variant: &str) -> bool {
    let Stmt::Expr(Expr::Call(call), None) = statement else {
        return false;
    };
    call.attrs.is_empty()
        && call.args.len() == 1
        && is_path(call.func.as_ref(), &["Err"])
        && is_path(&call.args[0], &["CliError", variant])
}

fn is_path(expression: &Expr, expected: &[&str]) -> bool {
    let Expr::Path(path) = expression else {
        return false;
    };
    path.attrs.is_empty()
        && path.qself.is_none()
        && path.path.leading_colon.is_none()
        && path.path.segments.len() == expected.len()
        && path
            .path
            .segments
            .iter()
            .zip(expected)
            .all(|(segment, expected)| segment.ident == *expected && segment.arguments.is_empty())
}
