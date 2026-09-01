use syn::visit::{self, Visit};
use syn::{ExprMethodCall, FnArg, Item, Type};

const CLAIM_SOURCE: &str = include_str!("../../src/cli/provider_credential_broker/claim.rs");

#[test]
fn production_claim_consumes_only_the_authenticated_native_bundle() {
    let violations = claim_source_violations(CLAIM_SOURCE);
    assert!(violations.is_empty(), "{violations:#?}");
}

#[test]
fn claim_policy_rejects_endpoint_injection_and_ticket_reread() {
    let cases = [
        CLAIM_SOURCE.replace(
            "writers: NativeProviderCredentialWriters",
            "endpoint: AuthenticatedDaemonControlEndpoint, writers: NativeProviderCredentialWriters",
        ),
        CLAIM_SOURCE.replace(".claim_on(", ".read_frame("),
    ];
    assert!(
        cases
            .iter()
            .all(|source| !claim_source_violations(source).is_empty())
    );
}

fn claim_source_violations(source: &str) -> Vec<String> {
    let file = match syn::parse_file(source) {
        Ok(file) => file,
        Err(error) => return vec![format!("claim source does not parse: {error}")],
    };
    let functions: Vec<_> = file
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Fn(function) if function.sig.ident == "claim_writer_authorization" => {
                Some(function)
            }
            _ => None,
        })
        .collect();
    if functions.len() != 1 {
        return vec![format!(
            "expected one production claim, found {}",
            functions.len()
        )];
    }
    let function = functions[0];
    let mut violations = Vec::new();
    if function.sig.inputs.len() != 1 || !is_native_writers(&function.sig.inputs[0]) {
        violations.push("production claim must accept only NativeProviderCredentialWriters".into());
    }
    let mut calls = Calls::default();
    calls.visit_block(&function.block);
    if calls.into_authenticated_parts != 1 {
        violations.push("claim must consume exactly one authenticated parts bundle".into());
    }
    if calls.claim_on != 1 {
        violations.push("claim must consume exactly one retained ticket".into());
    }
    if calls.read_frame != 0 {
        violations.push("production claim must not reread an IssueTicket".into());
    }
    violations
}

fn is_native_writers(argument: &FnArg) -> bool {
    let FnArg::Typed(argument) = argument else {
        return false;
    };
    let Type::Path(path) = argument.ty.as_ref() else {
        return false;
    };
    path.qself.is_none()
        && path.path.segments.len() == 1
        && path.path.segments[0].ident == "NativeProviderCredentialWriters"
}

#[derive(Default)]
struct Calls {
    into_authenticated_parts: usize,
    claim_on: usize,
    read_frame: usize,
}

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        match call.method.to_string().as_str() {
            "into_authenticated_parts" => self.into_authenticated_parts += 1,
            "claim_on" => self.claim_on += 1,
            "read_frame" => self.read_frame += 1,
            _ => {}
        }
        visit::visit_expr_method_call(self, call);
    }
}
